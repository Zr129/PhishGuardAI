"""
Report controller — generates a downloadable PDF security report.

POST /report
  Body: ReportRequest (URLRequest fields + AnalysisResult fields)
  Returns: PDF file as attachment

503 — GROQ_API_KEY not set
500 — WeasyPrint not installed or PDF generation failed
"""

import logging
import re
import traceback
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import Response
from slowapi import Limiter

from models.models import URLRequest, AnalysisResult

logger = logging.getLogger("PhishGuard")


class ReportRequest(URLRequest, AnalysisResult):
    """
    Request body for /report.

    Composes URLRequest + AnalysisResult so the report endpoint has
    every field it needs without re-running the analysis pipeline.
    The two parents share `url` and `domain` — Pydantic resolves them
    to a single field via MRO.
    """
    pass


# Safe characters for the download filename domain segment
_FILENAME_SAFE_RE = re.compile(r"[^A-Za-z0-9._-]")


def _safe_domain_for_filename(domain: str) -> str:
    return _FILENAME_SAFE_RE.sub("_", domain or "unknown")[:60]


def build_report_router(report_generator, extractor, limiter: Limiter) -> APIRouter:
    router = APIRouter()

    @router.post("/report")
    @limiter.limit("10/minute")   # Lower limit — LLM + PDF generation is expensive
    async def generate_report(request: Request, body: ReportRequest):
        logger.info(f"[REPORT] Request for {body.url}")

        try:
            refined     = extractor.extract(body.url, body.links)
            pdf_bytes   = report_generator.generate(body, body, refined)

            domain_safe = _safe_domain_for_filename(body.domain)
            ts          = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M")
            filename    = f"phishguard_{domain_safe}_{ts}.pdf"

            logger.info(f"[REPORT] Sending PDF: {filename} ({len(pdf_bytes):,} bytes)")

            return Response(
                content=pdf_bytes,
                media_type="application/pdf",
                headers={"Content-Disposition": f'attachment; filename="{filename}"'},
            )

        except ValueError as e:
            # GROQ_API_KEY not configured
            logger.warning(f"[REPORT] Config error: {e}")
            raise HTTPException(status_code=503, detail=str(e))

        except RuntimeError as e:
            # WeasyPrint not installed or PDF generation failed
            logger.error(f"[REPORT] PDF generation error: {e}")
            raise HTTPException(status_code=500, detail=str(e))

        except Exception as e:
            logger.error(traceback.format_exc())
            raise HTTPException(status_code=500, detail=f"Report generation failed: {str(e)}")

    return router