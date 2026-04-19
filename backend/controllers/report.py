"""
Report controller — generates downloadable HTML security report.

POST /report
  Body: { url, analysis_result, page_data }
  Returns: HTML file as attachment
"""

import logging
import traceback
from datetime import datetime

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from slowapi import Limiter
from slowapi.util import get_remote_address
from typing import Any, Dict, List, Optional

logger = logging.getLogger("PhishGuard")


class ReportRequest(BaseModel):
    """
    The extension sends the full analysis result and page data
    so the report can include everything without re-analysing.
    """
    # Analysis result fields
    action:         str
    prediction:     str
    confidence:     int
    reasons:        List[str]
    tagged_reasons: List[Dict[str, Any]] = []

    # Page data (URLRequest fields)
    url:                        str
    domain:                     str
    title:                      str = ""
    is_https:                   bool = True
    is_main_frame:              bool = True
    has_password_field:         bool = False
    is_hidden_submission:       bool = False
    action_to_different_domain: bool = False
    has_submit_button:          bool = False
    has_hidden_fields:          bool = False
    has_favicon:                bool = False
    has_description:            bool = False
    has_copyright:              bool = False
    has_social_net:             bool = False
    has_bank_keywords:          bool = False
    has_pay_keywords:           bool = False
    has_crypto_keywords:        bool = False
    no_of_self_ref:             int  = 0
    no_of_images:               int  = 0
    no_of_js:                   int  = 0
    no_of_css:                  int  = 0
    total_anchors:              int  = 0
    empty_anchors:              int  = 0
    links:                      List[str] = []


def build_report_router(report_generator, extractor, limiter: Limiter) -> APIRouter:
    router = APIRouter()

    @router.post("/report", response_class=HTMLResponse)
    @limiter.limit("10/minute")   # lower limit — LLM calls are expensive
    async def generate_report(request: Request, body: ReportRequest):
        logger.info(f"[REPORT] Generating report for {body.url}")

        try:
            # Reconstruct URLRequest and AnalysisResult from the body
            from models.models import URLRequest, AnalysisResult

            url_request = URLRequest(
                url=body.url, domain=body.domain, title=body.title,
                is_https=body.is_https, is_main_frame=body.is_main_frame,
                has_password_field=body.has_password_field,
                is_hidden_submission=body.is_hidden_submission,
                action_to_different_domain=body.action_to_different_domain,
                has_submit_button=body.has_submit_button,
                has_hidden_fields=body.has_hidden_fields,
                has_favicon=body.has_favicon,
                has_description=body.has_description,
                has_copyright=body.has_copyright,
                has_social_net=body.has_social_net,
                has_bank_keywords=body.has_bank_keywords,
                has_pay_keywords=body.has_pay_keywords,
                has_crypto_keywords=body.has_crypto_keywords,
                no_of_self_ref=body.no_of_self_ref,
                no_of_images=body.no_of_images,
                no_of_js=body.no_of_js,
                no_of_css=body.no_of_css,
                total_anchors=body.total_anchors,
                empty_anchors=body.empty_anchors,
                links=body.links,
            )

            analysis_result = AnalysisResult(
                action=body.action,
                prediction=body.prediction,
                confidence=body.confidence,
                reasons=body.reasons,
                tagged_reasons=body.tagged_reasons,
            )

            # Re-extract URL features for the report context
            refined = extractor.extract(body.url, body.links)

            # Generate report
            html = report_generator.generate(url_request, analysis_result, refined)

            # Return as downloadable HTML file
            domain  = body.domain.replace(".", "_")
            ts      = datetime.utcnow().strftime("%Y%m%d_%H%M")
            filename = f"phishguard_report_{domain}_{ts}.html"

            return HTMLResponse(
                content=html,
                headers={
                    "Content-Disposition": f'attachment; filename="{filename}"',
                    "Content-Type": "text/html; charset=utf-8",
                }
            )

        except ValueError as e:
            # GROQ_API_KEY not set
            raise HTTPException(status_code=503, detail=str(e))
        except Exception as e:
            logger.error(traceback.format_exc())
            raise HTTPException(status_code=500, detail=f"Report generation failed: {str(e)}")

    return router
