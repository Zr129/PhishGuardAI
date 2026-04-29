"""
HTTP controller — thin layer between FastAPI and the service.

Accepts URLAnalyser via build_router() factory so it has
no direct import of service internals (DIP at the HTTP layer).
"""

import logging
import traceback

from fastapi import APIRouter, HTTPException, Request
from slowapi import Limiter

from models.models import URLRequest, AnalysisResult
from services.url_analysis import URLAnalyser

logger = logging.getLogger("PhishGuard")


def build_router(analyser: URLAnalyser, limiter: Limiter, rate_limit: str) -> APIRouter:

    
    router = APIRouter()

    @router.post("/analyse", response_model=AnalysisResult)
    @limiter.limit(rate_limit)

    def analyse_url_endpoint(request: Request, body: URLRequest):
        logger.info(f"[REQUEST] {body.url}")

        try:
            result: AnalysisResult = analyser.analyse(body)
            logger.info(f"[RESPONSE] action={result.action} confidence={result.confidence}")

            return result

        except Exception as e:
            logger.error(traceback.format_exc())
            raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

    return router
