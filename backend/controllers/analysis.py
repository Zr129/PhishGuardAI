from fastapi import APIRouter, HTTPException
from models.models import URLRequest
from services.url_analysis import analyse_url as analyse_url_service

router = APIRouter()

@router.post("/analyse")
def analyse_url_endpoint(request: URLRequest):
    try:
        result = analyse_url_service(request.url)

        return {
            "url": request.url,
            "prediction": result["prediction"],
            "confidence": result["confidence"],
            "reasons": result["reasons"]
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))