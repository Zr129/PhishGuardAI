from fastapi import APIRouter, HTTPException
from models.models import URLRequest
import traceback
from services.url_analysis import URLAnalyser


router = APIRouter()
analyser = URLAnalyser()

@router.post("/analyse")
def analyse_url_endpoint(request: URLRequest):


    print("Received features:")
    print(request)
    try:
        result = analyser.analyse(request)
        print(f"Result: {result['action']} | Reasons: {result['reasons']}")

        return {
            "url": request.url,
            "action": result["action"],
            "prediction": result["prediction"],
            "confidence": result["confidence"],
            "reasons": result["reasons"]
        }

    except Exception as e:
        print(traceback.format_exc())
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")
    