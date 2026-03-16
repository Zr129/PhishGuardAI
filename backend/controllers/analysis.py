from fastapi import APIRouter
from models.models import URLRequest
from services.url_analysis import analyse_url

router = APIRouter()

@router.post("/analyse")
def analyse(request: URLRequest):

    result = analyse_url(request.url)

    return result