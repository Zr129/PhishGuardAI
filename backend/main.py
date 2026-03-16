from fastapi import FastAPI
from controllers.analysis import router

app = FastAPI()

app.include_router(router)

@app.get("/")
def root():
    return {"status": "Phishing detection backend running"}