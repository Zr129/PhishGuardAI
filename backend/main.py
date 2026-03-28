from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from controllers.analysis import router

app = FastAPI()

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
#chrome-extension://jalianmoiocjfglkikmfdpaphlafccic
# Include routes
app.include_router(router)