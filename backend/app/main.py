from fastapi import FastAPI
from app.core.config import settings

app = FastAPI(
    title=settings.APP_NAME,
    description="AI-Based Phishing Website Detection API using URL and HTML Content Analysis.",
    version="0.1.0",
)


@app.get("/health", summary="Health Check")
async def health_check():
    return {"status": "ok"}
