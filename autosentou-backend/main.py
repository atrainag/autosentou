import signal
import logging
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from  controllers.jobs_controller import router as jobs_router
from  database import engine
import models
from services.utils.logging_config import configure_app_logging

# Configure logging first (before anything else)
configure_app_logging()
logger = logging.getLogger(__name__)

logger.info("Starting Automated Pentesting Report Generator")
logger.info("Initializing database and creating tables...")

# Create all tables
models.Base.metadata.create_all(bind=engine)
logger.info("Database tables created successfully")

# Initiate FASTAPI
app = FastAPI(title="Automated Pentesting Report Generator")
logger.info("FastAPI application initialized")

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, replace with specific frontend URL
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
logger.info("CORS middleware configured")

# Include routes
app.include_router(jobs_router)
logger.info("API routes registered")

@app.on_event("startup")
async def startup_event():
    """Log when the application starts."""
    logger.info("=" * 80)
    logger.info("APPLICATION STARTUP COMPLETE")
    logger.info("Automated Pentesting Report Generator is ready to accept requests")
    logger.info("API Documentation available at: /docs")
    logger.info("=" * 80)

@app.on_event("shutdown")
async def shutdown_event():
    """Log when the application shuts down."""
    logger.info("=" * 80)
    logger.info("APPLICATION SHUTDOWN")
    logger.info("=" * 80)

@app.get("/")
def root():
    logger.debug("Root endpoint accessed")
    return {"message": "Pentesting Backend Running"}


def signal_handler(sig, frame):
    logger.warning("Received shutdown signal (SIGINT)")
    logger.info("Shutting down gracefully...")
    exit(0)


signal.signal(signal.SIGINT, signal_handler)
logger.info("Signal handlers configured")
# ssh kali@192.168.181.128
# uvicorn  main:app --reload --host 0.0.0.0 --port 8000
