import signal
from fastapi import FastAPI
from autosentou.controllers.jobs_controller import router as jobs_router
from autosentou.database import engine
from autosentou import models

# Create all tables
models.Base.metadata.create_all(bind=engine)

app = FastAPI(title="Automated Pentesting Report Generator")

# Include routes
app.include_router(jobs_router)


@app.get("/")
def root():
    return {"message": "FastAPI Pentesting Backend Running"}


def signal_handler(sig, frame):
    print("Shutting down gracefully…")
    exit(0)


signal.signal(signal.SIGINT, signal_handler)
# ssh kali@192.168.181.128
# uvicorn autosentou.main:app --reload --host 0.0.0.0 --port 8000
