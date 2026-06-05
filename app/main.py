from pathlib import Path
import json

from fastapi import FastAPI
from fastapi import Request
from fastapi.responses import JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles

app = FastAPI(title="SentinelOne Jira Dashboard")

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_FILE = BASE_DIR / "latest.json"

app.mount("/static", StaticFiles(directory="app/static"), name="static")

templates = Jinja2Templates(directory="app/templates")


@app.get("/")
def dashboard(request: Request):
    return templates.TemplateResponse(
        "dashboard.html",
        {"request": request}
    )


@app.get("/health")
def health():
    return {"status": "running"}


@app.get("/api/data")
def get_data():

    with open(DATA_FILE, "r") as f:
        return json.load(f)


@app.post("/api/update")
async def update_data(request: Request):

    payload = await request.json()

    with open(DATA_FILE, "w") as f:
        json.dump([payload], f, indent=4)

    return {
        "success": True
    }