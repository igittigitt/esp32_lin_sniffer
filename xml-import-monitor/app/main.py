"""
FastAPI backend for AlfaMediaPlan XML Import Monitor.
"""

import logging
import asyncio
import json
from contextlib import asynccontextmanager
from datetime import date

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse

from log_parser import (
    init_db,
    LogWatcher,
    DirWatcher,
    get_active,
    get_stats_today,
    get_stats_date,
    get_recent_events,
    get_available_dates,
    LOG_FILE,
    SAFEDIR,
    REJECTED,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

# ── Background workers ───────────────────────────────────────────────────────

log_watcher: LogWatcher | None = None
dir_watcher: DirWatcher | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global log_watcher, dir_watcher
    init_db()
    log_watcher = LogWatcher(LOG_FILE)
    dir_watcher = DirWatcher(SAFEDIR, REJECTED)
    log_watcher.start()
    dir_watcher.start()
    logger.info("Watchers started")
    yield
    if log_watcher:
        log_watcher.stop()
    if dir_watcher:
        dir_watcher.stop()
    logger.info("Watchers stopped")


app = FastAPI(title="AlfaXML Import Monitor", lifespan=lifespan)

# ── REST API ─────────────────────────────────────────────────────────────────

@app.get("/api/status")
def api_status():
    """Currently active imports."""
    return {"active": get_active()}


@app.get("/api/stats/today")
def api_stats_today():
    """5-minute slot statistics for today."""
    return {"date": date.today().isoformat(), "slots": get_stats_today()}


@app.get("/api/stats/{day}")
def api_stats_day(day: str):
    """5-minute slot statistics for a specific day (YYYY-MM-DD)."""
    try:
        date.fromisoformat(day)  # validate format
    except ValueError:
        return JSONResponse(status_code=400, content={"error": "Invalid date format, use YYYY-MM-DD"})
    return {"date": day, "slots": get_stats_date(day)}


@app.get("/api/events")
def api_events(limit: int = 50):
    """Recent import events."""
    return {"events": get_recent_events(limit)}


@app.get("/api/dates")
def api_dates():
    """Available dates with data."""
    return {"dates": get_available_dates()}


# ── WebSocket for live updates ───────────────────────────────────────────────

class ConnectionManager:
    def __init__(self):
        self._clients: list[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self._clients.append(ws)

    def disconnect(self, ws: WebSocket):
        self._clients.remove(ws)

    async def broadcast(self, data: dict):
        dead = []
        for ws in self._clients:
            try:
                await ws.send_json(data)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self._clients.remove(ws)


manager = ConnectionManager()


@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await manager.connect(ws)
    try:
        # Send current state immediately on connect
        await ws.send_json({
            "type": "init",
            "active": get_active(),
            "slots": get_stats_today(),
            "events": get_recent_events(20),
        })
        # Keep connection alive; push updates via background task
        while True:
            await asyncio.sleep(1)
            await ws.send_json({
                "type": "update",
                "active": get_active(),
                "slots": get_stats_today(),
            })
    except WebSocketDisconnect:
        manager.disconnect(ws)
    except Exception:
        try:
            manager.disconnect(ws)
        except Exception:
            pass


# ── Static files & SPA fallback ──────────────────────────────────────────────

app.mount("/static", StaticFiles(directory="/app/static"), name="static")


@app.get("/")
def index():
    return FileResponse("/app/static/index.html")
