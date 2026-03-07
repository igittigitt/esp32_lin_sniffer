"""
Log parser for AlfaMediaPlan XML import monitoring.
Watches /home/ngio/LogFile and directory changes in SafeDir/Rejected.
"""

import re
import os
import time
import threading
import sqlite3
from datetime import datetime, date
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import Optional
import logging

logger = logging.getLogger(__name__)

# Regex patterns for log lines
# Example: <user:ngio> NOTICE APPL 10:07:37 AlfaMediaPlan_ImportXml_IOScript: Called with ...
RE_TIMESTAMP = re.compile(
    r'<user:\w+>\s+\w+\s+\w+\s+(\d{2}:\d{2}:\d{2})\s+AlfaMediaPlan_ImportXml_IOScript:\s+(.*)'
)

PATTERN_CALLED   = re.compile(r"Called with\s+'?([^'\s]+)'?")
PATTERN_MANAGED  = re.compile(r"Managed to handle\s+'?([^']+)'?")
PATTERN_DONE     = re.compile(r"Done\s+'?([^']+)'?")
PATTERN_FAILED   = re.compile(r"(?:Failed|Error|Rejected)\s+'?([^']+)'?", re.IGNORECASE)


@dataclass
class ImportEvent:
    filename: str
    status: str          # "processing" | "success" | "rejected" | "failed"
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    log_time: Optional[str] = None  # HH:MM:SS from log


DB_PATH = os.environ.get("DB_PATH", "/data/monitor.db")
LOG_FILE = os.environ.get("LOG_FILE", "/logs/LogFile")
SAFEDIR  = os.environ.get("SAFEDIR",  "/watch/SafeDir")
REJECTED = os.environ.get("REJECTED", "/watch/Rejected")


def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    con = sqlite3.connect(DB_PATH)
    con.execute("""
        CREATE TABLE IF NOT EXISTS imports (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            filename    TEXT NOT NULL,
            status      TEXT NOT NULL,
            log_date    TEXT NOT NULL,
            log_time    TEXT NOT NULL,
            slot_5min   INTEGER NOT NULL,  -- minutes since midnight, rounded to 5
            created_at  TEXT NOT NULL
        )
    """)
    con.execute("CREATE INDEX IF NOT EXISTS idx_date ON imports(log_date)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_slot ON imports(log_date, slot_5min)")
    con.commit()
    con.close()


def _slot(time_str: str) -> int:
    """Convert HH:MM:SS to 5-minute slot (0..287)."""
    h, m, s = map(int, time_str.split(":"))
    total = h * 60 + m
    return (total // 5) * 5


def record_event(filename: str, status: str, time_str: str, log_date: str = None):
    if log_date is None:
        log_date = date.today().isoformat()
    slot = _slot(time_str)
    con = sqlite3.connect(DB_PATH)
    con.execute(
        "INSERT INTO imports (filename, status, log_date, log_time, slot_5min, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (filename, status, log_date, time_str, slot, datetime.now().isoformat())
    )
    con.commit()
    con.close()


def get_stats_today() -> list[dict]:
    """Return per-5min slot counts for today (success + rejected + failed)."""
    today = date.today().isoformat()
    con = sqlite3.connect(DB_PATH)
    rows = con.execute(
        """
        SELECT slot_5min, status, COUNT(*) as cnt
        FROM imports
        WHERE log_date = ?
        GROUP BY slot_5min, status
        """,
        (today,)
    ).fetchall()
    con.close()

    # Build full 0-23:55 grid
    grid: dict[int, dict] = {}
    for minute in range(0, 1440, 5):
        grid[minute] = {"slot": minute, "success": 0, "rejected": 0, "failed": 0, "processing": 0}
    for slot, status, cnt in rows:
        if slot in grid and status in grid[slot]:
            grid[slot][status] = cnt
    return list(grid.values())


def get_stats_date(day: str) -> list[dict]:
    """Return per-5min slot counts for a specific date (YYYY-MM-DD)."""
    con = sqlite3.connect(DB_PATH)
    rows = con.execute(
        """
        SELECT slot_5min, status, COUNT(*) as cnt
        FROM imports
        WHERE log_date = ?
        GROUP BY slot_5min, status
        """,
        (day,)
    ).fetchall()
    con.close()

    grid: dict[int, dict] = {}
    for minute in range(0, 1440, 5):
        grid[minute] = {"slot": minute, "success": 0, "rejected": 0, "failed": 0, "processing": 0}
    for slot, status, cnt in rows:
        if slot in grid and status in grid[slot]:
            grid[slot][status] = cnt
    return list(grid.values())


def get_recent_events(limit: int = 50) -> list[dict]:
    con = sqlite3.connect(DB_PATH)
    rows = con.execute(
        "SELECT filename, status, log_date, log_time, created_at "
        "FROM imports ORDER BY id DESC LIMIT ?",
        (limit,)
    ).fetchall()
    con.close()
    return [
        {"filename": r[0], "status": r[1], "log_date": r[2],
         "log_time": r[3], "created_at": r[4]}
        for r in rows
    ]


def get_available_dates() -> list[str]:
    con = sqlite3.connect(DB_PATH)
    rows = con.execute(
        "SELECT DISTINCT log_date FROM imports ORDER BY log_date DESC LIMIT 30"
    ).fetchall()
    con.close()
    return [r[0] for r in rows]


# ── Active import tracking (in-memory) ──────────────────────────────────────

_active_lock = threading.Lock()
_active: dict[str, dict] = {}   # filename → {started_at, log_time}


def _basename(path_str: str) -> str:
    return Path(path_str.strip("'\" ")).name


def _mark_started(filename: str, time_str: str):
    with _active_lock:
        _active[filename] = {
            "filename": filename,
            "status": "processing",
            "started_at": datetime.now().isoformat(),
            "log_time": time_str,
        }


def _mark_finished(filename: str, status: str, time_str: str):
    with _active_lock:
        _active.pop(filename, None)
    record_event(filename, status, time_str)


def get_active() -> list[dict]:
    with _active_lock:
        return list(_active.values())


# ── Log file tailer ──────────────────────────────────────────────────────────

class LogWatcher(threading.Thread):
    """Continuously tail the main log file and parse import events."""

    def __init__(self, path: str):
        super().__init__(daemon=True, name="LogWatcher")
        self.path = path
        self._stop_event = threading.Event()

    def stop(self):
        self._stop_event.set()

    def run(self):
        logger.info("LogWatcher started, watching %s", self.path)
        while not self._stop_event.is_set():
            try:
                self._tail()
            except Exception as exc:
                logger.warning("LogWatcher error: %s — retrying in 5s", exc)
                time.sleep(5)

    def _tail(self):
        # Wait for file to appear
        while not os.path.exists(self.path):
            logger.debug("Waiting for log file %s ...", self.path)
            time.sleep(2)
            if self._stop_event.is_set():
                return

        with open(self.path, "r", encoding="utf-8", errors="replace") as fh:
            # Seek to end on first open to avoid replaying old history
            fh.seek(0, 2)
            logger.info("LogWatcher: tailing from end of %s", self.path)
            while not self._stop_event.is_set():
                line = fh.readline()
                if not line:
                    time.sleep(0.2)
                    # Re-check if file was rotated
                    try:
                        if os.stat(self.path).st_ino != os.fstat(fh.fileno()).st_ino:
                            logger.info("Log file rotated, reopening")
                            return  # outer loop will reopen
                    except OSError:
                        return
                    continue
                self._parse(line.rstrip())

    def _parse(self, line: str):
        m = RE_TIMESTAMP.search(line)
        if not m:
            return
        time_str, rest = m.group(1), m.group(2)

        if mc := PATTERN_CALLED.search(rest):
            filename = _basename(mc.group(1))
            logger.debug("Import STARTED: %s at %s", filename, time_str)
            _mark_started(filename, time_str)
            record_event(filename, "processing", time_str)

        elif mc := PATTERN_MANAGED.search(rest):
            filename = _basename(mc.group(1))
            logger.debug("Import SUCCESS: %s at %s", filename, time_str)
            _mark_finished(filename, "success", time_str)

        elif mc := PATTERN_DONE.search(rest):
            filename = _basename(mc.group(1))
            # "Done" without prior "Managed to handle" → treat as success
            logger.debug("Import DONE: %s at %s", filename, time_str)
            with _active_lock:
                already_done = filename not in _active
            if not already_done:
                _mark_finished(filename, "success", time_str)

        elif mc := PATTERN_FAILED.search(rest):
            filename = _basename(mc.group(1))
            logger.debug("Import FAILED: %s at %s", filename, time_str)
            _mark_finished(filename, "failed", time_str)


# ── Directory watcher for SafeDir / Rejected ────────────────────────────────

class DirWatcher(threading.Thread):
    """
    Poll SafeDir and Rejected for new files as a fallback / cross-check.
    Files appearing in Rejected are recorded even if the log line was missed.
    """

    POLL_INTERVAL = 10  # seconds

    def __init__(self, safedir: str, rejected: str):
        super().__init__(daemon=True, name="DirWatcher")
        self.safedir  = safedir
        self.rejected = rejected
        self._seen: set[str] = set()
        self._stop_event = threading.Event()

    def stop(self):
        self._stop_event.set()

    def _scan(self, path: str, status: str):
        try:
            for entry in os.scandir(path):
                if entry.is_file() and entry.name not in self._seen:
                    self._seen.add(entry.name)
                    mtime = entry.stat().st_mtime
                    time_str = datetime.fromtimestamp(mtime).strftime("%H:%M:%S")
                    log_date = datetime.fromtimestamp(mtime).date().isoformat()
                    logger.info("DirWatcher: %s → %s", entry.name, status)
                    record_event(entry.name, status, time_str, log_date)
        except FileNotFoundError:
            pass

    def run(self):
        logger.info("DirWatcher started")
        # Pre-populate seen set from existing files so we don't re-record history
        for path in (self.safedir, self.rejected):
            try:
                for entry in os.scandir(path):
                    if entry.is_file():
                        self._seen.add(entry.name)
            except FileNotFoundError:
                pass

        while not self._stop_event.is_set():
            self._scan(self.safedir,  "success")
            self._scan(self.rejected, "rejected")
            self._stop_event.wait(self.POLL_INTERVAL)
