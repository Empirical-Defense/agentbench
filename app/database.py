from __future__ import annotations

import logging
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

DB_PATH = Path(__file__).resolve().parent.parent / "agentbench.db"
_db_initialized = False


def init_db(db_path: Path = DB_PATH) -> None:
    """Initialize database schema. Call once at application startup."""
    global _db_initialized
    if _db_initialized:
        return
    
    try:
        with sqlite3.connect(db_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS test_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    control_id TEXT NOT NULL,
                    prompt TEXT NOT NULL,
                    response TEXT NOT NULL,
                    result TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    timestamp TEXT NOT NULL
                )
                """
            )
        _db_initialized = True
        logger.debug(f"Database initialized at {db_path}")
    except sqlite3.Error as e:
        logger.error(f"Failed to initialize database: {e}")
        raise


def persist_result(
    control_id: str,
    prompt: str,
    response: str,
    result: str,
    reason: str,
    db_path: Path = DB_PATH,
) -> None:
    """Persist a test result to the database."""
    timestamp = datetime.now(timezone.utc).isoformat()
    try:
        with sqlite3.connect(db_path) as conn:
            conn.execute(
                """
                INSERT INTO test_results (control_id, prompt, response, result, reason, timestamp)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (control_id, prompt, response, result, reason, timestamp),
            )
        logger.debug(f"Persisted result for {control_id}: {result}")
    except sqlite3.Error as e:
        logger.error(f"Failed to persist result for {control_id}: {e}")
        raise
