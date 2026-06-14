import sqlite3
import json
import os
from datetime import datetime, timezone

# DB_PATH is in project root
DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "malscope.db")

def init_db():
    """Create table if not exists. Call once at app startup."""
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS analyses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sha256 TEXT UNIQUE NOT NULL,
            filename TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            verdict TEXT,
            confidence INTEGER,
            full_result TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

def lookup_cache(sha256: str) -> dict | None:
    """Check if SHA256 exists in cache. Return full result or None."""
    init_db()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.execute(
        "SELECT filename, timestamp, verdict, confidence, full_result FROM analyses WHERE sha256 = ?",
        (sha256,)
    )
    row = cursor.fetchone()
    conn.close()
    
    if row is None:
        return None
    
    try:
        result = json.loads(row[4])
    except Exception:
        return None
        
    result["cached"] = True
    result["analyzed_at"] = row[1]
    result["original_filename"] = row[0]
    return result

def store_result(sha256: str, filename: str, result: dict):
    """Store analysis result in cache."""
    init_db()
    verdict = result.get("report", {}).get("verdict", "unknown")
    confidence = result.get("report", {}).get("confidence", 0)
    timestamp = datetime.now(timezone.utc).isoformat()
    
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute(
            "INSERT OR REPLACE INTO analyses (sha256, filename, timestamp, verdict, confidence, full_result) VALUES (?, ?, ?, ?, ?, ?)",
            (sha256, filename, timestamp, verdict, confidence, json.dumps(result))
        )
        conn.commit()
    finally:
        conn.close()

def get_cached_image(sha256: str) -> str | None:
    """Retrieve the base64 image from the cached analysis result."""
    cached = lookup_cache(sha256)
    if not cached:
        return None
    for step in cached.get("steps", []):
        if step.get("tool") == "visualize_pe":
            return step.get("result", {}).get("image_base64")
    return None
