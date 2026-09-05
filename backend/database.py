"""
SQLite база для зберігання історії сканувань
"""

import json
import sqlite3
from datetime import datetime
from pathlib import Path

DB_PATH = Path(__file__).parent / "scans.db"


def get_connection():
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            scan_id TEXT PRIMARY KEY,
            url TEXT NOT NULL,
            status TEXT NOT NULL,
            risk_score INTEGER DEFAULT 0,
            level TEXT DEFAULT 'LOW',
            findings TEXT DEFAULT '[]',
            scanners TEXT DEFAULT '[]',
            created_at TEXT NOT NULL,
            completed_at TEXT,
            duration_ms INTEGER
        )
    """)
    cur.execute(
        "CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(created_at DESC)"
    )
    conn.commit()
    conn.close()


def save_scan(scan_id: str, url: str, status: str = "pending"):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "INSERT OR REPLACE INTO scans (scan_id, url, status, created_at) VALUES (?, ?, ?, ?)",
        (scan_id, url, status, datetime.utcnow().isoformat()),
    )
    conn.commit()
    conn.close()


def update_scan(
    scan_id: str,
    status: str | None = None,
    risk_score: int | None = None,
    level: str | None = None,
    findings: list | None = None,
    scanners: list | None = None,
    duration_ms: int | None = None,
):
    conn = get_connection()
    cur = conn.cursor()
    fields = []
    values = []

    if status is not None:
        fields.append("status = ?")
        values.append(status)
    if risk_score is not None:
        fields.append("risk_score = ?")
        values.append(risk_score)
    if level is not None:
        fields.append("level = ?")
        values.append(level)
    if findings is not None:
        fields.append("findings = ?")
        values.append(json.dumps(findings, ensure_ascii=False))
    if scanners is not None:
        fields.append("scanners = ?")
        values.append(json.dumps(scanners, ensure_ascii=False))
    if duration_ms is not None:
        fields.append("duration_ms = ?")
        values.append(duration_ms)
    if status == "completed":
        fields.append("completed_at = ?")
        values.append(datetime.utcnow().isoformat())

    if not fields:
        conn.close()
        return

    values.append(scan_id)
    cur.execute(f"UPDATE scans SET {', '.join(fields)} WHERE scan_id = ?", values)
    conn.commit()
    conn.close()


def get_scan(scan_id: str) -> dict | None:
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM scans WHERE scan_id = ?", (scan_id,))
    row = cur.fetchone()
    conn.close()
    if not row:
        return None
    d = dict(row)
    # Парсимо JSON поля
    for key in ("findings", "scanners"):
        try:
            d[key] = json.loads(d[key]) if isinstance(d[key], str) else (d[key] or [])
        except:
            d[key] = []
    return d


def get_history(
    limit: int = 50, offset: int = 0, q: str | None = None, level: str | None = None
) -> list[dict]:
    conn = get_connection()
    cur = conn.cursor()
    # Фільтри q (пошук по url) та level
    where = []
    params = []
    if q:
        where.append("url LIKE ?")
        params.append(f"%{q}%")
    if level:
        where.append("level = ?")
        params.append(level.upper())
    where_sql = f"WHERE {' AND '.join(where)}" if where else ""
    query = f"SELECT scan_id, url, status, risk_score, level, findings, created_at, completed_at FROM scans {where_sql} ORDER BY created_at DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])
    cur.execute(query, params)
    rows = cur.fetchall()
    conn.close()
    result = []
    for row in rows:
        d = dict(row)
        try:
            findings = (
                json.loads(d["findings"]) if isinstance(d["findings"], str) else []
            )
        except:
            findings = []
        result.append(
            {
                "scan_id": d["scan_id"],
                "url": d["url"],
                "status": d["status"],
                "risk_score": d["risk_score"],
                "level": d["level"],
                "findings_count": len(findings),
                "created_at": d["created_at"],
                "completed_at": d["completed_at"],
            }
        )
    return result


def delete_scan(scan_id: str) -> bool:
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM scans WHERE scan_id = ?", (scan_id,))
    changed = cur.rowcount > 0
    conn.commit()
    conn.close()
    return changed


# Ініціалізація при імпорті
init_db()
