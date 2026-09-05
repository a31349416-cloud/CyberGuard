"""
SQLite/PostgreSQL база для зберігання історії сканувань
- Якщо DATABASE_URL заданий (postgres://) — використовує PostgreSQL (psycopg2)
- Інакше — SQLite файл scans.db
- Підтримка user_id для ізоляції історії
"""

import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

DB_PATH = Path(__file__).parent / "scans.db"
DATABASE_URL = os.getenv("DATABASE_URL", "")

USE_PG = DATABASE_URL.startswith("postgres")


def _pg_conn(dict_cursor: bool = False):
    import psycopg2
    import psycopg2.extras

    if dict_cursor:
        return psycopg2.connect(
            DATABASE_URL, cursor_factory=psycopg2.extras.RealDictCursor
        )
    return psycopg2.connect(DATABASE_URL)


def get_connection(dict_cursor: bool = False):
    if USE_PG:
        return _pg_conn(dict_cursor=dict_cursor)
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    if USE_PG:
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
                duration_ms INTEGER,
                user_id TEXT DEFAULT 'anonymous',
                owasp_map TEXT DEFAULT '{}'
            )
        """)
        # Міграція: додати колонки якщо таблиця стара
        cur.execute("SELECT column_name FROM information_schema.columns WHERE table_name='scans'")
        cols = {r[0] for r in cur.fetchall()}
        for col, ddl in [("user_id", "ALTER TABLE scans ADD COLUMN user_id TEXT DEFAULT 'anonymous'"), ("owasp_map", "ALTER TABLE scans ADD COLUMN owasp_map TEXT DEFAULT '{}'")]:
            if col not in cols:
                cur.execute(ddl)
        cur.execute(
            "CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(created_at DESC)"
        )
        cur.execute(
            "CREATE INDEX IF NOT EXISTS idx_scans_user ON scans(user_id)"
        )
        conn.commit()
        cur.close()
        conn.close()
        return

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
            duration_ms INTEGER,
            user_id TEXT DEFAULT 'anonymous',
            owasp_map TEXT DEFAULT '{}'
        )
    """)
    # Міграція SQLite: додати колонки якщо немає
    cur.execute("PRAGMA table_info(scans)")
    cols = {r[1] for r in cur.fetchall()}
    if "user_id" not in cols:
        cur.execute("ALTER TABLE scans ADD COLUMN user_id TEXT DEFAULT 'anonymous'")
    if "owasp_map" not in cols:
        cur.execute("ALTER TABLE scans ADD COLUMN owasp_map TEXT DEFAULT '{}'")
    cur.execute(
        "CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(created_at DESC)"
    )
    cur.execute("CREATE INDEX IF NOT EXISTS idx_scans_user ON scans(user_id)")
    conn.commit()
    conn.close()


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


def save_scan(scan_id: str, url: str, status: str = "pending", user_id: str = "anonymous"):
    conn = get_connection()
    cur = conn.cursor()
    if USE_PG:
        cur.execute(
            "INSERT INTO scans (scan_id, url, status, created_at, user_id) VALUES (%s, %s, %s, %s, %s) ON CONFLICT (scan_id) DO UPDATE SET url=EXCLUDED.url, status=EXCLUDED.status",
            (scan_id, url, status, _now_iso(), user_id),
        )
    else:
        cur.execute(
            "INSERT OR REPLACE INTO scans (scan_id, url, status, created_at, user_id) VALUES (?, ?, ?, ?, ?)",
            (scan_id, url, status, _now_iso(), user_id),
        )
    conn.commit()
    try:
        cur.close()
    except:
        pass
    conn.close()


def update_scan(
    scan_id: str,
    status: str | None = None,
    risk_score: int | None = None,
    level: str | None = None,
    findings: list | None = None,
    scanners: list | None = None,
    duration_ms: int | None = None,
    owasp_map: dict | None = None,
):
    conn = get_connection()
    cur = conn.cursor()
    ph = "%s" if USE_PG else "?"
    fields = []
    values = []

    if status is not None:
        fields.append(f"status = {ph}")
        values.append(status)
    if risk_score is not None:
        fields.append(f"risk_score = {ph}")
        values.append(risk_score)
    if level is not None:
        fields.append(f"level = {ph}")
        values.append(level)
    if findings is not None:
        fields.append(f"findings = {ph}")
        values.append(json.dumps(findings, ensure_ascii=False))
    if scanners is not None:
        fields.append(f"scanners = {ph}")
        values.append(json.dumps(scanners, ensure_ascii=False))
    if duration_ms is not None:
        fields.append(f"duration_ms = {ph}")
        values.append(duration_ms)
    if owasp_map is not None:
        fields.append(f"owasp_map = {ph}")
        values.append(json.dumps(owasp_map, ensure_ascii=False))
    if status == "completed":
        fields.append(f"completed_at = {ph}")
        values.append(_now_iso())

    if not fields:
        conn.close()
        return

    values.append(scan_id)
    cur.execute(f"UPDATE scans SET {', '.join(fields)} WHERE scan_id = {ph}", values)
    conn.commit()
    try:
        cur.close()
    except:
        pass
    conn.close()


def get_scan(scan_id: str) -> dict | None:
    conn = get_connection(dict_cursor=USE_PG)
    cur = conn.cursor()
    ph = "%s" if USE_PG else "?"
    cur.execute(f"SELECT * FROM scans WHERE scan_id = {ph}", (scan_id,))
    row = cur.fetchone()
    if not row:
        cur.close()
        conn.close()
        return None
    d = dict(row)
    cur.close()
    conn.close()
    for key in ("findings", "scanners", "owasp_map"):
        try:
            d[key] = json.loads(d[key]) if isinstance(d[key], str) else (d[key] or ([] if key != "owasp_map" else {}))
        except:
            d[key] = [] if key != "owasp_map" else {}
    return d


def get_history(
    limit: int = 50,
    offset: int = 0,
    q: str | None = None,
    level: str | None = None,
    user_id: str | None = None,
) -> list[dict]:
    conn = get_connection(dict_cursor=USE_PG)
    cur = conn.cursor()
    ph = "%s" if USE_PG else "?"
    where = []
    params: list = []
    if q:
        where.append(f"url LIKE {ph}")
        params.append(f"%{q}%")
    if level:
        where.append(f"level = {ph}")
        params.append(level.upper())
    if user_id:
        where.append(f"user_id = {ph}")
        params.append(user_id)
    where_sql = f"WHERE {' AND '.join(where)}" if where else ""
    query = f"SELECT scan_id, url, status, risk_score, level, findings, created_at, completed_at, user_id FROM scans {where_sql} ORDER BY created_at DESC LIMIT {ph} OFFSET {ph}"
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


def delete_scan(scan_id: str, user_id: str | None = None) -> bool:
    conn = get_connection()
    cur = conn.cursor()
    ph = "%s" if USE_PG else "?"
    if user_id:
        cur.execute(f"DELETE FROM scans WHERE scan_id = {ph} AND user_id = {ph}", (scan_id, user_id))
    else:
        cur.execute(f"DELETE FROM scans WHERE scan_id = {ph}", (scan_id,))
    changed = cur.rowcount > 0
    conn.commit()
    cur.close()
    conn.close()
    return changed


def get_trend(url: str, limit: int = 5, user_id: str | None = None) -> list[dict]:
    """Останні скани для URL — для тренду в PDF"""
    conn = get_connection(dict_cursor=USE_PG)
    cur = conn.cursor()
    ph = "%s" if USE_PG else "?"
    where = f"url = {ph}"
    params: list = [url]
    if user_id:
        where += f" AND user_id = {ph}"
        params.append(user_id)
    cur.execute(
        f"SELECT risk_score, level, created_at FROM scans WHERE {where} AND status='completed' ORDER BY created_at DESC LIMIT {ph}",
        params + [limit],
    )
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return [dict(r) for r in rows]


def get_owasp_stats(limit: int = 50) -> dict:
    """Агрегована статистика по OWASP категоріям"""
    conn = get_connection(dict_cursor=USE_PG)
    cur = conn.cursor()
    cur.execute("SELECT findings FROM scans WHERE status='completed' ORDER BY created_at DESC LIMIT %s" if USE_PG else "SELECT findings FROM scans WHERE status='completed' ORDER BY created_at DESC LIMIT ?", (limit,))
    rows = cur.fetchall()
    cur.close()
    conn.close()
    from collections import Counter

    c = Counter()
    for r in rows:
        d = dict(r)
        try:
            findings = json.loads(d["findings"]) if isinstance(d["findings"], str) else d["findings"]
        except:
            continue
        for f in findings:
            cat = (f.get("owasp_category") or "Unknown").split(" -")[0].strip()
            c[cat] += 1
    return dict(c)


# Ініціалізація при імпорті
init_db()
