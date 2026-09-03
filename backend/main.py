"""
CyberGuard FastAPI Backend — v2
- 10 сканерів паралельно через asyncio.gather + ThreadPool
- WebSocket /ws/{scan_id} для live прогресу
- Rate limiting (slowapi) + SSRF/DNS rebinding захист (models.py)
- Redis опційно для scan_status persistence
"""
import asyncio
import uuid
import time
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Dict

from fastapi import FastAPI, HTTPException, BackgroundTasks, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from .models import ScanRequest, ScanResult, ScanStatus, RiskLevel, Finding, ScannerResult
from .database import save_scan, update_scan, get_scan, get_history, init_db
from .risk_engine import calculate_risk, aggregate_findings, sort_findings, get_summary
from .report import generate_pdf
from .scanners.headers import scan_headers
from .scanners.ssl_check import scan_ssl
from .scanners.ports import scan_ports
from .scanners.xss import scan_xss
from .scanners.sqli import scan_sqli
from .scanners.cors_check import scan_cors
from .scanners.csrf import scan_csrf
from .scanners.redirect import scan_redirect
from .scanners.traversal import scan_traversal
from .scanners.security_txt import scan_security_txt

# Rate limiter: 20 scan / хв на IP, 100 результатів / хв
limiter = Limiter(key_func=get_remote_address, default_limits=["100/minute"])

app = FastAPI(
    title="CyberGuard API",
    description="OWASP TOP-10 Security Audit — 10 паралельних сканерів, risk engine, PDF звіти",
    version="2.0.0",
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Scan status: Redis if REDIS_URL set, else in-memory Dict
scan_status: Dict[str, dict] = {}
redis_client = None
try:
    redis_url = os.getenv("REDIS_URL")
    if redis_url:
        import redis
        redis_client = redis.from_url(redis_url, decode_responses=True)
        redis_client.ping()
        print(f"[CyberGuard] Redis connected: {redis_url[:30]}...")
    else:
        print("[CyberGuard] REDIS_URL not set — using in-memory scan_status")
except Exception as e:
    print(f"[CyberGuard] Redis unavailable ({e}) — fallback to memory")
    redis_client = None

def _status_set(scan_id: str, data: dict):
    scan_status[scan_id] = data
    if redis_client:
        try:
            redis_client.setex(f"scan:{scan_id}", 3600, json.dumps(data, ensure_ascii=False))
        except Exception:
            pass

def _status_get(scan_id: str):
    if scan_id in scan_status:
        return scan_status[scan_id]
    if redis_client:
        try:
            raw = redis_client.get(f"scan:{scan_id}")
            if raw:
                return json.loads(raw)
        except Exception:
            pass
    return None

def _status_pop(scan_id: str):
    scan_status.pop(scan_id, None)
    if redis_client:
        try:
            redis_client.delete(f"scan:{scan_id}")
        except Exception:
            pass

# WebSocket connections per scan_id
ws_connections: Dict[str, list] = {}

async def _ws_broadcast(scan_id: str, payload: dict):
    conns = ws_connections.get(scan_id, [])
    dead = []
    for ws in conns:
        try:
            await ws.send_json(payload)
        except Exception:
            dead.append(ws)
    for ws in dead:
        conns.remove(ws)

import concurrent.futures
executor = concurrent.futures.ThreadPoolExecutor(max_workers=16)

async def run_scanners_parallel(url: str, scan_id: str = None) -> list:
    """
    10 сканерів паралельно. Порти + SSL важчі, решта швидкі.
    """
    loop = asyncio.get_event_loop()

    # Окремо бродкастимо прогрес через WS
    async def run_with_progress(name, func):
        if scan_id:
            await _ws_broadcast(scan_id, {"event": "scanner_start", "scanner": name})
        res = await loop.run_in_executor(executor, func, url)
        if scan_id:
            await _ws_broadcast(scan_id, {"event": "scanner_done", "scanner": name, "findings": len(res.get("findings", []))})
        return res

    # Запускаємо через gather
    tasks = [
        run_with_progress("headers", scan_headers),
        run_with_progress("ssl", scan_ssl),
        run_with_progress("ports", scan_ports),
        run_with_progress("xss", scan_xss),
        run_with_progress("sqli", scan_sqli),
        run_with_progress("cors", scan_cors),
        run_with_progress("csrf", scan_csrf),
        run_with_progress("redirect", scan_redirect),
        run_with_progress("traversal", scan_traversal),
        run_with_progress("security_txt", scan_security_txt),
    ]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    scanner_names = ["headers", "ssl", "ports", "xss", "sqli", "cors", "csrf", "redirect", "traversal", "security_txt"]
    cleaned = []
    for i, r in enumerate(results):
        if isinstance(r, Exception):
            cleaned.append({
                "scanner": scanner_names[i],
                "findings": [{"type": f"{scanner_names[i]} Scanner Error", "severity": "LOW", "score": 0, "description": str(r)[:200], "fix": "Перевірити логи", "owasp_category": "N/A"}],
                "duration_ms": 0, "error": str(r)[:300],
            })
        else:
            cleaned.append(r)
    return cleaned

async def perform_scan(scan_id: str, url: str):
    start = time.time()
    _status_set(scan_id, {"status": "running", "progress": 10, "message": "Запускаємо 10 сканерів...", "url": url})
    await _ws_broadcast(scan_id, {"event": "progress", "progress": 10, "message": "Запускаємо 10 сканерів..."})

    try:
        _status_set(scan_id, {"status": "running", "progress": 30, "message": "Скануємо headers, SSL, ports, XSS, SQLi, CORS, CSRF, redirect, traversal, security.txt паралельно...", "url": url})
        await _ws_broadcast(scan_id, {"event": "progress", "progress": 30, "message": "Скануємо паралельно..."})

        scanner_results = await run_scanners_parallel(url, scan_id)

        _status_set(scan_id, {"status": "running", "progress": 80, "message": "Агрегуємо результати та рахуємо ризик...", "url": url})
        await _ws_broadcast(scan_id, {"event": "progress", "progress": 80, "message": "Агрегуємо..."})
        all_findings = aggregate_findings(scanner_results)
        all_findings = sort_findings(all_findings)
        risk_score, level = calculate_risk(all_findings)
        findings_dicts = [f.model_dump() if hasattr(f, "model_dump") else f for f in all_findings]
        duration_ms = int((time.time() - start) * 1000)
        update_scan(scan_id, status="completed", risk_score=risk_score, level=level.value, findings=findings_dicts, scanners=scanner_results, duration_ms=duration_ms)
        final = {"status": "completed", "progress": 100, "message": "Готово!", "risk_score": risk_score, "level": level.value, "findings": findings_dicts, "scanners": scanner_results, "duration_ms": duration_ms, "url": url}
        _status_set(scan_id, final)
        await _ws_broadcast(scan_id, {"event": "completed", "progress": 100, "risk_score": risk_score, "level": level.value, "findings": findings_dicts})
    except Exception as e:
        update_scan(scan_id, status="failed")
        err = {"status": "failed", "progress": 0, "message": f"Помилка: {str(e)[:200]}", "error": str(e)[:500], "url": url}
        _status_set(scan_id, err)
        await _ws_broadcast(scan_id, {"event": "failed", "message": str(e)[:200]})

# ============ API ============

@app.get("/api/health")
async def health():
    return {"status": "ok", "service": "CyberGuard", "version": "2.0.0", "scanners": 10}

@app.post("/api/scan")
@limiter.limit("20/minute")
async def create_scan(req: ScanRequest, request: Request, background_tasks: BackgroundTasks):
    url = req.url
    scan_id = uuid.uuid4().hex[:8]
    save_scan(scan_id, url, status="running")
    _status_set(scan_id, {"status": "running", "progress": 5, "message": "Ініціалізація...", "url": url})
    background_tasks.add_task(perform_scan, scan_id, url)
    return {"scan_id": scan_id, "url": url, "status": "running", "message": "Сканування запущено. WS: /ws/{scan_id} або polling /api/result/{scan_id}"}

@app.get("/api/result/{scan_id}")
@limiter.limit("100/minute")
async def get_result(scan_id: str, request: Request):
    s = _status_get(scan_id)
    if s:
        if s["status"] in ("running", "pending"):
            return {"scan_id": scan_id, "status": s["status"], "progress": s.get("progress", 0), "message": s.get("message", ""), "url": s.get("url", "")}
        elif s["status"] == "completed":
            db_data = get_scan(scan_id)
            if db_data:
                return {"scan_id": scan_id, "url": db_data["url"], "status": "completed", "progress": 100, "risk_score": db_data["risk_score"], "level": db_data["level"], "findings": db_data["findings"], "scanners": db_data["scanners"], "created_at": db_data["created_at"], "completed_at": db_data["completed_at"], "duration_ms": db_data["duration_ms"], "summary": get_summary([Finding(**f) for f in db_data["findings"]] if db_data["findings"] else [])}
            return {"scan_id": scan_id, "status": "completed", "progress": 100, "risk_score": s.get("risk_score", 0), "level": s.get("level", "LOW"), "findings": s.get("findings", []), "scanners": s.get("scanners", []), "duration_ms": s.get("duration_ms", 0)}
        elif s["status"] == "failed":
            return {"scan_id": scan_id, "status": "failed", "progress": 0, "message": s.get("message", "Scan failed"), "error": s.get("error", "")}
    db_data = get_scan(scan_id)
    if db_data:
        if db_data["status"] == "completed":
            findings_objs = []
            for f in db_data["findings"]:
                try: findings_objs.append(Finding(**f))
                except: continue
            return {"scan_id": scan_id, "url": db_data["url"], "status": db_data["status"], "progress": 100 if db_data["status"] == "completed" else 0, "risk_score": db_data["risk_score"], "level": db_data["level"], "findings": db_data["findings"], "scanners": db_data["scanners"], "created_at": db_data["created_at"], "completed_at": db_data["completed_at"], "duration_ms": db_data["duration_ms"], "summary": get_summary(findings_objs)}
        else:
            return {"scan_id": scan_id, "url": db_data["url"], "status": db_data["status"], "progress": 50 if db_data["status"] == "running" else 0, "risk_score": db_data["risk_score"], "level": db_data["level"]}
    raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")

@app.websocket("/ws/{scan_id}")
async def ws_progress(websocket: WebSocket, scan_id: str):
    await websocket.accept()
    if scan_id not in ws_connections:
        ws_connections[scan_id] = []
    ws_connections[scan_id].append(websocket)
    # Відразу відправ поточний статус
    s = _status_get(scan_id)
    if s:
        await websocket.send_json({"event": "init", **{k: v for k, v in s.items() if k not in ("findings", "scanners")}, "findings_count": len(s.get("findings", []))})
    else:
        db_data = get_scan(scan_id)
        if db_data:
            await websocket.send_json({"event": "init", "status": db_data["status"], "progress": 100 if db_data["status"] == "completed" else 50})
        else:
            await websocket.send_json({"event": "error", "message": "scan_id not found"})
    try:
        while True:
            await websocket.receive_text()  # keep alive, ignore
    except WebSocketDisconnect:
        pass
    finally:
        if scan_id in ws_connections and websocket in ws_connections[scan_id]:
            ws_connections[scan_id].remove(websocket)

@app.get("/api/history")
@limiter.limit("100/minute")
async def history(request: Request, limit: int = 50, offset: int = 0, q: str = None, level: str = None):
    limit = min(limit, 100)
    items = get_history(limit=limit, offset=offset, q=q, level=level)
    return {"history": items, "count": len(items), "limit": limit, "offset": offset, "q": q, "level": level}

@app.get("/api/compare")
async def compare(ids: str):
    """Порівняння 2 сканів: /api/compare?ids=a1b2c3,d4e5f6"""
    parts = [p.strip() for p in ids.split(",") if p.strip()][:2]
    if len(parts) < 2:
        raise HTTPException(status_code=400, detail="Потрібно 2 scan_id: ?ids=id1,id2")
    out = []
    for sid in parts:
        d = get_scan(sid)
        if not d:
            raise HTTPException(status_code=404, detail=f"Scan {sid} not found")
        out.append(d)
    # diff
    types_a = {f.get("type") for f in out[0].get("findings", [])}
    types_b = {f.get("type") for f in out[1].get("findings", [])}
    return {
        "scans": out,
        "diff": {
            "only_in_first": sorted(types_a - types_b),
            "only_in_second": sorted(types_b - types_a),
            "common": sorted(types_a & types_b),
            "score_delta": out[1].get("risk_score", 0) - out[0].get("risk_score", 0),
        }
    }

@app.get("/api/export/{scan_id}")
async def export_csv(scan_id: str):
    """CSV експорт findings"""
    import csv, io
    db_data = get_scan(scan_id)
    if not db_data:
        raise HTTPException(status_code=404, detail="Scan not found")
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["type", "severity", "score", "description", "fix", "owasp", "evidence"])
    for f in db_data.get("findings", []):
        writer.writerow([f.get("type",""), f.get("severity",""), f.get("score",""), f.get("description",""), f.get("fix",""), f.get("owasp_category",""), f.get("evidence","")])
    from fastapi.responses import Response
    return Response(content=output.getvalue(), media_type="text/csv", headers={"Content-Disposition": f"attachment; filename=CyberGuard_{scan_id}.csv"})

@app.delete("/api/history/{scan_id}")
async def delete_history(scan_id: str):
    from .database import delete_scan
    _status_pop(scan_id)
    ok = delete_scan(scan_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {"deleted": scan_id}

@app.get("/api/report/{scan_id}")
async def download_report(scan_id: str):
    db_data = get_scan(scan_id)
    if not db_data:
        raise HTTPException(status_code=404, detail="Scan not found")
    if db_data["status"] != "completed":
        raise HTTPException(status_code=400, detail="Scan not completed yet")
    pdf_path = generate_pdf(db_data)
    return FileResponse(pdf_path, media_type="application/pdf", filename=f"CyberGuard_{scan_id}.pdf", headers={"Content-Disposition": f"attachment; filename=CyberGuard_{scan_id}.pdf"})

# Статика
frontend_path = Path(__file__).parent.parent / "frontend"
if frontend_path.exists():
    try:
        app.mount("/", StaticFiles(directory=str(frontend_path), html=True), name="frontend")
    except Exception:
        pass
