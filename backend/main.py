"""
CyberGuard FastAPI Backend
Паралельний запуск 5 сканерів через asyncio.gather — 8-15 сек замість 60
"""
import asyncio
import uuid
import time
from datetime import datetime
from pathlib import Path
from typing import Dict

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from .models import ScanRequest, ScanResult, ScanStatus, RiskLevel, Finding, ScannerResult
from .database import save_scan, update_scan, get_scan, get_history, init_db
from .risk_engine import calculate_risk, aggregate_findings, sort_findings, get_summary
from .report import generate_pdf
from .scanners.headers import scan_headers
from .scanners.ssl_check import scan_ssl
from .scanners.ports import scan_ports
from .scanners.xss import scan_xss
from .scanners.sqli import scan_sqli

app = FastAPI(
    title="CyberGuard API",
    description="OWASP TOP-10 Security Audit — паралельні сканери, risk engine, PDF звіти",
    version="1.0.0",
)

# CORS для фронтенду
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory статуси (для прогрес-бару) + SQLite як персистентність
scan_status: Dict[str, dict] = {}

# Для запуску sync сканерів в thread pool без блокування event loop
import concurrent.futures

executor = concurrent.futures.ThreadPoolExecutor(max_workers=10)


async def run_scanners_parallel(url: str) -> list:
    """
    Запускає всі 5 сканерів паралельно через asyncio.gather + thread pool
    """
    loop = asyncio.get_event_loop()

    tasks = [
        loop.run_in_executor(executor, scan_headers, url),
        loop.run_in_executor(executor, scan_ssl, url),
        loop.run_in_executor(executor, scan_ports, url),
        loop.run_in_executor(executor, scan_xss, url),
        loop.run_in_executor(executor, scan_sqli, url),
    ]

    results = await asyncio.gather(*tasks, return_exceptions=True)

    # Обробляємо exceptions
    cleaned = []
    scanner_names = ["headers", "ssl", "ports", "xss", "sqli"]
    for i, r in enumerate(results):
        if isinstance(r, Exception):
            cleaned.append({
                "scanner": scanner_names[i],
                "findings": [{
                    "type": f"{scanner_names[i]} Scanner Error",
                    "severity": "LOW",
                    "score": 0,
                    "description": str(r)[:200],
                    "fix": "Перевірити логи сервера",
                    "owasp_category": "N/A",
                }],
                "duration_ms": 0,
                "error": str(r)[:300],
            })
        else:
            cleaned.append(r)
    return cleaned


async def perform_scan(scan_id: str, url: str):
    """
    Background task — виконує сканування, агрегує, рахує ризик, зберігає в БД
    """
    start = time.time()
    scan_status[scan_id] = {"status": "running", "progress": 10, "message": "Запускаємо сканери..."}

    try:
        scan_status[scan_id]["progress"] = 30
        scan_status[scan_id]["message"] = "Скануємо headers, SSL, ports, XSS, SQLi паралельно..."

        scanner_results = await run_scanners_parallel(url)

        scan_status[scan_id]["progress"] = 80
        scan_status[scan_id]["message"] = "Агрегуємо результати та рахуємо ризик..."

        # Агрегація
        all_findings = aggregate_findings(scanner_results)
        all_findings = sort_findings(all_findings)
        risk_score, level = calculate_risk(all_findings)

        # Конвертуємо findings в dict для зберігання
        findings_dicts = [f.model_dump() if hasattr(f, "model_dump") else f for f in all_findings]

        duration_ms = int((time.time() - start) * 1000)

        # Зберігаємо в БД
        update_scan(
            scan_id,
            status="completed",
            risk_score=risk_score,
            level=level.value,
            findings=findings_dicts,
            scanners=scanner_results,
            duration_ms=duration_ms,
        )

        scan_status[scan_id] = {
            "status": "completed",
            "progress": 100,
            "message": "Готово!",
            "risk_score": risk_score,
            "level": level.value,
            "findings": findings_dicts,
            "scanners": scanner_results,
            "duration_ms": duration_ms,
        }

    except Exception as e:
        update_scan(scan_id, status="failed")
        scan_status[scan_id] = {
            "status": "failed",
            "progress": 0,
            "message": f"Помилка: {str(e)[:200]}",
            "error": str(e)[:500],
        }


# ============ API Endpoints ============

@app.get("/api/health")
async def health():
    return {"status": "ok", "service": "CyberGuard", "version": "1.0.0"}


@app.post("/api/scan")
async def create_scan(req: ScanRequest, background_tasks: BackgroundTasks):
    """
    Запускає нове сканування. Повертає scan_id.
    Frontend потім опитує GET /api/result/{scan_id}
    """
    url = req.url  # вже валідований в Pydantic
    scan_id = uuid.uuid4().hex[:8]

    # Зберігаємо в БД та пам'яті
    save_scan(scan_id, url, status="running")
    scan_status[scan_id] = {"status": "running", "progress": 5, "message": "Ініціалізація...", "url": url}

    # Запускаємо в background
    background_tasks.add_task(perform_scan, scan_id, url)

    return {"scan_id": scan_id, "url": url, "status": "running", "message": "Сканування запущено. Опитуйте /api/result/{scan_id}"}


@app.get("/api/result/{scan_id}")
async def get_result(scan_id: str):
    """
    Отримати результат сканування. Підтримує polling для прогрес-бару.
    """
    # Спочатку дивимось в пам'яті (швидко + прогрес)
    if scan_id in scan_status:
        s = scan_status[scan_id]
        if s["status"] in ("running", "pending"):
            return {
                "scan_id": scan_id,
                "status": s["status"],
                "progress": s.get("progress", 0),
                "message": s.get("message", ""),
                "url": s.get("url", ""),
            }
        elif s["status"] == "completed":
            # Віддаємо повний результат
            db_data = get_scan(scan_id)
            if db_data:
                return {
                    "scan_id": scan_id,
                    "url": db_data["url"],
                    "status": "completed",
                    "progress": 100,
                    "risk_score": db_data["risk_score"],
                    "level": db_data["level"],
                    "findings": db_data["findings"],
                    "scanners": db_data["scanners"],
                    "created_at": db_data["created_at"],
                    "completed_at": db_data["completed_at"],
                    "duration_ms": db_data["duration_ms"],
                    "summary": get_summary([Finding(**f) for f in db_data["findings"]] if db_data["findings"] else []),
                }
            # Fallback на memory
            return {
                "scan_id": scan_id,
                "status": "completed",
                "progress": 100,
                "risk_score": s.get("risk_score", 0),
                "level": s.get("level", "LOW"),
                "findings": s.get("findings", []),
                "scanners": s.get("scanners", []),
                "duration_ms": s.get("duration_ms", 0),
            }
        elif s["status"] == "failed":
            return {
                "scan_id": scan_id,
                "status": "failed",
                "progress": 0,
                "message": s.get("message", "Scan failed"),
                "error": s.get("error", ""),
            }

    # Якщо немає в пам'яті — дивимось в БД (після рестарту)
    db_data = get_scan(scan_id)
    if db_data:
        if db_data["status"] == "completed":
            findings_objs = []
            for f in db_data["findings"]:
                try:
                    findings_objs.append(Finding(**f))
                except:
                    continue
            return {
                "scan_id": scan_id,
                "url": db_data["url"],
                "status": db_data["status"],
                "progress": 100 if db_data["status"] == "completed" else 0,
                "risk_score": db_data["risk_score"],
                "level": db_data["level"],
                "findings": db_data["findings"],
                "scanners": db_data["scanners"],
                "created_at": db_data["created_at"],
                "completed_at": db_data["completed_at"],
                "duration_ms": db_data["duration_ms"],
                "summary": get_summary(findings_objs),
            }
        else:
            return {
                "scan_id": scan_id,
                "url": db_data["url"],
                "status": db_data["status"],
                "progress": 50 if db_data["status"] == "running" else 0,
                "risk_score": db_data["risk_score"],
                "level": db_data["level"],
            }

    raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")


@app.get("/api/history")
async def history(limit: int = 50, offset: int = 0):
    limit = min(limit, 100)
    items = get_history(limit=limit, offset=offset)
    return {"history": items, "count": len(items), "limit": limit, "offset": offset}


@app.delete("/api/history/{scan_id}")
async def delete_history(scan_id: str):
    from .database import delete_scan
    # Видаляємо з обох сховищ
    scan_status.pop(scan_id, None)
    ok = delete_scan(scan_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {"deleted": scan_id}


@app.get("/api/report/{scan_id}")
async def download_report(scan_id: str):
    """
    Генерує та віддає PDF звіт
    """
    db_data = get_scan(scan_id)
    if not db_data:
        raise HTTPException(status_code=404, detail="Scan not found")
    if db_data["status"] != "completed":
        raise HTTPException(status_code=400, detail="Scan not completed yet")

    pdf_path = generate_pdf(db_data)
    return FileResponse(
        pdf_path,
        media_type="application/pdf",
        filename=f"CyberGuard_{scan_id}.pdf",
        headers={"Content-Disposition": f"attachment; filename=CyberGuard_{scan_id}.pdf"},
    )


# Статика фронтенду (якщо запускаємо разом)
frontend_path = Path(__file__).parent.parent / "frontend"
if frontend_path.exists():
    try:
        app.mount("/", StaticFiles(directory=str(frontend_path), html=True), name="frontend")
    except Exception:
        pass
