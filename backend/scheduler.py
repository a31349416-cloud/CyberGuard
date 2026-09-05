"""
Scheduler — щоденні скани через APScheduler
Зберігає jobs в пам'яті (при рестарті зникають, для продакшн треба DB)
Підтримка Telegram сповіщень (TELEGRAM_BOT_TOKEN)
"""
import os
from datetime import datetime
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger

scheduler = BackgroundScheduler()
scheduler.start()

# In-memory jobs meta
jobs_meta: dict[str, dict] = {}

def _run_scheduled(url: str, telegram_chat_id: str | None = None):
    """Виконується по крону — запускає скан через внутрішній API"""
    import requests
    # Локальний виклик через HTTP (якщо сервер на Render, використовує PUBLIC_URL)
    base = os.getenv("PUBLIC_URL", "http://localhost:8000")
    try:
        r = requests.post(f"{base}/api/scan", json={"url": url}, timeout=10)
        sid = r.json().get("scan_id")
        # Telegram
        if telegram_chat_id and os.getenv("TELEGRAM_BOT_TOKEN"):
            token = os.getenv("TELEGRAM_BOT_TOKEN")
            # Не чекаємо результату, просто сповістимо про запуск
            try:
                requests.post(f"https://api.telegram.org/bot{token}/sendMessage", json={"chat_id": telegram_chat_id, "text": f"CyberGuard scheduled scan started: {url} (id {sid})"}, timeout=5)
            except:
                pass
    except Exception as e:
        print(f"[Scheduler] failed {url}: {e}")

def add_job(url: str, cron_expr: str = "0 9 * * *", telegram_chat_id: str | None = None) -> str:
    import uuid
    job_id = uuid.uuid4().hex[:6]
    # cron_expr: "0 9 * * *" -> minute hour day month weekday
    parts = cron_expr.strip().split()
    if len(parts) != 5:
        cron_expr = "0 9 * * *"
        parts = cron_expr.split()
    trigger = CronTrigger(minute=parts[0], hour=parts[1], day=parts[2], month=parts[3], day_of_week=parts[4])
    scheduler.add_job(_run_scheduled, trigger, args=[url, telegram_chat_id], id=job_id, replace_existing=True)
    jobs_meta[job_id] = {"url": url, "cron": cron_expr, "telegram_chat_id": telegram_chat_id, "created": datetime.utcnow().isoformat()}
    return job_id

def remove_job(job_id: str) -> bool:
    try:
        scheduler.remove_job(job_id)
    except:
        return False
    jobs_meta.pop(job_id, None)
    return True

def list_jobs() -> list[dict]:
    out = []
    for j in scheduler.get_jobs():
        meta = jobs_meta.get(j.id, {})
        out.append({"job_id": j.id, "url": meta.get("url"), "cron": meta.get("cron"), "next_run": str(j.next_run_time)})
    return out
