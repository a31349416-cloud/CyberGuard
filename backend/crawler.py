"""
Crawler — BFS same-origin, до 4 сторінок
Опційно Playwright для SPA (якщо встановлено)
"""
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import time

def crawl_same_origin(start_url: str, max_pages: int = 20, timeout: int = 5) -> list[str]:
    if not start_url.startswith("http"):
        start_url = "https://" + start_url
    parsed = urlparse(start_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    visited = set()
    to_visit = [start_url]
    result = []
    session = requests.Session()
    session.headers.update({"User-Agent": "CyberGuard/1.0 Crawler v3 (20 pages)"})
    while to_visit and len(result) < max_pages:
        url = to_visit.pop(0)
        if url in visited:
            continue
        visited.add(url)
        try:
            # Спробувати Playwright якщо є і якщо сторінка важка (SPA)
            # Поки що використовуємо requests, Playwright — опційно
            r = session.get(url, timeout=timeout, verify=True)
            if "text/html" not in r.headers.get("Content-Type", ""):
                result.append(url)
                continue
            result.append(url)
            try:
                soup = BeautifulSoup(r.text, "lxml")
            except:
                soup = BeautifulSoup(r.text, "html.parser")
            for a in soup.find_all("a", href=True):
                href = a["href"]
                full = urljoin(url, href)
                p = urlparse(full)
                # same-origin + http(s) тільки
                if p.scheme not in ("http", "https"):
                    continue
                if f"{p.scheme}://{p.netloc}" != origin:
                    continue
                # фільтр
                if any(x in full for x in ["#", "mailto:", "tel:", ".pdf", ".jpg", ".png", ".zip"]):
                    continue
                # нормалізувати (без фрагменту)
                full = full.split("#")[0].rstrip("/")
                if full not in visited and full not in to_visit and full != url:
                    to_visit.append(full)
                    if len(to_visit) > 20:
                        break
        except Exception:
            result.append(url)
            continue
    return result[:max_pages]

def try_playwright_fetch(url: str, timeout: int = 8000) -> str | None:
    """Опційно: якщо playwright встановлено, відрендерити SPA"""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return None
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            page.goto(url, wait_until="networkidle", timeout=timeout)
            content = page.content()
            browser.close()
            return content
    except Exception:
        return None
