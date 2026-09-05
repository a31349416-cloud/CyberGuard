"""CSRF Scanner — перевірка форм на CSRF токени"""

import time

import requests
from bs4 import BeautifulSoup


def scan_csrf(url: str, timeout: int = 8) -> dict:
    start = time.time()
    findings = []
    error = None
    if not url.startswith("http"):
        url = "https://" + url
    try:
        r = requests.get(url, timeout=timeout, verify=True)
        try:
            soup = BeautifulSoup(r.text, "lxml")
        except:
            soup = BeautifulSoup(r.text, "html.parser")
        forms = soup.find_all("form")
        if not forms:
            return {
                "scanner": "csrf",
                "findings": [],
                "duration_ms": int((time.time() - start) * 1000),
                "error": None,
            }
        vulnerable = 0
        for form in forms:
            method = form.get("method", "get").lower()
            if method == "get":
                continue
            inputs = [i.get("name", "").lower() for i in form.find_all("input")]
            has_token = any(
                "csrf" in n or "token" in n or "_token" in n for n in inputs
            )
            # Також шукаємо hidden csrf
            hidden = [
                i
                for i in form.find_all("input", {"type": "hidden"})
                if "csrf" in i.get("name", "").lower()
                or "token" in i.get("name", "").lower()
            ]
            if not has_token and not hidden:
                vulnerable += 1
        if vulnerable > 0:
            findings.append(
                {
                    "type": f"CSRF: {vulnerable} forms without token",
                    "severity": "MEDIUM",
                    "score": 15,
                    "description": f"{vulnerable} POST форм без CSRF токена — ризик підробки запитів",
                    "fix": "Додати CSRF токен: <input type=hidden name=csrf_token value={{token}}> + перевірка на бекенді + SameSite=Lax",
                    "owasp_category": "A01:2021 - Broken Access Control",
                    "evidence": f"{vulnerable}/{len(forms)} forms vulnerable",
                }
            )
        # SameSite cookie
        set_cookie = r.headers.get("Set-Cookie", "")
        if set_cookie and "SameSite" not in set_cookie:
            findings.append(
                {
                    "type": "Cookie without SameSite",
                    "severity": "LOW",
                    "score": 5,
                    "description": "Cookies без SameSite — послаблює захист від CSRF",
                    "fix": "Встановити Set-Cookie: SameSite=Lax; Secure",
                    "owasp_category": "A01:2021",
                    "evidence": set_cookie[:120],
                }
            )
    except Exception as e:
        error = str(e)[:300]
    return {
        "scanner": "csrf",
        "findings": findings,
        "duration_ms": int((time.time() - start) * 1000),
        "error": error,
    }
