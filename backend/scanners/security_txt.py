"""security.txt + well-known checks"""

import time

import requests


def scan_security_txt(url: str, timeout: int = 8) -> dict:
    start = time.time()
    findings = []
    error = None
    if not url.startswith("http"):
        url = "https://" + url.rstrip("/")
    try:
        url.split("?")[0].rstrip("/")
        # Витягуємо origin
        from urllib.parse import urlparse

        parsed = urlparse(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        # 1. security.txt
        for path in ["/.well-known/security.txt", "/security.txt"]:
            try:
                r = requests.get(origin + path, timeout=4, verify=True)
                if r.status_code == 200 and "Contact:" in r.text:
                    break
            except:
                continue
        else:
            findings.append(
                {
                    "type": "Missing security.txt",
                    "severity": "LOW",
                    "score": 5,
                    "description": "Відсутній /.well-known/security.txt — ускладнює responsible disclosure",
                    "fix": "Додати security.txt з Contact: та Expires: https://securitytxt.org/",
                    "owasp_category": "A05:2021",
                    "evidence": "404 for /.well-known/security.txt",
                }
            )
        # 2. robots.txt інфо
        try:
            r = requests.get(origin + "/robots.txt", timeout=4, verify=True)
            if r.status_code == 200 and "Disallow:" in r.text and len(r.text) > 500:
                # Багато Disallow — може розкривати адмін шляхи
                pass
        except:
            pass
    except Exception as e:
        error = str(e)[:300]
    return {
        "scanner": "security_txt",
        "findings": findings,
        "duration_ms": int((time.time() - start) * 1000),
        "error": error,
    }
