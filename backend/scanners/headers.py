"""
Headers Scanner — перевірка security headers (OWASP A05:2021)
"""
import time
import requests
from typing import List

# Ініціалізуємо findings як dict для сумісності з risk_engine
REQUIRED_HEADERS = {
    "Content-Security-Policy": {
        "severity": "MEDIUM",
        "score": 15,
        "owasp": "A05:2021 - Security Misconfiguration",
        "description": "Відсутній Content-Security-Policy - ризик XSS та data injection",
        "fix": "Додати header: Content-Security-Policy: default-src 'self'; script-src 'self'",
    },
    "Strict-Transport-Security": {
        "severity": "MEDIUM",
        "score": 15,
        "owasp": "A05:2021 - Security Misconfiguration",
        "description": "Відсутній HSTS - ризик downgrade атак та cookie hijacking",
        "fix": "Додати header: Strict-Transport-Security: max-age=31536000; includeSubDomains",
    },
    "X-Frame-Options": {
        "severity": "LOW",
        "score": 5,
        "owasp": "A01:2021 - Broken Access Control",
        "description": "Відсутній X-Frame-Options - ризик Clickjacking",
        "fix": "Додати header: X-Frame-Options: DENY або SAMEORIGIN",
    },
    "X-Content-Type-Options": {
        "severity": "LOW",
        "score": 5,
        "owasp": "A05:2021 - Security Misconfiguration",
        "description": "Відсутній X-Content-Type-Options - ризик MIME sniffing",
        "fix": "Додати header: X-Content-Type-Options: nosniff",
    },
    "Referrer-Policy": {
        "severity": "LOW",
        "score": 5,
        "owasp": "A01:2021 - Broken Access Control",
        "description": "Відсутній Referrer-Policy - витік URL у referrer",
        "fix": "Додати header: Referrer-Policy: strict-origin-when-cross-origin",
    },
    "Permissions-Policy": {
        "severity": "LOW",
        "score": 5,
        "owasp": "A05:2021 - Security Misconfiguration",
        "description": "Відсутній Permissions-Policy - не обмежено доступ до sensitive API",
        "fix": "Додати header: Permissions-Policy: geolocation=(), microphone=()",
    },
}


ADDITIONAL_CHECKS = {
    "Server": {
        "check": lambda v: v is not None and v != "",
        "severity": "LOW",
        "score": 5,
        "type": "Information Disclosure: Server header",
        "description": "Header Server розкриває інформацію про сервер (версія, ПЗ)",
        "fix": "Приховати або замінити Server header: server_tokens off; (nginx)",
        "owasp": "A01:2021 - Broken Access Control",
    },
    "X-Powered-By": {
        "check": lambda v: v is not None,
        "severity": "LOW",
        "score": 5,
        "type": "Information Disclosure: X-Powered-By",
        "description": "Header X-Powered-By розкриває технологічний стек",
        "fix": "Видалити header: expose_php Off, або helmet.hidePoweredBy()",
        "owasp": "A05:2021",
    },
}


def scan_headers(url: str, timeout: int = 8) -> dict:
    """
    Сканує security headers. Повертає dict з findings.
    """
    start = time.time()
    findings: List[dict] = []
    error = None

    try:
        headers = {
            "User-Agent": "CyberGuard/1.0 Security Scanner (OWASP Audit)"
        }
        resp = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True, verify=True)
        resp_headers = {k.lower(): v for k, v in resp.headers.items()}

        # Перевірка обов'язкових headers
        for hdr, meta in REQUIRED_HEADERS.items():
            if hdr.lower() not in resp_headers:
                findings.append({
                    "type": f"Missing {hdr}",
                    "severity": meta["severity"],
                    "score": meta["score"],
                    "description": meta["description"],
                    "fix": meta["fix"],
                    "owasp_category": meta["owasp"],
                    "evidence": f"Header '{hdr}' not found in response",
                })
            else:
                # Додаткові перевірки значень
                val = resp_headers[hdr.lower()]
                if hdr == "Strict-Transport-Security" and "max-age" not in val.lower():
                    findings.append({
                        "type": "Weak HSTS",
                        "severity": "LOW",
                        "score": 5,
                        "description": "HSTS присутній але без max-age - неефективний",
                        "fix": "Встановити HSTS з max-age >= 31536000",
                        "owasp_category": "A05:2021",
                        "evidence": f"HSTS value: {val}",
                    })
                if hdr == "X-Frame-Options" and val.lower() not in ("deny", "sameorigin"):
                    findings.append({
                        "type": "Weak X-Frame-Options",
                        "severity": "LOW",
                        "score": 5,
                        "description": f"X-Frame-Options має неочікуване значення: {val}",
                        "fix": "Встановити X-Frame-Options: DENY або SAMEORIGIN",
                        "owasp_category": "A01:2021",
                        "evidence": val,
                    })

        # Перевірка інформаційних витоків
        for hdr, meta in ADDITIONAL_CHECKS.items():
            val = resp.headers.get(hdr)
            if meta["check"](val):
                findings.append({
                    "type": meta["type"],
                    "severity": meta["severity"],
                    "score": meta["score"],
                    "description": meta["description"],
                    "fix": meta["fix"],
                    "owasp_category": meta["owasp"],
                    "evidence": f"{hdr}: {val}",
                })

        # Перевірка cookie flags
        cookies = resp.headers.get("Set-Cookie", "")
        if cookies:
            if "Secure" not in cookies:
                findings.append({
                    "type": "Cookie without Secure flag",
                    "severity": "MEDIUM",
                    "score": 10,
                    "description": "Cookie без Secure flag може передаватись по HTTP",
                    "fix": "Додати Secure та HttpOnly до всіх cookies",
                    "owasp_category": "A05:2021",
                    "evidence": cookies[:120],
                })
            if "HttpOnly" not in cookies:
                findings.append({
                    "type": "Cookie without HttpOnly",
                    "severity": "MEDIUM",
                    "score": 10,
                    "description": "Cookie без HttpOnly доступна з JavaScript - ризик XSS крадіжки",
                    "fix": "Додати HttpOnly flag до cookies",
                    "owasp_category": "A03:2021 - Injection",
                    "evidence": cookies[:120],
                })

    except requests.exceptions.SSLError as e:
        error = f"SSL error: {str(e)[:200]}"
        findings.append({
            "type": "SSL/TLS Error",
            "severity": "HIGH",
            "score": 25,
            "description": f"SSL помилка при запиті: {error}",
            "fix": "Перевірити SSL сертифікат та налаштування TLS",
            "owasp_category": "A05:2021",
            "evidence": error,
        })
    except Exception as e:
        error = str(e)[:300]
        findings.append({
            "type": "Headers Scan Failed",
            "severity": "LOW",
            "score": 0,
            "description": f"Не вдалося виконати перевірку заголовків: {error}",
            "fix": "Перевірити доступність сайту",
            "owasp_category": "N/A",
            "evidence": error,
        })

    duration = int((time.time() - start) * 1000)
    return {
        "scanner": "headers",
        "findings": findings,
        "duration_ms": duration,
        "error": error,
    }
