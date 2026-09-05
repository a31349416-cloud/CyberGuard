"""CORS Scanner — перевірка Access-Control-Allow-Origin"""

import time

import requests


def scan_cors(url: str, timeout: int = 8) -> dict:
    start = time.time()
    findings = []
    error = None
    if not url.startswith("http"):
        url = "https://" + url
    try:
        headers = {"Origin": "https://evil.com"}
        r = requests.get(url, headers=headers, timeout=timeout, verify=True)
        acao = r.headers.get("Access-Control-Allow-Origin", "")
        acac = r.headers.get("Access-Control-Allow-Credentials", "")
        if acao == "*" and acac.lower() == "true":
            findings.append(
                {
                    "type": "CORS: Wildcard + Credentials",
                    "severity": "HIGH",
                    "score": 25,
                    "description": "Access-Control-Allow-Origin: * з Allow-Credentials: true — будь-який сайт може красти дані",
                    "fix": "Вказати конкретний Origin замість *, або прибрати Allow-Credentials",
                    "owasp_category": "A01:2021 - Broken Access Control",
                    "evidence": f"ACAO: {acao}, ACAC: {acac}",
                }
            )
        elif acao == "*":
            findings.append(
                {
                    "type": "CORS: Wildcard Origin",
                    "severity": "MEDIUM",
                    "score": 10,
                    "description": "CORS дозволяє будь-який Origin (*) — ризик витоку даних",
                    "fix": "Вказати whitelist доменів: Access-Control-Allow-Origin: https://yourdomain.com",
                    "owasp_category": "A01:2021",
                    "evidence": f"ACAO: {acao}",
                }
            )
        elif acao == "https://evil.com":
            findings.append(
                {
                    "type": "CORS: Reflected Origin (misconfigured)",
                    "severity": "HIGH",
                    "score": 25,
                    "description": "Сервер віддзеркалює будь-який Origin — CORS misconfiguration",
                    "fix": "Валідувати Origin на сервері, дозволити тільки довірені",
                    "owasp_category": "A01:2021",
                    "evidence": "Reflected evil.com",
                }
            )
        elif not acao and "Access-Control" in str(r.headers):
            findings.append(
                {
                    "type": "CORS headers present",
                    "severity": "LOW",
                    "score": 0,
                    "description": "CORS налаштовано",
                    "fix": "",
                    "owasp_category": "A01:2021",
                    "evidence": acao,
                }
            )
    except Exception as e:
        error = str(e)[:300]
    return {
        "scanner": "cors",
        "findings": findings,
        "duration_ms": int((time.time() - start) * 1000),
        "error": error,
    }
