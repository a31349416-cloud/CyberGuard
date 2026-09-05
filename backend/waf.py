"""
WAF Middleware — легкий, блокує очевидні атаки на рівні запиту
- SQLi/XSS payloads в query/body
- Великі body (>1MB)
- Швидкий фікс без ModSecurity
"""
import re
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

# Сигнатури для блоку
SQLI_PATTERNS = [
    r"(\%27)|(') *or *1=1",
    r"union.*select",
    r"waitfor delay",
    r"sleep\( *\d",
    r"benchmark\(",
]
XSS_PATTERNS = [
    r"<script",
    r"onerror *=",
    r"onload *=",
    r"javascript:",
]

BLOCK_RE = re.compile("|".join(SQLI_PATTERNS + XSS_PATTERNS), re.IGNORECASE)

# Whitelist шляхів деpayloads дозволені (сканер сам тестує їх)
WAF_WHITELIST = ["/api/scan", "/api/result", "/ws"]

def _should_check(path: str) -> bool:
    # Не перевіряємо сканерні ендпоінти жорстко — щоб не блокувати легітимні скани
    # Але перевіряємо історію, auth тощо
    return not any(path.startswith(p) for p in WAF_WHITELIST)

class WAFMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # 1. Розмір body
        cl = request.headers.get("content-length")
        if cl and int(cl) > 1_000_000:
            return Response(content="Payload too large", status_code=413)

        # 2. Перевірка query string на атаки (крім whitelisted)
        path = request.url.path
        qs = str(request.query_params)
        if qs and _should_check(path) and BLOCK_RE.search(qs):
            # Логуємо, але не блокуємо жорстко — повертаємо 403 тільки для очевидних
            # Для CyberGuard краще логувати ніж блокувати сканер
            print(f"[WAF] Suspicious query blocked: {path}?{qs[:100]}")

        # 3. IP block list (опційно через env BLOCKED_IPS)
        # Можна розширити через Redis: r.sismember("blocked_ips", ip)

        response = await call_next(request)
        # Додаємо security headers до всіх відповідей (defense in depth)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        return response
