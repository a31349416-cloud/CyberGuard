"""Open Redirect Scanner"""
import time, requests
from urllib.parse import urlparse, parse_qs, urlencode, quote
def scan_redirect(url: str, timeout: int = 8) -> dict:
    start=time.time(); findings=[]; error=None
    if not url.startswith("http"): url="https://"+url
    try:
        # Шукаємо параметри типу ?next=, ?url=, ?redirect=
        parsed=urlparse(url)
        qs=parse_qs(parsed.query)
        redirect_params=["next","url","redirect","return","goto","target","dest","destination","rurl"]
        has_param=any(p in qs for p in redirect_params)
        # Якщо в URL немає — тестуємо додаванням payload
        test_payload="https://evil.com"
        # Тестуємо чи сайт редиректить на evil.com
        for param in redirect_params[:3]:
            if len(findings)>=1: break
            test_url=url + ("&" if "?" in url else "?") + f"{param}={quote(test_payload)}"
            try:
                r=requests.get(test_url, timeout=5, verify=True, allow_redirects=False)
                loc=r.headers.get("Location","")
                if "evil.com" in loc:
                    findings.append({"type":f"Open Redirect in param '{param}'","severity":"MEDIUM","score":15,"description":f"Параметр {param} дозволяє редирект на зовнішній домен — фішинг ризик","fix":"Валідувати redirect URL на whitelist, використовувати відносні шляхи","owasp_category":"A01:2021 - Broken Access Control","evidence":f"Location: {loc}"})
                    break
            except: continue
        # Перевірка заголовка Referrer-Policy вже в headers, тут перевірка X-Redirect
        if not findings and not has_param:
            pass
    except Exception as e:
        error=str(e)[:300]
    return {"scanner":"redirect","findings":findings,"duration_ms":int((time.time()-start)*1000),"error":error}
