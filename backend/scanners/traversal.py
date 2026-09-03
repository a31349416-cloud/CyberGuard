"""Directory Traversal Scanner — легка перевірка"""
import time, requests
from urllib.parse import quote
def scan_traversal(url: str, timeout: int = 8) -> dict:
    start=time.time(); findings=[]; error=None
    if not url.startswith("http"): url="https://"+url
    try:
        payloads=["../../../../etc/passwd","..%2F..%2Fetc%2Fpasswd","..\\..\\windows\\win.ini"]
        base=url.rstrip("/")+"/"
        for p in payloads[:2]:
            test=base+quote(p, safe="")
            try:
                r=requests.get(test, timeout=5, verify=True)
                txt=r.text.lower()
                if "root:" in txt and "bin:" in txt:
                    findings.append({"type":"Directory Traversal (etc/passwd disclosed)","severity":"HIGH","score":25,"description":"Сайт віддає /etc/passwd — критична Directory Traversal","fix":"Валідувати шлях, заборонити ../, використовувати whitelist + chroot","owasp_category":"A01:2021 - Broken Access Control","evidence":"root: found in response"})
                    break
                if "[extensions]" in txt or "for 16-bit app" in txt:
                    findings.append({"type":"Directory Traversal (win.ini disclosed)","severity":"HIGH","score":25,"description":"Витік win.ini — Directory Traversal","fix":"Те саме","owasp_category":"A01:2021","evidence":"win.ini found"})
                    break
            except: continue
    except Exception as e:
        error=str(e)[:300]
    return {"scanner":"traversal","findings":findings,"duration_ms":int((time.time()-start)*1000),"error":error}
