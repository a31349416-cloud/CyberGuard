"""
XSS Scanner — пошук Reflected XSS через аналіз форм та payload injection
OWASP A03:2021 - Injection
"""
import time
import re
import requests
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, quote
from bs4 import BeautifulSoup

XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "\"><svg onload=alert(1)>",
    "'\"><img src=x onerror=alert(1)>",
    "javascript:alert(1)",
    "<iframe src=javascript:alert(1)>",
    "'-alert(1)-'",
    "{{7*7}}",  # SSTI/XSS hint
]

# Blind/encoded variants
XSS_ENCODED_PAYLOADS = [
    "%3Cscript%3Ealert(1)%3C%2Fscript%3E",
    "&lt;script&gt;alert(1)&lt;/script&gt;",
]

# Для перевірки відображення — спрощені маркери
XSS_MARKERS = [
    "<script>alert",
    "onload=alert",
    "onerror=alert",
    "<svg",
    "<img src=x",
]


def scan_xss(url: str, timeout: int = 8) -> dict:
    start = time.time()
    findings = []
    error = None

    # Нормалізуємо URL
    if not url.startswith("http"):
        url = "https://" + url

    session = requests.Session()
    session.headers.update({"User-Agent": "CyberGuard/1.0 XSS Scanner"})

    try:
        # Крок 1: Отримуємо сторінку та шукаємо форми
        resp = session.get(url, timeout=timeout, verify=True)
        try:
            soup = BeautifulSoup(resp.text, "lxml")
        except Exception:
            soup = BeautifulSoup(resp.text, "html.parser")
        forms = soup.find_all("form")

        # Крок 2: Перевірка headers для XSS захисту
        headers_lower = {k.lower(): v for k, v in resp.headers.items()}

        # X-XSS-Protection
        if "x-xss-protection" not in headers_lower:
            findings.append({
                "type": "Missing X-XSS-Protection header",
                "severity": "LOW",
                "score": 5,
                "description": "Відсутній X-XSS-Protection header (додатковий захист в старих браузерах)",
                "fix": "Додати header: X-XSS-Protection: 1; mode=block (або покладатись на CSP)",
                "owasp_category": "A03:2021 - Injection",
                "evidence": "Header not found",
            })

        # Перевірка чи є CSP з захистом від XSS
        csp = headers_lower.get("content-security-policy", "")
        if not csp:
            # Вже покрито в headers scanner, але XSS контекст
            pass
        elif "unsafe-inline" in csp:
            findings.append({
                "type": "Weak CSP allows unsafe-inline",
                "severity": "MEDIUM",
                "score": 10,
                "description": "CSP містить 'unsafe-inline' - послаблює захист від XSS",
                "fix": "Видалити 'unsafe-inline', використати nonce або hash для inline скриптів",
                "owasp_category": "A03:2021 - Injection",
                "evidence": f"CSP: {csp[:150]}",
            })

        # Крок 3: Шукаємо відображення user input без екранування (reflected)
        # Перевірка query параметрів у URL — чи відображаються на сторінці без екранування
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)

        # Якщо є параметри — тестуємо
        if query_params:
            for param, values in list(query_params.items())[:3]:  # max 3 параметри
                test_payload = XSS_PAYLOADS[0]
                test_url = url.replace(f"{param}={values[0]}", f"{param}={quote(test_payload)}")
                try:
                    r = session.get(test_url, timeout=5, verify=True)
                    # Перевіряємо чи payload відобразився без екранування
                    if test_payload in r.text and "html.escape" not in r.text.lower():
                        # Перевіряємо чи не екрановано (< -> &lt;)
                        if "&lt;script&gt;" not in r.text or test_payload in r.text:
                            # Двошарова перевірка: payload є в raw HTML
                            findings.append({
                                "type": f"Potential Reflected XSS in parameter '{param}'",
                                "severity": "HIGH",
                                "score": 25,
                                "description": f"Параметр '{param}' відображається без екранування - можливий Reflected XSS",
                                "fix": "Екранувати вивід: html.escape(user_input), використати templating з auto-escape",
                                "owasp_category": "A03:2021 - Injection (XSS)",
                                "evidence": f"Payload '{test_payload}' reflected in response for param '{param}'",
                            })
                            break
                except Exception:
                    continue

        # Крок 4: Тестуємо форми на XSS
        if forms:
            # Повідомлення про наявність форм — це не вразливість, а інфо
            # Тестуємо перші 2 форми
            for form in forms[:2]:
                action = form.get("action", "")
                method = form.get("method", "get").lower()
                form_url = urljoin(url, action) if action else url

                inputs = form.find_all(["input", "textarea", "select"])
                text_inputs = [inp for inp in inputs if inp.get("type", "text") not in ("submit", "button", "hidden", "checkbox", "radio", "file")]
                if not text_inputs:
                    continue

                # Готуємо payload
                data = {}
                for inp in text_inputs:
                    name = inp.get("name")
                    if not name:
                        continue
                    data[name] = XSS_PAYLOADS[1]  # payload з svg

                # Додаємо hidden поля
                for inp in form.find_all("input", {"type": "hidden"}):
                    name = inp.get("name")
                    if name:
                        data[name] = inp.get("value", "")

                try:
                    if method == "post":
                        r = session.post(form_url, data=data, timeout=5, verify=True)
                    else:
                        # GET — додаємо до query string
                        qs = urlencode(data)
                        sep = "&" if "?" in form_url else "?"
                        r = session.get(form_url + sep + qs, timeout=5, verify=True)

                    # Перевіряємо чи payload відобразився
                    for marker in XSS_MARKERS:
                        if marker.lower() in r.text.lower():
                            # Перевіряємо чи це не екранована версія
                            if "&lt;" not in r.text[r.text.lower().find(marker.lower())-20:r.text.lower().find(marker.lower())+50]:
                                findings.append({
                                    "type": "Potential Stored/Reflected XSS in form",
                                    "severity": "HIGH",
                                    "score": 25,
                                    "description": f"Форма {form_url} можливо вразлива до XSS - payload відобразився без екранування",
                                    "fix": "Екранувати всі user inputs перед виводом, використати CSP, валідувати вхідні дані",
                                    "owasp_category": "A03:2021 - Injection (XSS)",
                                    "evidence": f"Form action: {form_url}, payload marker '{marker}' found in response",
                                })
                                break
                    break  # Тестуємо тільки одну форму для швидкості
                except Exception:
                    continue

            # Якщо форм багато — додаємо інфо
            if len(forms) > 5:
                findings.append({
                    "type": f"Many forms detected ({len(forms)})",
                    "severity": "LOW",
                    "score": 0,
                    "description": f"Сторінка містить {len(forms)} форм - збільшена поверхня для XSS атак",
                    "fix": "Перевірити всі форми на валідацію та екранування вводу",
                    "owasp_category": "A03:2021",
                    "evidence": f"{len(forms)} forms found",
                })
        else:
            # Немає форм — перевіряємо чи є query params для reflected XSS
            if not query_params:
                # Немає форм і параметрів — XSS ризик низький, не додаємо finding
                pass

        # Крок 5: Перевірка на DOM-XSS індикатори (inline event handlers)
        inline_handlers = soup.find_all(attrs={"onload": True}) + soup.find_all(attrs={"onerror": True}) + soup.find_all(attrs={"onclick": True})
        if len(inline_handlers) > 3:
            findings.append({
                "type": "Inline event handlers detected",
                "severity": "LOW",
                "score": 5,
                "description": f"Знайдено {len(inline_handlers)} inline event handlers (onclick, onload) - ускладнює CSP та може вказувати на XSS-unsafe код",
                "fix": "Винести JS в окремі файли, використати addEventListener, налаштувати CSP без unsafe-inline",
                "owasp_category": "A03:2021",
                "evidence": f"{len(inline_handlers)} inline handlers found",
            })

    except requests.exceptions.RequestException as e:
        error = str(e)[:300]
        findings.append({
            "type": "XSS Scan Failed",
            "severity": "LOW",
            "score": 0,
            "description": f"Не вдалося виконати XSS сканування: {error[:100]}",
            "fix": "Перевірити доступність сайту",
            "owasp_category": "N/A",
            "evidence": error[:200],
        })
    except Exception as e:
        error = str(e)[:300]
        findings.append({
            "type": "XSS Scan Error",
            "severity": "LOW",
            "score": 0,
            "description": f"Помилка XSS сканера: {error[:100]}",
            "fix": "Перевірити логи",
            "owasp_category": "N/A",
            "evidence": error[:200],
        })

    duration = int((time.time() - start) * 1000)
    return {
        "scanner": "xss",
        "findings": findings,
        "duration_ms": duration,
        "error": error,
    }
