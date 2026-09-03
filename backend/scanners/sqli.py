"""
SQLi Scanner — пошук SQL Injection через аналіз помилок БД
OWASP A03:2021 - Injection
"""
import time
import re
import requests
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, quote
from bs4 import BeautifulSoup

# SQL помилки — індикатори вразливості
SQL_ERRORS = [
    (r"SQL syntax.*MySQL", "MySQL"),
    (r"Warning.*mysql_.*", "MySQL"),
    (r"valid MySQL result", "MySQL"),
    (r"MySqlClient\.", "MySQL"),
    (r"PostgreSQL.*ERROR", "PostgreSQL"),
    (r"Warning.*\Wpg_.*", "PostgreSQL"),
    (r"valid PostgreSQL result", "PostgreSQL"),
    (r"Npgsql\.", "PostgreSQL"),
    (r"Driver.* SQL[\-\_\ ]*Server", "MSSQL"),
    (r"OLE DB.* SQL Server", "MSSQL"),
    (r"SQLServer JDBC Driver", "MSSQL"),
    (r"SqlException", "MSSQL"),
    (r"ORA-[0-9]{5}", "Oracle"),
    (r"Oracle error", "Oracle"),
    (r"Oracle.*Driver", "Oracle"),
    (r"SQLite/JDBCDriver", "SQLite"),
    (r"SQLite\.Exception", "SQLite"),
    (r"System\.Data\.SQLite", "SQLite"),
    (r"Warning.*sqlite_.*", "SQLite"),
    (r"Warning.*SQLite3::", "SQLite"),
    (r"Unclosed quotation mark after the character string", "MSSQL"),
    (r"quoted string not properly terminated", "Oracle"),
    (r"SQLSTATE\[", "Generic SQL"),
]

SQLI_PAYLOADS = [
    "'",
    "\"",
    "' OR '1'='1",
    "' OR 1=1--",
    "\" OR \"1\"=\"1",
    "' UNION SELECT 1,2,3--",
    "1' AND 1=1--",
]

# Time-based / blind payloads
TIME_PAYLOADS = [
    "' AND SLEEP(3)--",
    "' OR SLEEP(3)--",
    "'; WAITFOR DELAY '0:0:3'--",
]


def check_sqli_error(text: str) -> tuple[bool, str]:
    """Перевіряє чи містить відповідь SQL помилку"""
    for pattern, db_type in SQL_ERRORS:
        if re.search(pattern, text, re.IGNORECASE):
            return True, db_type
    return False, ""


def scan_sqli(url: str, timeout: int = 8) -> dict:
    start = time.time()
    findings = []
    error = None

    if not url.startswith("http"):
        url = "https://" + url

    session = requests.Session()
    session.headers.update({"User-Agent": "CyberGuard/1.0 SQLi Scanner"})

    try:
        resp = session.get(url, timeout=timeout, verify=True)
        try:
            soup = BeautifulSoup(resp.text, "lxml")
        except Exception:
            soup = BeautifulSoup(resp.text, "html.parser")
        forms = soup.find_all("form")
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)

        # Крок 1: Тестуємо URL параметри на SQLi
        if query_params:
            for param, values in list(query_params.items())[:2]:
                original_val = values[0]
                for payload in SQLI_PAYLOADS[:3]:  # Тестуємо 3 payloads для швидкості
                    test_val = original_val + payload
                    # Замінюємо параметр
                    test_params = {k: v[0] for k, v in query_params.items()}
                    test_params[param] = test_val
                    qs = urlencode(test_params)
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{qs}"

                    try:
                        r = session.get(test_url, timeout=5, verify=True)
                        has_error, db_type = check_sqli_error(r.text)
                        if has_error:
                            findings.append({
                                "type": f"Potential SQL Injection in parameter '{param}' ({db_type})",
                                "severity": "HIGH",
                                "score": 25,
                                "description": f"Параметр '{param}' можливо вразливий до SQL Injection - виявлено помилку БД {db_type} при payload '{payload}'",
                                "fix": "Використати parameterized queries / prepared statements, ORM, екранувати вхідні дані. Ніколи не конкатенувати SQL з user input!",
                                "owasp_category": "A03:2021 - Injection (SQLi)",
                                "evidence": f"Payload: '{payload}' triggered {db_type} error in param '{param}'",
                            })
                            break
                        # Перевірка на різницю у відповіді (boolean-based)
                        # Якщо оригінал і payload дають різний контент — потенційно вразливо
                    except Exception:
                        continue
                if findings and findings[-1]["severity"] == "HIGH":
                    break

        # Крок 2: Тестуємо форми
        if forms:
            for form in forms[:2]:
                action = form.get("action", "")
                method = form.get("method", "get").lower()
                form_url = urljoin(url, action) if action else url

                inputs = form.find_all(["input", "textarea"])
                text_inputs = [inp for inp in inputs if inp.get("type", "text") not in ("submit", "button", "checkbox", "radio", "file")]
                # Якщо немає текстових — пробуємо всі з name
                if not text_inputs:
                    text_inputs = [inp for inp in inputs if inp.get("name")]

                if not text_inputs:
                    continue

                # Базові дані форми
                base_data = {}
                for inp in form.find_all(["input", "textarea", "select"]):
                    name = inp.get("name")
                    if not name:
                        continue
                    if inp.get("type") == "hidden":
                        base_data[name] = inp.get("value", "")
                    elif inp.name == "select":
                        opt = inp.find("option")
                        base_data[name] = opt.get("value", "") if opt else ""
                    elif inp.get("type") not in ("submit", "button"):
                        base_data[name] = inp.get("value", "test")

                # Тестуємо кожен input окремо
                vulnerable = False
                for inp in text_inputs[:2]:
                    name = inp.get("name")
                    if not name:
                        continue

                    for payload in ["'", "' OR '1'='1"]:
                        test_data = base_data.copy()
                        test_data[name] = payload

                        try:
                            if method == "post":
                                r = session.post(form_url, data=test_data, timeout=5, verify=True)
                            else:
                                qs = urlencode(test_data)
                                sep = "&" if "?" in form_url else "?"
                                r = session.get(form_url + sep + qs, timeout=5, verify=True)

                            has_error, db_type = check_sqli_error(r.text)
                            if has_error:
                                findings.append({
                                    "type": f"Potential SQL Injection in form field '{name}' ({db_type})",
                                    "severity": "HIGH",
                                    "score": 25,
                                    "description": f"Поле форми '{name}' можливо вразливе до SQL Injection ({db_type})",
                                    "fix": "Використати prepared statements: cursor.execute('SELECT * FROM users WHERE id=%s', (user_id,))",
                                    "owasp_category": "A03:2021 - Injection (SQLi)",
                                    "evidence": f"Form {form_url}, field '{name}' with payload '{payload}' triggered {db_type} error",
                                })
                                vulnerable = True
                                break
                        except Exception:
                            continue
                    if vulnerable:
                        break
                if vulnerable:
                    break

        # Крок 3: Time-based blind SQLi (затримка)
        if not findings:
            for payload in TIME_PAYLOADS[:1]:
                try:
                    base_params = {k: v[0] for k, v in query_params.items()} if query_params else {"id": "1"}
                    test_params = base_params.copy()
                    # додаємо payload до першого параметра
                    first_key = next(iter(test_params), "id")
                    test_params[first_key] = str(test_params[first_key]) + payload
                    qs = urlencode(test_params)
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{qs}" if query_params else f"{url.rstrip('/')}?{qs}"
                    import time as _t
                    t0 = _t.time()
                    r = session.get(test_url, timeout=7, verify=True)
                    dt = _t.time() - t0
                    if dt > 2.5 and r.status_code < 500:
                        findings.append({
                            "type": f"Potential Blind SQLi (time-based) in '{first_key}'",
                            "severity": "HIGH",
                            "score": 25,
                            "description": f"Параметр затримав відповідь на {dt:.1f}s з payload {payload} — можливий blind SQLi",
                            "fix": "Parameterized queries, WAF, обмежити час виконання запитів",
                            "owasp_category": "A03:2021 - Injection (SQLi)",
                            "evidence": f"Delay {dt:.1f}s for payload {payload}",
                        })
                        break
                except Exception:
                    continue

        # Крок 4: Перевірка на information disclosure через SQL коментарі / stack trace
        error_indicators = ["stack trace", "exception", "error in your SQL syntax", "mysql_fetch", "pg_query"]
        text_lower = resp.text.lower()
        for indicator in error_indicators:
            if indicator in text_lower:
                # Перевіряємо чи це не false positive (дефолтна сторінка)
                if not findings:  # Тільки якщо ще немає HIGH findings
                    findings.append({
                        "type": "Information Disclosure: SQL error in page",
                        "severity": "MEDIUM",
                        "score": 10,
                        "description": f"Сторінка містить технічну інформацію про БД ('{indicator}') - може допомогти зловмиснику",
                        "fix": "Вимкнути debug mode, налаштувати custom error pages, не показувати stack trace користувачу",
                        "owasp_category": "A01:2021 - Broken Access Control",
                        "evidence": f"Found '{indicator}' in page content",
                    })
                break

        # Якщо немає ні параметрів ні форм — низький ризик SQLi
        if not query_params and not forms:
            # Не додаємо finding, просто немає поверхні атаки
            pass

        # Якщо є параметри але не вразливі — додаємо інфо що перевірено
        if findings == [] and (query_params or forms):
            # Не додаємо LOW finding якщо все чисто — це нормально
            pass

    except requests.exceptions.RequestException as e:
        error = str(e)[:300]
        findings.append({
            "type": "SQLi Scan Failed",
            "severity": "LOW",
            "score": 0,
            "description": f"Не вдалося виконати SQLi сканування: {error[:100]}",
            "fix": "Перевірити доступність сайту",
            "owasp_category": "N/A",
            "evidence": error[:200],
        })
    except Exception as e:
        error = str(e)[:300]
        findings.append({
            "type": "SQLi Scan Error",
            "severity": "LOW",
            "score": 0,
            "description": f"Помилка SQLi сканера: {error[:100]}",
            "fix": "Перевірити логи",
            "owasp_category": "N/A",
            "evidence": error[:200],
        })

    duration = int((time.time() - start) * 1000)
    return {
        "scanner": "sqli",
        "findings": findings,
        "duration_ms": duration,
        "error": error,
    }
