"""
SSL/TLS Scanner — перевірка сертифіката, TLS версії, http->https редиректу
"""
import ssl
import socket
import time
from urllib.parse import urlparse
from datetime import datetime, timezone
import requests


def scan_ssl(url: str, timeout: int = 8) -> dict:
    start = time.time()
    findings = []
    error = None

    parsed = urlparse(url if url.startswith("http") else "https://" + url)
    host = parsed.hostname or parsed.path.split("/")[0]
    # Прибираємо порт якщо є
    if host and ":" in host:
        host = host.split(":")[0]
    port = 443

    # Якщо URL не https — перевірка редиректу
    if parsed.scheme == "http":
        findings.append({
            "type": "Site served over HTTP",
            "severity": "HIGH",
            "score": 25,
            "description": "Сайт доступний по HTTP без шифрування - трафік може перехоплюватись",
            "fix": "Налаштувати редирект HTTP -> HTTPS та HSTS",
            "owasp_category": "A05:2021 - Security Misconfiguration",
            "evidence": url,
        })
        # Спробувати https версію для подальших перевірок
        url = url.replace("http://", "https://", 1)
        parsed = urlparse(url)
        host = parsed.hostname or host

    try:
        # HTTP -> HTTPS редирект перевірка
        try:
            http_url = f"http://{host}"
            resp = requests.get(http_url, timeout=5, allow_redirects=False)
            if resp.status_code not in (301, 302, 307, 308):
                # Перевіряємо чи взагалі є редирект
                if "https" not in resp.headers.get("Location", ""):
                    findings.append({
                        "type": "Missing HTTP to HTTPS redirect",
                        "severity": "MEDIUM",
                        "score": 15,
                        "description": "HTTP не редиректить на HTTPS - користувачі можуть потрапити на незахищену версію",
                        "fix": "Налаштувати 301 redirect з http:// на https:// на рівні веб-сервера",
                        "owasp_category": "A05:2021",
                        "evidence": f"GET http://{host} -> {resp.status_code} Location: {resp.headers.get('Location','-')}",
                    })
        except Exception:
            pass  # Не критично якщо не вдалося перевірити редирект

        # Отримуємо сертифікат
        ctx = ssl.create_default_context()
        # Не перевіряємо самоподписані — хочемо побачити їх як finding
        # Але для отримання інфо спробуємо спочатку з перевіркою
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                tls_version = ssock.version()
                cipher = ssock.cipher()

                # Перевірка TLS версії
                if tls_version in ("TLSv1", "TLSv1.1", "SSLv2", "SSLv3"):
                    findings.append({
                        "type": f"Weak TLS version: {tls_version}",
                        "severity": "HIGH",
                        "score": 25,
                        "description": f"Використовується застаріла версія TLS {tls_version} з відомими вразливостями",
                        "fix": "Вимкнути TLS 1.0/1.1, залишити тільки TLS 1.2 та 1.3",
                        "owasp_category": "A05:2021",
                        "evidence": f"TLS: {tls_version}, Cipher: {cipher}",
                    })
                elif tls_version == "TLSv1.2":
                    pass  # OK
                elif tls_version == "TLSv1.3":
                    pass  # Best

                # Перевірка дати сертифіката
                not_after_str = cert.get("notAfter")
                not_before_str = cert.get("notBefore")
                if not_after_str:
                    # Формат: 'May  9 12:00:00 2025 GMT'
                    expire_date = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    now = datetime.now(timezone.utc)
                    days_left = (expire_date - now).days

                    if days_left < 0:
                        findings.append({
                            "type": "Expired SSL Certificate",
                            "severity": "HIGH",
                            "score": 25,
                            "description": f"SSL сертифікат прострочено {abs(days_left)} днів тому ({expire_date.date()})",
                            "fix": "Терміново оновити SSL сертифікат (Let's Encrypt, або CA)",
                            "owasp_category": "A05:2021",
                            "evidence": f"notAfter: {not_after_str}",
                        })
                    elif days_left < 7:
                        findings.append({
                            "type": "SSL Certificate expiring soon",
                            "severity": "MEDIUM",
                            "score": 15,
                            "description": f"SSL сертифікат закінчується через {days_left} днів",
                            "fix": "Оновити сертифікат та налаштувати автооновлення",
                            "owasp_category": "A05:2021",
                            "evidence": f"notAfter: {not_after_str} ({days_left} days left)",
                        })
                    elif days_left < 30:
                        findings.append({
                            "type": "SSL Certificate expiring within 30 days",
                            "severity": "LOW",
                            "score": 5,
                            "description": f"Сертифікат закінчується через {days_left} днів",
                            "fix": "Запланувати оновлення сертифіката",
                            "owasp_category": "A05:2021",
                            "evidence": f"notAfter: {not_after_str}",
                        })

                # Перевірка subject / issuer
                issuer = cert.get("issuer", ())
                issuer_str = " ".join([f"{k}={v}" for tup in issuer for k, v in tup]) if issuer else "unknown"
                subject = cert.get("subject", ())
                # Перевірка самоподписаного (issuer == subject)
                if issuer == subject and issuer:
                    findings.append({
                        "type": "Self-signed SSL Certificate",
                        "severity": "MEDIUM",
                        "score": 15,
                        "description": "Використовується самоподписаний сертифікат - браузери покажуть попередження",
                        "fix": "Встановити сертифікат від довіреного CA (Let's Encrypt безкоштовно)",
                        "owasp_category": "A05:2021",
                        "evidence": f"Issuer: {issuer_str}",
                    })

                # Перевірка hostname mismatch — якщо cert не покриває host
                # (ssl already validates, but we check SAN)
                san = cert.get("subjectAltName", [])
                sans = [v for k, v in san if k in ("DNS", "IP Address")]
                if sans and host not in sans and not any(s.startswith("*.") and host.endswith(s[2:]) for s in sans):
                    # Перевірка wildcard не точна, але для сигналу
                    if not any(host == s or (s.startswith("*.") and host.count(".") >= s.count(".")) for s in sans):
                        pass  # Не додаємо false positive, ssl вже перевірив

    except socket.timeout:
        error = f"Timeout connecting to {host}:{port}"
        findings.append({
            "type": "SSL Check Timeout",
            "severity": "LOW",
            "score": 0,
            "description": f"Не вдалося підключитись до {host}:{port} для перевірки SSL (timeout)",
            "fix": "Перевірити доступність порту 443 та фаєрвол",
            "owasp_category": "N/A",
            "evidence": error,
        })
    except ssl.SSLCertVerificationError as e:
        findings.append({
            "type": "Invalid SSL Certificate",
            "severity": "HIGH",
            "score": 25,
            "description": f"SSL сертифікат недійсний: {str(e)[:150]}",
            "fix": "Встановити валідний сертифікат від довіреного CA",
            "owasp_category": "A05:2021",
            "evidence": str(e)[:200],
        })
    except socket.gaierror as e:
        error = f"DNS error for {host}: {e}"
        findings.append({
            "type": "DNS Resolution Failed",
            "severity": "LOW",
            "score": 0,
            "description": f"Не вдалося резолвити хост {host}",
            "fix": "Перевірити правильність URL та DNS",
            "owasp_category": "N/A",
            "evidence": error,
        })
    except ConnectionRefusedError:
        error = f"Connection refused {host}:{port}"
        findings.append({
            "type": "Port 443 Closed / Refused",
            "severity": "MEDIUM",
            "score": 10,
            "description": "Порт 443 закритий - HTTPS недоступний",
            "fix": "Відкрити порт 443 та налаштувати TLS",
            "owasp_category": "A05:2021",
            "evidence": error,
        })
    except Exception as e:
        error = str(e)[:300]
        # Якщо це сертифікат проблема - додаємо finding
        if "certificate" in error.lower() or "ssl" in error.lower():
            findings.append({
                "type": "SSL Configuration Issue",
                "severity": "HIGH",
                "score": 20,
                "description": f"Проблема з SSL конфігурацією: {error[:150]}",
                "fix": "Перевірити SSL сертифікат та налаштування сервера",
                "owasp_category": "A05:2021",
                "evidence": error[:200],
            })
        else:
            findings.append({
                "type": "SSL Scan Error",
                "severity": "LOW",
                "score": 0,
                "description": f"Помилка SSL сканування: {error[:150]}",
                "fix": "Перевірити доступність хоста",
                "owasp_category": "N/A",
                "evidence": error[:200],
            })

    duration = int((time.time() - start) * 1000)
    return {
        "scanner": "ssl",
        "findings": findings,
        "duration_ms": duration,
        "error": error,
    }
