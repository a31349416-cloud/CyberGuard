"""
Ports Scanner — перевірка відкритих портів через socket
"""

import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

# Порти для сканування: (порт, сервіс, severity, score)
COMMON_PORTS = [
    (
        21,
        "FTP",
        "MEDIUM",
        15,
        "FTP відкритий - ризик brute-force та перехоплення трафіку",
        "Закрити порт 21 або обмежити фаєрволом, використати SFTP (22)",
    ),
    (
        22,
        "SSH",
        "MEDIUM",
        15,
        "SSH відкритий - перевірити brute-force захист",
        "Обмежити доступ по IP, використати ключі замість паролів, fail2ban",
    ),
    (
        23,
        "Telnet",
        "HIGH",
        25,
        "Telnet відкритий - незашифрований протокол!",
        "Негайно закрити Telnet, використати SSH",
    ),
    (25, "SMTP", "LOW", 5, "SMTP відкритий", "Перевірити чи потрібен, обмежити relay"),
    (53, "DNS", "LOW", 5, "DNS порт відкритий", "Перевірити чи не open resolver"),
    (
        80,
        "HTTP",
        "LOW",
        5,
        "HTTP порт відкритий (перевірити редирект на HTTPS)",
        "Налаштувати редирект HTTP->HTTPS",
    ),
    (
        443,
        "HTTPS",
        "LOW",
        0,
        "HTTPS порт відкритий",
        "",
    ),  # 443 відкритий - нормально, не finding якщо є
    (
        3306,
        "MySQL",
        "HIGH",
        25,
        "MySQL порт відкритий в інтернет - критично!",
        "Закрити порт 3306 фаєрволом, дозволити тільки з localhost/VPN",
    ),
    (
        5432,
        "PostgreSQL",
        "HIGH",
        25,
        "PostgreSQL порт відкритий в інтернет",
        "Закрити порт 5432, дозволити тільки локально",
    ),
    (
        6379,
        "Redis",
        "HIGH",
        25,
        "Redis відкритий - часто без аутентифікації!",
        "Закрити порт 6379, увімкнути AUTH, bind 127.0.0.1",
    ),
    (
        27017,
        "MongoDB",
        "HIGH",
        25,
        "MongoDB порт відкритий - ризик витоку даних",
        "Закрити порт 27017, увімкнути аутентифікацію",
    ),
    (
        8080,
        "HTTP-Alt",
        "LOW",
        5,
        "Альтернативний HTTP порт 8080 відкритий",
        "Перевірити що на порту, обмежити доступ",
    ),
]


def check_port(host: str, port: int, timeout: float = 1.5) -> bool:
    """Перевіряє чи відкритий порт (TCP connect)"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((host, port))
            return result == 0
    except Exception:
        return False


def scan_ports(url: str, timeout: float = 1.5) -> dict:
    start = time.time()
    findings = []
    error = None

    parsed = urlparse(url if url.startswith("http") else "https://" + url)
    host = parsed.hostname or parsed.path.split("/")[0]
    if host and ":" in host:
        host = host.split(":")[0]

    # Перевіряємо DNS спочатку
    try:
        socket.gethostbyname(host)
    except socket.gaierror as e:
        return {
            "scanner": "ports",
            "findings": [
                {
                    "type": "DNS Resolution Failed",
                    "severity": "LOW",
                    "score": 0,
                    "description": f"Не вдалося резолвити {host}: {e}",
                    "fix": "Перевірити URL",
                    "owasp_category": "N/A",
                    "evidence": str(e),
                }
            ],
            "duration_ms": int((time.time() - start) * 1000),
            "error": str(e),
        }

    open_ports = []
    # Паралельна перевірка портів через ThreadPool
    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_port = {
            executor.submit(check_port, host, port, timeout): (
                port,
                service,
                sev,
                score,
                desc,
                fix,
            )
            for port, service, sev, score, desc, fix in COMMON_PORTS
        }
        for future in as_completed(future_to_port):
            port, service, sev, score, desc, fix = future_to_port[future]
            try:
                is_open = future.result()
                if is_open:
                    open_ports.append(port)
                    # Порт 443 відкритий - це нормально, не додаємо finding
                    if port == 443:
                        continue
                    # HTTP 80 - додаємо тільки як LOW інфо
                    findings.append(
                        {
                            "type": f"Open Port {port}/{service}",
                            "severity": sev,
                            "score": score,
                            "description": desc,
                            "fix": fix,
                            "owasp_category": "A01:2021 - Broken Access Control"
                            if sev == "HIGH"
                            else "A05:2021",
                            "evidence": f"{host}:{port} is open ({service})",
                        }
                    )
            except Exception:
                continue

    # Додатковий аналіз: якщо багато портів відкрито
    if len(open_ports) > 4:
        findings.append(
            {
                "type": f"Multiple open ports ({len(open_ports)})",
                "severity": "MEDIUM",
                "score": 10,
                "description": f"Виявлено {len(open_ports)} відкритих портів: {open_ports} - велика поверхня атаки",
                "fix": "Закрити непотрібні порти, принцип мінімальних привілеїв",
                "owasp_category": "A05:2021",
                "evidence": f"Open: {open_ports}",
            }
        )

    duration = int((time.time() - start) * 1000)
    return {
        "scanner": "ports",
        "findings": findings,
        "duration_ms": duration,
        "error": error,
        "open_ports": open_ports,  # для дебагу, не входить в Finding модель
    }
