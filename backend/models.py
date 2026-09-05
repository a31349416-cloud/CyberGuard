"""
Pydantic моделі для CyberGuard
"""

import re
from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field, field_validator


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class ScanRequest(BaseModel):
    url: str = Field(
        ..., description="URL для сканування", examples=["https://testphp.vulnweb.com"]
    )

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        v = v.strip()

        # Блокуємо небезпечні схеми
        lowered = v.lower()
        if lowered.startswith(("file://", "ftp://", "gopher://", "dict://", "ldap://")):
            raise ValueError(f"Недозволена схема URL: {v}")

        # Додаємо https якщо немає схеми
        if not v.startswith(("http://", "https://")):
            v = "https://" + v

        # Блок приватних мереж / localhost / metadata
        blocked_patterns = [
            r"localhost",
            r"127\.0\.0\.1",
            r"0\.0\.0\.0",
            r"10\.\d+\.\d+\.\d+",
            r"192\.168\.\d+\.\d+",
            r"172\.(1[6-9]|2\d|3[0-1])\.\d+\.\d+",
            r"::1",
            r"169\.254\.\d+\.\d+",  # link-local
            r"metadata\.google",  # GCP metadata
            r"169\.254\.169\.254",  # AWS/GCP metadata
        ]
        for pat in blocked_patterns:
            if re.search(pat, v, re.IGNORECASE):
                raise ValueError(
                    f"Сканування приватних/localhost/metadata адрес заборонено: {v}"
                )

        # Парсинг URL для додаткових перевірок
        import ipaddress
        from urllib.parse import urlparse

        parsed = urlparse(v)
        host = parsed.hostname or ""
        # Якщо host — IP, перевіряємо ipaddress.is_private
        try:
            ip = ipaddress.ip_address(host)
            if (
                ip.is_private
                or ip.is_loopback
                or ip.is_link_local
                or ip.is_multicast
                or ip.is_reserved
            ):
                raise ValueError(f"Сканування приватних IP заборонено: {host}")
        except ValueError as e:
            if "заборонено" in str(e):
                raise
            # не IP — ок

        if len(v) > 2048:
            raise ValueError("URL занадто довгий")
        # DNS rebinding: резолв хоста і перевірка IP на приватність
        try:
            import socket

            # Не фейлити валідацію якщо DNS недоступний — перевірка в сканерах пізніше
            infos = socket.getaddrinfo(host, None, family=socket.AF_UNSPEC)
            for fam, _, _, _, sockaddr in infos:
                ip_str = sockaddr[0]
                try:
                    ip2 = ipaddress.ip_address(ip_str)
                    if ip2.is_private or ip2.is_loopback or ip2.is_link_local:
                        raise ValueError(
                            f"Хост {host} резолвиться в приватний IP {ip_str} — заблоковано"
                        )
                except ValueError as e:
                    if "заблоковано" in str(e):
                        raise
        except ValueError:
            raise
        except Exception:
            pass
        return v


class Finding(BaseModel):
    type: str = Field(..., description="Тип вразливості")
    severity: Severity
    score: int = Field(..., ge=0, le=100)
    description: str = ""
    fix: str = Field(..., description="Рекомендація з виправлення")
    owasp_category: str | None = None
    evidence: str | None = None


class ScannerResult(BaseModel):
    scanner: str
    findings: list[Finding] = []
    duration_ms: int | None = None
    error: str | None = None


class ScanResult(BaseModel):
    scan_id: str
    url: str
    status: ScanStatus = ScanStatus.COMPLETED
    risk_score: int = Field(..., ge=0, le=100)
    level: RiskLevel
    findings: list[Finding] = []
    scanners: list[ScannerResult] = []
    created_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: datetime | None = None
    duration_ms: int | None = None

    @property
    def findings_by_severity(self) -> dict:
        counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
        for f in self.findings:
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
        return counts


class ScanHistoryItem(BaseModel):
    scan_id: str
    url: str
    risk_score: int
    level: RiskLevel
    status: ScanStatus
    findings_count: int
    created_at: datetime


class ScanStatusResponse(BaseModel):
    scan_id: str
    status: ScanStatus
    url: str
    progress: int = Field(..., ge=0, le=100, description="Прогрес 0-100%")
    message: str | None = None
