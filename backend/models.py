"""
Pydantic моделі для CyberGuard
"""
from pydantic import BaseModel, HttpUrl, Field, field_validator
from typing import List, Optional, Literal
from datetime import datetime
from enum import Enum
import re


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
    url: str = Field(..., description="URL для сканування", examples=["https://testphp.vulnweb.com"])

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        v = v.strip()
        # Додаємо https якщо немає схеми
        if not v.startswith(("http://", "https://")):
            v = "https://" + v

        # Блокуємо localhost / приватні мережі
        blocked_patterns = [
            r"localhost",
            r"127\.0\.0\.1",
            r"0\.0\.0\.0",
            r"10\.\d+\.\d+\.\d+",
            r"192\.168\.\d+\.\d+",
            r"172\.(1[6-9]|2\d|3[0-1])\.\d+\.\d+",
            r"::1",
            r"file://",
        ]
        for pat in blocked_patterns:
            if re.search(pat, v, re.IGNORECASE):
                raise ValueError(f"Сканування приватних/localhost адрес заборонено: {v}")

        # Базовая перевірка URL
        if len(v) > 2048:
            raise ValueError("URL занадто довгий")
        return v


class Finding(BaseModel):
    type: str = Field(..., description="Тип вразливості")
    severity: Severity
    score: int = Field(..., ge=0, le=100)
    description: str = ""
    fix: str = Field(..., description="Рекомендація з виправлення")
    owasp_category: Optional[str] = None
    evidence: Optional[str] = None


class ScannerResult(BaseModel):
    scanner: str
    findings: List[Finding] = []
    duration_ms: Optional[int] = None
    error: Optional[str] = None


class ScanResult(BaseModel):
    scan_id: str
    url: str
    status: ScanStatus = ScanStatus.COMPLETED
    risk_score: int = Field(..., ge=0, le=100)
    level: RiskLevel
    findings: List[Finding] = []
    scanners: List[ScannerResult] = []
    created_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None
    duration_ms: Optional[int] = None

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
    message: Optional[str] = None
