"""
Risk Engine v2 — CVSS-подібне зважування + OWASP ваги
- База: LOW=5, MEDIUM=15, HIGH=25, CRITICAL=40
- Множник за кількість: 1.5x якщо >=3 HIGH, 1.3x якщо >=5 total
- OWASP категорії A03 (Injection) та A01 (Access Control) мають +5 бонус
- Капається 0-100, рівень LOW 0-30, MEDIUM 31-69, HIGH 70-100
"""

from .models import Finding, RiskLevel, Severity

SEVERITY_WEIGHTS = {
    Severity.LOW: 5,
    Severity.MEDIUM: 15,
    Severity.HIGH: 25,
    Severity.CRITICAL: 40,
}

OWASP_BONUS = {
    "A03:2021": 5,
    "A01:2021": 5,
    "A05:2021": 2,
}


def finding_score(finding: Finding) -> int:
    base = (
        finding.score
        if finding.score and finding.score > 0
        else SEVERITY_WEIGHTS.get(finding.severity, 5)
    )
    # OWASP бонус
    if finding.owasp_category:
        for k, bonus in OWASP_BONUS.items():
            if k in finding.owasp_category:
                base += bonus
                break
    return base


def calculate_risk(findings: list[Finding]) -> tuple[int, RiskLevel]:
    total = sum(finding_score(f) for f in findings)
    # Множники за концентрацію вразливостей
    counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    for f in findings:
        key = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        counts[key] = counts.get(key, 0) + 1
    if counts["CRITICAL"] >= 1:
        total = int(total * 1.4)
    elif counts["HIGH"] >= 3:
        total = int(total * 1.3)
    elif len(findings) >= 6:
        total = int(total * 1.15)
    total = max(0, min(100, total))
    if total <= 30:
        level = RiskLevel.LOW
    elif total <= 69:
        level = RiskLevel.MEDIUM
    else:
        level = RiskLevel.HIGH
    return total, level


def aggregate_findings(scanner_results: list) -> list[Finding]:
    all_findings: list[Finding] = []
    for sr in scanner_results:
        if isinstance(sr, dict):
            findings = sr.get("findings", [])
            for f in findings:
                if isinstance(f, dict):
                    try:
                        all_findings.append(Finding(**f))
                    except Exception:
                        continue
                elif isinstance(f, Finding):
                    all_findings.append(f)
        elif hasattr(sr, "findings"):
            all_findings.extend(sr.findings)
    # Дедуплікація по type+severity
    seen = set()
    deduped = []
    for f in all_findings:
        key = (
            f.type,
            f.severity.value if hasattr(f.severity, "value") else str(f.severity),
        )
        if key not in seen:
            seen.add(key)
            deduped.append(f)
    return deduped


def sort_findings(findings: list[Finding]) -> list[Finding]:
    order = {
        Severity.CRITICAL: 0,
        Severity.HIGH: 1,
        Severity.MEDIUM: 2,
        Severity.LOW: 3,
    }
    return sorted(findings, key=lambda f: order.get(f.severity, 99))


def get_summary(findings: list[Finding]) -> dict:
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        key = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        counts[key] = counts.get(key, 0) + 1
    score, level = calculate_risk(findings)
    return {
        "risk_score": score,
        "level": level.value,
        "total_findings": len(findings),
        "by_severity": counts,
    }
