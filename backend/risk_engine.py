"""
Risk Engine — підрахунок загального балу ризику 0-100
"""
from typing import List
from .models import Finding, Severity, RiskLevel


# Ваги за severity
SEVERITY_WEIGHTS = {
    Severity.LOW: 5,
    Severity.MEDIUM: 15,
    Severity.HIGH: 25,
    Severity.CRITICAL: 40,
}

# Якщо finding не має явного score — рахуємо по severity
def finding_score(finding: Finding) -> int:
    if finding.score and finding.score > 0:
        return finding.score
    return SEVERITY_WEIGHTS.get(finding.severity, 5)


def calculate_risk(findings: List[Finding]) -> tuple[int, RiskLevel]:
    """
    Рахує сумарний risk_score (0-100) та рівень.
    Сума всіх findings капається на 100.
    """
    total = sum(finding_score(f) for f in findings)
    # Капаємо 0-100
    total = max(0, min(100, total))

    if total <= 30:
        level = RiskLevel.LOW
    elif total <= 69:
        level = RiskLevel.MEDIUM
    else:
        level = RiskLevel.HIGH

    return total, level


def aggregate_findings(scanner_results: list) -> List[Finding]:
    """
    Збирає всі findings з різних сканерів в один список.
    """
    all_findings: List[Finding] = []
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
    return all_findings


def sort_findings(findings: List[Finding]) -> List[Finding]:
    """
    Сортує за severity: CRITICAL > HIGH > MEDIUM > LOW
    """
    order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3}
    return sorted(findings, key=lambda f: order.get(f.severity, 99))


def get_summary(findings: List[Finding]) -> dict:
    """
    Статистика для дашборду / PDF
    """
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
