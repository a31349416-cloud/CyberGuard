"""
Генерація PDF звіту через fpdf2
"""

from datetime import datetime
from pathlib import Path

from fpdf import FPDF

# Кольори
COLORS = {
    "LOW": (34, 197, 94),  # green
    "MEDIUM": (234, 179, 8),  # yellow
    "HIGH": (239, 68, 68),  # red
    "CRITICAL": (153, 27, 27),
    "bg": (248, 250, 252),
    "dark": (15, 23, 42),
    "muted": (100, 116, 139),
}


class CyberGuardPDF(FPDF):
    def header(self):
        self.set_font("Helvetica", "B", 10)
        self.set_text_color(*COLORS["muted"])
        self.cell(0, 8, "CyberGuard  |  OWASP TOP-10 Security Audit", align="C")
        self.ln(10)
        # Лінія
        self.set_draw_color(226, 232, 240)
        self.set_line_width(0.4)
        self.line(10, self.get_y(), 200, self.get_y())
        self.ln(4)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 7)
        self.set_text_color(*COLORS["muted"])
        self.cell(
            0,
            10,
            f"CyberGuard Report  |  Page {self.page_no()}/{{nb}}  |  Generated {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}  |  Ethical Use Only",
            align="C",
        )

    def risk_badge(self, score: int, level: str):
        color = COLORS.get(level, COLORS["LOW"])
        # Круглий бейдж
        x = 85
        y = self.get_y()
        self.set_fill_color(*color)
        self.set_text_color(255, 255, 255)
        self.set_font("Helvetica", "B", 28)
        # Прямокутник з круглими кутами (імітація)
        self.set_xy(x, y)
        self.cell(40, 26, f"{score}", align="C", fill=True)
        self.ln(28)
        self.set_font("Helvetica", "B", 11)
        self.set_text_color(*color)
        self.cell(0, 6, f"RISK LEVEL: {level}", align="C")
        self.ln(8)
        self.set_text_color(*COLORS["muted"])
        self.set_font("Helvetica", "", 8)
        scale = "0-30 LOW  |  31-69 MEDIUM  |  70-100 HIGH"
        self.cell(0, 4, scale, align="C")
        self.ln(8)

    def section_title(self, title: str):
        self.set_font("Helvetica", "B", 12)
        self.set_text_color(*COLORS["dark"])
        self.set_fill_color(*COLORS["bg"])
        self.cell(0, 9, f"  {title}", fill=True)
        self.ln(11)

    def finding_card(self, idx: int, finding: dict):
        severity = finding.get("severity", "LOW")
        color = COLORS.get(severity, COLORS["LOW"])
        score = finding.get("score", 0)
        ftype = finding.get("type", "Unknown")
        desc = finding.get("description", "")
        fix = finding.get("fix", "")
        owasp = finding.get("owasp_category", "")

        # Перевірка місця на сторінці
        if self.get_y() > 240:
            self.add_page()

        y_start = self.get_y()

        # Severity смужка зліва
        self.set_fill_color(*color)
        self.rect(10, y_start, 3, 28, style="F")

        # Фон картки
        self.set_fill_color(255, 255, 255)
        self.set_draw_color(226, 232, 240)
        self.rect(10, y_start, 190, 28, style="D")

        # Вміст
        self.set_xy(15, y_start + 2)
        self.set_font("Helvetica", "B", 9)
        self.set_text_color(*COLORS["dark"])
        self.cell(130, 5, f"#{idx}  {ftype}")

        self.set_font("Helvetica", "B", 7)
        self.set_text_color(*color)
        self.set_fill_color(255, 255, 255)
        # Badges справа
        self.cell(25, 5, f"{severity}", align="C", border=1)
        self.cell(15, 5, f"+{score}", align="C", border=1)
        self.ln(7)

        self.set_x(15)
        self.set_font("Helvetica", "", 7)
        self.set_text_color(*COLORS["muted"])
        # Обрізаємо опис щоб вліз
        desc_short = desc[:120] + ("..." if len(desc) > 120 else "")
        self.cell(0, 4, desc_short)
        self.ln(5)

        self.set_x(15)
        self.set_font("Helvetica", "I", 7)
        self.set_text_color(37, 99, 235)
        fix_short = fix[:130] + ("..." if len(fix) > 130 else "")
        self.cell(0, 4, f"Fix: {fix_short}")
        self.ln(6)

        if owasp:
            self.set_x(15)
            self.set_font("Helvetica", "", 6)
            self.set_text_color(*COLORS["muted"])
            self.cell(0, 3, f"OWASP: {owasp}")
            self.ln(4)

        self.set_y(y_start + 30)


def generate_pdf(scan_data: dict, output_path: str | None = None) -> str:
    """
    Генерує PDF звіт і повертає шлях до файлу.
    scan_data: dict з полями scan_id, url, risk_score, level, findings, created_at
    """
    scan_id = scan_data.get("scan_id", "unknown")
    url = scan_data.get("url", "")
    score = scan_data.get("risk_score", 0)
    level = scan_data.get("level", "LOW")
    findings: list[dict] = scan_data.get("findings", [])
    created_at = scan_data.get("created_at", datetime.utcnow().isoformat())
    # Якщо created_at вже datetime
    if hasattr(created_at, "isoformat"):
        created_at = created_at.isoformat()

    pdf = CyberGuardPDF()
    pdf.alias_nb_pages()
    pdf.set_auto_page_break(auto=True, margin=20)
    pdf.add_page()

    # Титулка
    pdf.set_font("Helvetica", "B", 22)
    pdf.set_text_color(*COLORS["dark"])
    pdf.cell(0, 12, "CyberGuard v2", align="C")
    pdf.ln(9)
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(*COLORS["muted"])
    pdf.cell(0, 5, "OWASP TOP-10  |  10 Scanners Security Audit Report", align="C")
    pdf.ln(8)

    pdf.set_draw_color(226, 232, 240)
    pdf.line(60, pdf.get_y(), 150, pdf.get_y())
    pdf.ln(6)

    # Мета
    pdf.set_font("Helvetica", "", 8)
    pdf.set_text_color(*COLORS["dark"])
    pdf.cell(0, 5, f"Target URL:  {url}", align="C")
    pdf.ln(5)
    pdf.set_text_color(*COLORS["muted"])
    pdf.cell(
        0,
        4,
        f"Scan ID: {scan_id}   |   Date: {created_at[:19]}   |   Findings: {len(findings)}",
        align="C",
    )
    pdf.ln(12)

    # Шкала ризику
    pdf.risk_badge(score, level)
    pdf.ln(2)

    # Summary таблиця + міні-бар chart
    pdf.section_title("Summary by Severity")
    pdf.ln(1)
    counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    for f in findings:
        s = f.get("severity", "LOW")
        counts[s] = counts.get(s, 0) + 1

    # Таблиця
    pdf.set_font("Helvetica", "B", 8)
    pdf.set_fill_color(*COLORS["dark"])
    pdf.set_text_color(255, 255, 255)
    cols = [
        "LOW (5 pts)",
        "MEDIUM (15 pts)",
        "HIGH (25 pts)",
        "CRITICAL (40 pts)",
        "TOTAL",
    ]
    col_w = [36, 38, 38, 40, 38]
    for i, c in enumerate(cols):
        pdf.cell(col_w[i], 8, c, border=1, align="C", fill=True)
    pdf.ln()
    pdf.set_font("Helvetica", "B", 10)
    pdf.set_text_color(*COLORS["dark"])
    pdf.set_fill_color(255, 255, 255)
    vals = [
        str(counts["LOW"]),
        str(counts["MEDIUM"]),
        str(counts["HIGH"]),
        str(counts["CRITICAL"]),
        str(len(findings)),
    ]
    for i, v in enumerate(vals):
        c = COLORS.get(cols[i].split()[0], COLORS["dark"])
        pdf.set_text_color(*c if i < 4 else COLORS["dark"])
        pdf.cell(col_w[i], 8, v, border=1, align="C")
    pdf.ln(10)
    # Бар візуалізація
    total = max(1, len(findings))
    bar_w = 150
    x0 = 30
    y = pdf.get_y()
    pdf.set_font("Helvetica", "", 6)
    pdf.set_text_color(*COLORS["muted"])
    pdf.set_xy(x0, y)
    pdf.cell(bar_w, 4, f"Severity distribution (total {len(findings)})", align="C")
    pdf.ln(5)
    x = x0
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        cnt = counts[sev]
        w = bar_w * cnt / total if cnt else 0
        if w > 0:
            pdf.set_fill_color(*COLORS[sev])
            pdf.rect(x, pdf.get_y(), w, 6, style="F")
            if w > 12:
                pdf.set_xy(x, pdf.get_y())
                pdf.set_font("Helvetica", "B", 6)
                pdf.set_text_color(255, 255, 255)
                pdf.cell(w, 6, str(cnt), align="C")
        x += w
    # рамка
    pdf.rect(x0, pdf.get_y(), bar_w, 6, style="D")
    pdf.ln(10)
    # Легенда
    pdf.set_font("Helvetica", "", 6)
    pdf.set_text_color(*COLORS["muted"])
    pdf.set_x(x0)
    pdf.cell(
        bar_w,
        3,
        "  ".join([f"{s}: {counts[s]}" for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]]),
        align="C",
    )
    pdf.ln(4)

    # OWASP мапа
    owasp_map = scan_data.get("owasp_map") or {}
    if not owasp_map and findings:
        from collections import Counter

        c = Counter()
        for f in findings:
            cat = (f.get("owasp_category") or "Unknown").split(" -")[0].strip()
            c[cat] += 1
        owasp_map = dict(c)
    if owasp_map:
        pdf.section_title("OWASP Top-10 Map")
        pdf.ln(1)
        pdf.set_font("Helvetica", "", 7)
        pdf.set_text_color(*COLORS["dark"])
        for cat, cnt in sorted(owasp_map.items(), key=lambda x: -x[1]):
            pdf.set_x(14)
            bar = "#" * min(cnt * 3, 30)
            pdf.cell(0, 4, f"{cat:12} : {cnt:2}  {bar}")
            pdf.ln(4)
        pdf.ln(2)

    # Тренд (останні 5 сканів для цього URL)
    trend = scan_data.get("trend")
    if not trend and url:
        try:
            from .database import get_trend

            trend = get_trend(url, limit=5)
        except:
            trend = None
    if trend and len(trend) > 1:
        pdf.section_title("Risk Trend (last 5 scans for this URL)")
        pdf.ln(1)
        pdf.set_font("Helvetica", "", 7)
        pdf.set_text_color(*COLORS["muted"])
        # Графік лінія ASCII + бари
        max_score = 100
        x0, y0, w, h = 20, pdf.get_y() + 2, 170, 28
        pdf.set_draw_color(226, 232, 240)
        pdf.rect(x0, y0, w, h, style="D")
        # Сітка
        for i in [0, 25, 50, 75, 100]:
            xx = x0 + w * i / 100
            pdf.set_draw_color(248, 250, 252)
            pdf.line(xx, y0, xx, y0 + h)
        trend_rev = list(reversed(trend))  # хронологічно
        for idx, t in enumerate(trend_rev):
            sc = t.get("risk_score", 0)
            # бари вертикальні
            bar_h = h * sc / max_score
            xx = x0 + w * idx / max(1, len(trend_rev) - 1) if len(trend_rev) > 1 else x0
            # мітка
            lvl = t.get("level", "LOW")
            pdf.set_fill_color(*COLORS.get(lvl, COLORS["LOW"]))
            pdf.rect(xx - 2, y0 + h - bar_h, 4, bar_h, style="F")
            # дата
            dt = str(t.get("created_at", ""))[:10]
            pdf.set_xy(xx - 12, y0 + h + 1)
            pdf.set_font("Helvetica", "", 5)
            pdf.set_text_color(*COLORS["muted"])
            pdf.cell(24, 3, f"{sc}", align="C")
        pdf.set_y(y0 + h + 6)
        pdf.ln(2)

    # Список вразливостей
    pdf.section_title(f"Findings Detail  ({len(findings)} issues)")
    pdf.ln(2)
    if not findings:
        pdf.set_font("Helvetica", "I", 9)
        pdf.set_text_color(*COLORS["LOW"])
        pdf.cell(0, 8, "No vulnerabilities found. Good job!", align="C")
        pdf.ln(8)
    else:
        for idx, f in enumerate(findings, 1):
            pdf.finding_card(idx, f)

    # Рекомендації
    if pdf.get_y() > 220:
        pdf.add_page()
    pdf.ln(4)
    pdf.section_title("Recommendations & Next Steps")
    pdf.ln(1)
    pdf.set_font("Helvetica", "", 8)
    pdf.set_text_color(*COLORS["dark"])
    recommendations = [
        "1. Fix HIGH/CRITICAL issues first - they pose immediate risk.",
        "2. Add missing security headers (CSP, HSTS, X-Frame-Options) via web server config.",
        "3. Ensure HTTPS with valid TLS certificate and redirect HTTP -> HTTPS.",
        "4. Sanitize all user inputs: use html.escape(), parameterized queries, CSP.",
        "5. Close unnecessary ports (21, 22, 3306) via firewall rules.",
        "6. Re-scan after fixes to verify risk score drops to LOW (0-30).",
        "7. Schedule regular scans and keep dependencies updated.",
    ]
    for r in recommendations:
        pdf.set_x(14)
        pdf.multi_cell(182, 5, r)
        pdf.ln(1)

    # Disclaimer
    pdf.ln(4)
    pdf.set_font("Helvetica", "I", 6)
    pdf.set_text_color(*COLORS["muted"])
    pdf.multi_cell(
        0,
        4,
        "Disclaimer: This report is for educational and authorized testing purposes only. Scan only sites you own or have permission to test. The authors are not responsible for misuse. Results are indicative and not a substitute for professional penetration testing.",
        align="C",
    )

    # Збереження
    if output_path is None:
        out_dir = Path(__file__).parent / "reports"
        out_dir.mkdir(exist_ok=True)
        output_path = str(out_dir / f"CyberGuard_{scan_id}.pdf")

    pdf.output(output_path)
    return output_path
