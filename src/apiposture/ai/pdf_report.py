"""
Generiranje PDF izvještaja nakon skeniranja.

Uzima rezultat AI filtera (kept + suppressed) i stvara uredan PDF
s pregledom nalaza, pogodan za dokumentaciju i prilaganje uz rad.

Pokretanje (iz koda):
    from apiposture.ai.pdf_report import generate_pdf_report
    generate_pdf_report(ai_result, scan_path="putanja/do/projekta")

Zahtjev:
    pip install reportlab
"""

from datetime import datetime
from pathlib import Path

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.units import cm
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                    Table, TableStyle)
    REPORTLAB_OK = True
except ImportError:
    REPORTLAB_OK = False


# Boje po ozbiljnosti
SEVERITY_COLORS = {
    "critical": colors.HexColor("#c0392b") if REPORTLAB_OK else None,
    "high": colors.HexColor("#e67e22") if REPORTLAB_OK else None,
    "medium": colors.HexColor("#f39c12") if REPORTLAB_OK else None,
    "low": colors.HexColor("#3498db") if REPORTLAB_OK else None,
}


def generate_pdf_report(ai_result: dict, scan_path: str = "",
                        output_path: str = None) -> str:
    """
    Stvara PDF izvjestaj iz rezultata AI filtera.

    Args:
        ai_result: rjecnik s kljucevima "kept", "suppressed", "stats"
                   (izlaz funkcije process_findings)
        scan_path: putanja skeniranog projekta (za zaglavlje)
        output_path: gdje spremiti PDF (ako None, generira se ime s datumom)

    Returns:
        putanja do stvorenog PDF-a
    """
    if not REPORTLAB_OK:
        print("PDF izvjestaj zahtijeva reportlab. Pokreni: pip install reportlab")
        return ""

    # Ime datoteke
    if output_path is None:
        stamp = datetime.now().strftime("%Y-%m-%d_%H-%M")
        output_path = f"apiposture_izvjestaj_{stamp}.pdf"

    doc = SimpleDocTemplate(output_path, pagesize=A4,
                            leftMargin=2*cm, rightMargin=2*cm,
                            topMargin=2*cm, bottomMargin=2*cm)

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("Naslov", parent=styles["Title"],
                                 fontSize=18, spaceAfter=12)
    h2_style = ParagraphStyle("Pod", parent=styles["Heading2"],
                              fontSize=13, spaceBefore=12, spaceAfter=6)
    normal = styles["Normal"]

    elements = []

    # ---- Zaglavlje ----
    elements.append(Paragraph("ApiPosture - Izvjestaj skeniranja", title_style))
    elements.append(Paragraph(
        f"Datum: {datetime.now().strftime('%d.%m.%Y. %H:%M')}", normal))
    if scan_path:
        elements.append(Paragraph(f"Projekt: {scan_path}", normal))
    elements.append(Spacer(1, 12))

    # ---- Statistika ----
    stats = ai_result.get("stats", {})
    kept = ai_result.get("kept", [])
    suppressed = ai_result.get("suppressed", [])
    total = stats.get("total", len(kept) + len(suppressed))

    elements.append(Paragraph("Sazetak", h2_style))
    stat_data = [
        ["Pokazatelj", "Vrijednost"],
        ["Ukupno nalaza", str(total)],
        ["Aktivni (prave ranjivosti)", str(len(kept))],
        ["Izdvojeni (lazni alarmi)", str(len(suppressed))],
        ["  - pravilima", str(stats.get("by_rule", 0))],
        ["  - jezicnim modelom", str(stats.get("by_llm", 0))],
        ["  - od strane developera", str(stats.get("by_developer", 0))],
    ]
    if total:
        fp_rate = len(suppressed) / total * 100
        stat_data.append(["Stopa izdvojenih", f"{fp_rate:.1f}%"])

    stat_table = Table(stat_data, colWidths=[8*cm, 5*cm])
    stat_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c3e50")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f2f2f2")]),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
    ]))
    elements.append(stat_table)
    elements.append(Spacer(1, 16))

    # ---- Aktivni nalazi (prave ranjivosti) ----
    elements.append(Paragraph("Aktivni nalazi (zadrzani za pregled)", h2_style))
    if kept:
        rows = [["Alarm", "Metoda", "Ruta", "Ozbiljnost"]]
        for f in kept:
            rows.append([
                f.get("alarm", ""),
                f.get("method", ""),
                f.get("route", "")[:40],
                str(f.get("severity", "")).upper(),
            ])
        t = _make_findings_table(rows)
        elements.append(t)
    else:
        elements.append(Paragraph("Nema aktivnih nalaza.", normal))
    elements.append(Spacer(1, 16))

    # ---- Izdvojeni nalazi (lazni alarmi) ----
    elements.append(Paragraph("Izdvojeni nalazi (lazno pozitivni)", h2_style))
    if suppressed:
        rows = [["Alarm", "Metoda", "Ruta", "Izvor", "Sigurnost"]]
        src_map = {"rule": "pravilo", "llm": "LLM", "developer": "developer"}
        for f in suppressed:
            rows.append([
                f.get("alarm", ""),
                f.get("method", ""),
                f.get("route", "")[:35],
                src_map.get(f.get("ai_source"), "?"),
                f"{f.get('confidence', 0)}%",
            ])
        t = _make_findings_table(rows, cols=5)
        elements.append(t)
    else:
        elements.append(Paragraph("Nema izdvojenih nalaza.", normal))

    # ---- Napomena ----
    elements.append(Spacer(1, 20))
    note_style = ParagraphStyle("Napomena", parent=normal,
                                fontSize=8, textColor=colors.grey)
    elements.append(Paragraph(
        "Izvjestaj generiran automatski pomocu ApiPosture AI filtera. "
        "Aktivni nalazi zahtijevaju pregled razvojnog inzenjera.", note_style))

    doc.build(elements)
    print(f"PDF izvjestaj stvoren: {output_path}")
    return output_path


def _make_findings_table(rows, cols=4):
    """Pomocna funkcija za tablicu nalaza."""
    if cols == 4:
        widths = [2.5*cm, 2*cm, 7*cm, 2.5*cm]
    else:
        widths = [2*cm, 1.8*cm, 6*cm, 2.2*cm, 2*cm]

    t = Table(rows, colWidths=widths, repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#34495e")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8f8f8")]),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    return t


if __name__ == "__main__":
    # Demo s izmisljenim podacima da se vidi izgled
    demo = {
        "kept": [
            {"alarm": "AP004", "method": "POST", "route": "/deserialize",
             "severity": "critical", "ai_source": "none", "confidence": 0},
            {"alarm": "AP001", "method": "GET", "route": "/admin/config",
             "severity": "high", "ai_source": "none", "confidence": 0},
        ],
        "suppressed": [
            {"alarm": "AP001", "method": "GET", "route": "/",
             "severity": "high", "ai_source": "rule", "confidence": 95},
            {"alarm": "AP008", "method": "GET", "route": "/lab",
             "severity": "high", "ai_source": "rule", "confidence": 95},
        ],
        "stats": {"total": 4, "kept": 2, "suppressed": 2,
                  "by_rule": 2, "by_llm": 0, "by_developer": 0},
    }
    generate_pdf_report(demo, scan_path="demo/projekt")