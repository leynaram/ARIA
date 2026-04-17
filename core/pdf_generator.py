# core/pdf_generator.py
import io
from datetime import datetime

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.lib import colors
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer,
        Table, TableStyle, HRFlowable
    )
    from reportlab.lib.enums import TA_CENTER, TA_LEFT
    REPORTLAB_OK = True
except ImportError:
    REPORTLAB_OK = False

from core.regulations import REGULATIONS


def generate_audit_pdf(audit_results: dict, company_name: str = "Lemonway") -> bytes:
    """Génère le PDF d'audit. Fallback texte si reportlab absent."""
    if REPORTLAB_OK:
        return _generate_with_reportlab(audit_results, company_name)
    else:
        return _generate_text_fallback(audit_results, company_name)


# ─── VERSION REPORTLAB ─────────────────────────────────────────────
def _generate_with_reportlab(audit_results: dict, company_name: str) -> bytes:
    buffer = io.BytesIO()

    C_DARK   = colors.HexColor("#0a1628")
    C_ACCENT = colors.HexColor("#00d4ff")
    C_GREEN  = colors.HexColor("#00ff88")
    C_YELLOW = colors.HexColor("#ffc800")
    C_RED    = colors.HexColor("#ff3366")
    C_WHITE  = colors.white
    C_LIGHT  = colors.HexColor("#f0f6ff")
    C_MUTED  = colors.HexColor("#4a7a9b")
    C_TEXT   = colors.HexColor("#1a1a2e")

    def status_color(s):
        return {"good":"#00ff88","pass":"#00ff88","warning":"#ffc800",
                "fail":"#ff3366","critical":"#ff3366"}.get(s, "#4a7a9b")

    def status_label(s):
        return {"good":"✓ BON","pass":"✓ OK","warning":"⚠ ATTENTION",
                "fail":"✗ ÉCHEC","critical":"✗ CRITIQUE"}.get(s, s.upper())

    doc    = SimpleDocTemplate(buffer, pagesize=A4,
                               topMargin=1.5*cm, bottomMargin=1.5*cm,
                               leftMargin=2*cm, rightMargin=2*cm)
    styles = getSampleStyleSheet()
    story  = []

    # Styles
    title_s = ParagraphStyle("T", parent=styles["Normal"], fontSize=22,
                              textColor=C_WHITE, fontName="Helvetica-Bold",
                              alignment=TA_CENTER, spaceAfter=4)
    sub_s   = ParagraphStyle("S", parent=styles["Normal"], fontSize=10,
                              textColor=C_ACCENT, alignment=TA_CENTER)
    sec_s   = ParagraphStyle("H", parent=styles["Normal"], fontSize=12,
                              textColor=C_WHITE, fontName="Helvetica-Bold",
                              spaceBefore=12, spaceAfter=6, backColor=C_DARK,
                              leftIndent=-10, rightIndent=-10, leading=20)
    body_s  = ParagraphStyle("B", parent=styles["Normal"], fontSize=9,
                              textColor=C_TEXT, spaceAfter=4, leading=14)
    bold_s  = ParagraphStyle("Bd", parent=styles["Normal"], fontSize=9,
                              textColor=C_TEXT, fontName="Helvetica-Bold")
    foot_s  = ParagraphStyle("F", parent=styles["Normal"], fontSize=7,
                              textColor=C_MUTED, alignment=TA_CENTER)

    # ── En-tête ──────────────────────────────────────────────────
    hdr = Table([[Paragraph(f"⬡ ARIA — RAPPORT D'AUDIT DE SÉCURITÉ", title_s)],
                 [Paragraph(company_name, sub_s)],
                 [Paragraph(datetime.now().strftime("%d/%m/%Y à %H:%M"), sub_s)]],
                colWidths=[17*cm])
    hdr.setStyle(TableStyle([
        ("BACKGROUND",    (0,0),(-1,-1), C_DARK),
        ("TOPPADDING",    (0,0),(-1,-1), 16),
        ("BOTTOMPADDING", (0,0),(-1,-1), 16),
    ]))
    story += [hdr, Spacer(1, 0.4*cm)]

    # ── Score global ─────────────────────────────────────────────
    gs = audit_results.get("global_score", 0)
    st = audit_results.get("global_status", "critical")
    sc = colors.HexColor(status_color(st))
    lbl = {"good":"✅ CONFORME","warning":"⚠️ À AMÉLIORER","critical":"🚨 NON CONFORME"}.get(st,"")

    score_tbl = Table([[Paragraph("SCORE GLOBAL", ParagraphStyle("sg",parent=styles["Normal"],
                                  fontSize=9,textColor=C_MUTED,alignment=TA_CENTER))],
                       [Paragraph(f"{gs}%", ParagraphStyle("sv",parent=styles["Normal"],
                                  fontSize=44,textColor=sc,fontName="Helvetica-Bold",alignment=TA_CENTER))],
                       [Paragraph(lbl, ParagraphStyle("sl",parent=styles["Normal"],
                                  fontSize=11,textColor=sc,fontName="Helvetica-Bold",alignment=TA_CENTER))]],
                      colWidths=[17*cm])
    score_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0,0),(-1,-1), C_LIGHT),
        ("TOPPADDING",    (0,0),(-1,-1), 10),
        ("BOTTOMPADDING", (0,0),(-1,-1), 10),
        ("BOX",           (0,0),(-1,-1), 1.5, sc),
    ]))
    story += [score_tbl, Spacer(1, 0.4*cm)]

    # ── Domaines ─────────────────────────────────────────────────
    story.append(Paragraph("  1. RÉSUMÉ PAR DOMAINE", sec_s))
    rows = [["Domaine","Score","Statut"]]
    for d in audit_results.get("domains", {}).values():
        rows.append([d["label"], f"{d['score']}%", status_label(d["status"])])
    tbl = Table(rows, colWidths=[10*cm,3*cm,4*cm])
    ts  = [("BACKGROUND",(0,0),(-1,0),C_DARK),("TEXTCOLOR",(0,0),(-1,0),C_ACCENT),
           ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),("FONTSIZE",(0,0),(-1,-1),9),
           ("ROWBACKGROUNDS",(0,1),(-1,-1),[C_WHITE,C_LIGHT]),
           ("GRID",(0,0),(-1,-1),0.5,colors.HexColor("#d0e4f0")),
           ("TOPPADDING",(0,0),(-1,-1),7),("BOTTOMPADDING",(0,0),(-1,-1),7),
           ("LEFTPADDING",(0,0),(-1,-1),8),("ALIGN",(1,0),(-1,-1),"CENTER")]
    for i, d in enumerate(audit_results.get("domains",{}).values(), 1):
        c = colors.HexColor(status_color(d["status"]))
        ts += [("TEXTCOLOR",(2,i),(2,i),c),("FONTNAME",(2,i),(2,i),"Helvetica-Bold")]
    tbl.setStyle(TableStyle(ts))
    story += [tbl, Spacer(1, 0.4*cm)]

    # ── Recommandations ──────────────────────────────────────────
    recs = audit_results.get("recommendations", [])
    if recs:
        story.append(Paragraph("  2. RECOMMANDATIONS PRIORITAIRES", sec_s))
        rec_rows = [["#","Domaine","Problème","Action","Sévérité"]]
        for r in recs:
            rec_rows.append([str(r["priority"]), r["domain"][:22],
                             r["issue"][:28], r["action"][:48], r["severity"]])
        rt = Table(rec_rows, colWidths=[0.7*cm,3.3*cm,3.5*cm,6.5*cm,2.5*cm])
        rs = [("BACKGROUND",(0,0),(-1,0),C_DARK),("TEXTCOLOR",(0,0),(-1,0),C_ACCENT),
              ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),("FONTSIZE",(0,0),(-1,-1),7.5),
              ("ROWBACKGROUNDS",(0,1),(-1,-1),[C_WHITE,C_LIGHT]),
              ("GRID",(0,0),(-1,-1),0.5,colors.HexColor("#d0e4f0")),
              ("TOPPADDING",(0,0),(-1,-1),5),("BOTTOMPADDING",(0,0),(-1,-1),5),
              ("LEFTPADDING",(0,0),(-1,-1),5),("VALIGN",(0,0),(-1,-1),"MIDDLE")]
        for i, r in enumerate(recs, 1):
            c = C_RED if r["severity"] == "Critique" else C_YELLOW
            rs += [("TEXTCOLOR",(4,i),(4,i),c),("FONTNAME",(4,i),(4,i),"Helvetica-Bold")]
        rt.setStyle(TableStyle(rs))
        story += [rt, Spacer(1, 0.4*cm)]

    # ── Réglementations ──────────────────────────────────────────
    applicable = audit_results.get("regulations", ["RGPD", "NIS2", "DORA"])
    story.append(Paragraph("  3. RÉGLEMENTATIONS & SANCTIONS", sec_s))
    for reg_name in applicable:
        reg = REGULATIONS.get(reg_name)
        if not reg:
            continue
        story += [
            Spacer(1, 0.2*cm),
            Paragraph(f"📋 {reg_name} — {reg['nom_complet']}", bold_s),
            Paragraph(f"Autorité : {reg.get('autorité','N/A')} | Délai : {reg.get('délai_notification','N/A')}", body_s),
        ]
        s_rows = [["Niveau","Montant max","% CA"]]
        for niveau, details in reg.get("sanctions", {}).items():
            s_rows.append([
                niveau.replace("_"," ").title(),
                details.get("montant_max", details.get("amendes_mensuelles","Variable")),
                details.get("pourcentage_ca", details.get("astreinte_journalière","—"))
            ])
        st_tbl = Table(s_rows, colWidths=[4*cm,6*cm,7*cm])
        st_tbl.setStyle(TableStyle([
            ("BACKGROUND",(0,0),(-1,0),colors.HexColor("#ffe0e8")),
            ("TEXTCOLOR",(0,0),(-1,0),C_RED),("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),
            ("FONTSIZE",(0,0),(-1,-1),8),("ROWBACKGROUNDS",(0,1),(-1,-1),[C_WHITE,C_LIGHT]),
            ("GRID",(0,0),(-1,-1),0.5,colors.HexColor("#ffccd5")),
            ("TOPPADDING",(0,0),(-1,-1),5),("BOTTOMPADDING",(0,0),(-1,-1),5),
            ("LEFTPADDING",(0,0),(-1,-1),8),
        ]))
        story += [st_tbl, Spacer(1, 0.2*cm)]

    # ── Pied de page ─────────────────────────────────────────────
    story += [
        HRFlowable(width="100%", thickness=1, color=C_MUTED),
        Spacer(1, 0.2*cm),
        Paragraph(f"Document confidentiel — ARIA CyberAI — {datetime.now().strftime('%d/%m/%Y %H:%M')}", foot_s)
    ]

    doc.build(story)
    return buffer.getvalue()


# ─── FALLBACK TEXTE (si reportlab absent) ─────────────────────────
def _generate_text_fallback(audit_results: dict, company_name: str) -> bytes:
    """Génère un PDF basique en texte brut si reportlab n'est pas installé."""
    lines = [
        f"RAPPORT D'AUDIT DE SÉCURITÉ — {company_name}",
        f"Généré le {datetime.now().strftime('%d/%m/%Y à %H:%M')}",
        "=" * 60,
        f"SCORE GLOBAL : {audit_results.get('global_score', 0)}%",
        f"STATUT : {audit_results.get('global_status', 'N/A').upper()}",
        "=" * 60,
        "DOMAINES :",
    ]
    for key, d in audit_results.get("domains", {}).items():
        lines.append(f"  {d['label']} : {d['score']}%")

    lines += ["", "RECOMMANDATIONS :"]
    for r in audit_results.get("recommendations", [])[:10]:
        lines.append(f"  [{r['severity']}] {r['issue']}")
        lines.append(f"    → {r['action']}")

    content = "\n".join(lines).encode("utf-8")
    return content