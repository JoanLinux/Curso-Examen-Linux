from datetime import datetime
import html
from pathlib import Path
import re

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import Image, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


ROOT = Path(__file__).resolve().parents[1]
MANUAL_MD = ROOT / "docs" / "MANUAL_USUARIO_DESARROLLO.md"
OUT_DIR = ROOT / "output" / "pdf"
OUT_PDF = OUT_DIR / "MANUAL_USUARIO_DESARROLLO_CursoLinux.pdf"
IKUSI_LOGO = ROOT / "static" / "images" / "ikusi_logo_local.png"
SAT_LOGO = ROOT / "static" / "images" / "sat_logo_local.png"


def build_styles():
    styles = getSampleStyleSheet()
    return {
        "title": ParagraphStyle(
            "title",
            parent=styles["Heading1"],
            fontName="Helvetica-Bold",
            fontSize=24,
            leading=28,
            textColor=colors.HexColor("#0f3557"),
            spaceAfter=8,
        ),
        "subtitle": ParagraphStyle(
            "subtitle",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=11,
            leading=14,
            textColor=colors.HexColor("#35526e"),
            spaceAfter=14,
        ),
        "h2": ParagraphStyle(
            "h2",
            parent=styles["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=14,
            leading=18,
            textColor=colors.HexColor("#0f3557"),
            spaceBefore=8,
            spaceAfter=6,
        ),
        "h3": ParagraphStyle(
            "h3",
            parent=styles["Heading3"],
            fontName="Helvetica-Bold",
            fontSize=12,
            leading=15,
            textColor=colors.HexColor("#174d7d"),
            spaceBefore=6,
            spaceAfter=4,
        ),
        "p": ParagraphStyle(
            "p",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=10.2,
            leading=14,
            textColor=colors.HexColor("#1b2733"),
            spaceAfter=4,
        ),
        "bullet": ParagraphStyle(
            "bullet",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=10.2,
            leading=14,
            leftIndent=12,
            bulletIndent=2,
            textColor=colors.HexColor("#1b2733"),
            spaceAfter=2,
        ),
        "code": ParagraphStyle(
            "code",
            parent=styles["Code"],
            fontName="Courier",
            fontSize=9,
            leading=12,
            textColor=colors.HexColor("#0f3557"),
            backColor=colors.HexColor("#edf3fa"),
            borderWidth=0.6,
            borderColor=colors.HexColor("#c7d6e6"),
            borderPadding=6,
            spaceAfter=6,
        ),
    }


def footer(canvas, doc):
    canvas.saveState()
    page_num = canvas.getPageNumber()
    canvas.setFont("Helvetica", 8.5)
    canvas.setFillColor(colors.HexColor("#6a7e93"))
    canvas.drawString(doc.leftMargin, 0.8 * cm, "CursoLinux - Manual de Usuario (Desarrollo)")
    canvas.drawRightString(A4[0] - doc.rightMargin, 0.8 * cm, f"Pagina {page_num}")
    canvas.restoreState()


def header_block(styles):
    title = Paragraph("Manual de Usuario (Desarrollo)", styles["title"])
    subtitle = Paragraph(
        f"Plataforma CursoLinux | Fecha de generacion: {datetime.now().strftime('%Y-%m-%d %H:%M')}",
        styles["subtitle"],
    )

    ikusi = Image(str(IKUSI_LOGO), width=3.6 * cm, height=1.8 * cm)
    sat = Image(str(SAT_LOGO), width=3.6 * cm, height=1.8 * cm)

    logos = Table(
        [[ikusi, sat]],
        colWidths=[3.8 * cm, 3.8 * cm],
        hAlign="RIGHT",
    )
    logos.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ]
        )
    )

    header_table = Table(
        [[title, logos], [subtitle, ""]],
        colWidths=[10.0 * cm, 7.6 * cm],
        hAlign="LEFT",
    )
    header_table.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("SPAN", (0, 1), (1, 1)),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
            ]
        )
    )
    return header_table


def parse_markdown(md_text, styles):
    story = []
    in_code = False
    code_lines = []

    def fmt_inline(text):
        esc = html.escape(text)
        return re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", esc)

    def flush_code():
        nonlocal code_lines
        if code_lines:
            text = "<br/>".join(
                line.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;") for line in code_lines
            )
            story.append(Paragraph(text, styles["code"]))
            code_lines = []

    for raw in md_text.splitlines():
        line = raw.rstrip()
        if line.strip().startswith("```"):
            if in_code:
                flush_code()
                in_code = False
            else:
                in_code = True
            continue

        if in_code:
            code_lines.append(line)
            continue

        if not line.strip():
            story.append(Spacer(1, 0.14 * cm))
            continue

        if line.startswith("# "):
            continue
        if line.startswith("## "):
            story.append(Paragraph(line[3:].strip(), styles["h2"]))
            continue
        if line.startswith("### "):
            story.append(Paragraph(line[4:].strip(), styles["h3"]))
            continue
        if line.startswith("- "):
            text = fmt_inline(line[2:].strip())
            story.append(Paragraph(text, styles["bullet"], bulletText="•"))
            continue

        text = fmt_inline(line)
        story.append(Paragraph(text, styles["p"]))

    flush_code()
    return story


def main():
    if not MANUAL_MD.exists():
        raise SystemExit(f"No existe: {MANUAL_MD}")
    if not IKUSI_LOGO.exists() or not SAT_LOGO.exists():
        raise SystemExit("No se encontraron logos IKUSI/SAT en static/images")

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    styles = build_styles()

    story = [
        header_block(styles),
        Spacer(1, 0.4 * cm),
        Paragraph("Guia operativa y tecnica para uso diario del desarrollo y UAT.", styles["p"]),
        Spacer(1, 0.18 * cm),
    ]
    story.extend(parse_markdown(MANUAL_MD.read_text(encoding="utf-8"), styles))

    doc = SimpleDocTemplate(
        str(OUT_PDF),
        pagesize=A4,
        leftMargin=1.7 * cm,
        rightMargin=1.7 * cm,
        topMargin=1.5 * cm,
        bottomMargin=1.6 * cm,
        title="Manual Usuario Desarrollo CursoLinux",
        author="CursoLinux",
    )
    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    print(str(OUT_PDF))


if __name__ == "__main__":
    main()
