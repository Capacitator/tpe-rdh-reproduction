#!/usr/bin/env python3
"""Render the authenticated-TPE NIST Markdown report as a paginated PDF."""
from __future__ import annotations

import html
import re
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import landscape, letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    BaseDocTemplate, Frame, KeepTogether, PageTemplate, Paragraph, Spacer, Table,
    TableStyle,
)

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "authenticated_tpe" / "output" / "nist_sp800_22_improved"
SOURCE = OUT / "NIST_AUTHENTICATED_TPE_REPORT.md"
DEST = OUT / "NIST_AUTHENTICATED_TPE_REPORT.pdf"


def inline(text: str) -> str:
    value = html.escape(text.strip(), quote=False)
    value = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", value)
    value = re.sub(r"`([^`]+)`", r"<font name='Vera'>\1</font>", value)
    value = re.sub(r"\*\*([^*]+)\*\*", r"<b>\1</b>", value)
    value = re.sub(r"(?<!\*)\*([^*]+)\*", r"<i>\1</i>", value)
    return value.replace("\\|", "|")


def table_cells(line: str) -> list[str]:
    return [cell.strip() for cell in line.strip().strip("|").split("|")]


def create_pdf() -> None:
    fonts = Path(__import__("reportlab").__file__).parent / "fonts"
    pdfmetrics.registerFont(TTFont("Vera", str(fonts / "Vera.ttf")))
    pdfmetrics.registerFont(TTFont("Vera-Bold", str(fonts / "VeraBd.ttf")))
    pdfmetrics.registerFont(TTFont("Vera-Italic", str(fonts / "VeraIt.ttf")))

    page = landscape(letter)
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="ReportTitle", parent=styles["Title"], fontName="Vera-Bold", fontSize=19, leading=23, alignment=TA_LEFT, textColor=colors.HexColor("#13314b"), spaceAfter=14))
    styles.add(ParagraphStyle(name="H2x", parent=styles["Heading2"], fontName="Vera-Bold", fontSize=13, leading=16, textColor=colors.HexColor("#174a6e"), spaceBefore=12, spaceAfter=6, keepWithNext=True))
    styles.add(ParagraphStyle(name="H3x", parent=styles["Heading3"], fontName="Vera-Bold", fontSize=10, leading=13, textColor=colors.HexColor("#236482"), spaceBefore=8, spaceAfter=4, keepWithNext=True))
    styles.add(ParagraphStyle(name="Bodyx", parent=styles["BodyText"], fontName="Vera", fontSize=8.1, leading=11, alignment=TA_LEFT, spaceAfter=6, splitLongWords=1))
    styles.add(ParagraphStyle(name="Bulletx", parent=styles["BodyText"], fontName="Vera", fontSize=7.8, leading=10, leftIndent=12, firstLineIndent=-8, spaceAfter=3, splitLongWords=1))
    styles.add(ParagraphStyle(name="Cellx", fontName="Vera", fontSize=6.0, leading=7.0, splitLongWords=1, wordWrap="CJK"))
    styles.add(ParagraphStyle(name="CellHeadx", fontName="Vera-Bold", fontSize=6.2, leading=7.2, textColor=colors.white, splitLongWords=1, wordWrap="CJK"))

    doc = BaseDocTemplate(str(DEST), pagesize=page, leftMargin=28, rightMargin=28, topMargin=30, bottomMargin=30, title="NIST SP 800-22 Evaluation of Authenticated-TPE", author="Authenticated-TPE Evaluation")
    frame = Frame(doc.leftMargin, doc.bottomMargin, doc.width, doc.height, id="main", leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0)

    def footer(canvas, document):
        canvas.saveState()
        canvas.setStrokeColor(colors.HexColor("#cbd6df"))
        canvas.line(28, 23, page[0] - 28, 23)
        canvas.setFont("Vera", 7)
        canvas.setFillColor(colors.HexColor("#526575"))
        canvas.drawString(28, 12, "Authenticated-TPE | NIST STS 2.1.2 | alpha = 0.01")
        canvas.drawRightString(page[0] - 28, 12, f"Page {document.page}")
        canvas.restoreState()

    doc.addPageTemplates([PageTemplate(id="report", frames=[frame], onPage=footer)])
    lines = SOURCE.read_text(encoding="utf-8").splitlines()
    story = []
    i = 0
    while i < len(lines):
        raw = lines[i]
        stripped = raw.strip()
        if not stripped:
            i += 1
            continue
        if stripped.startswith("|"):
            grid = []
            while i < len(lines) and lines[i].strip().startswith("|"):
                row = table_cells(lines[i])
                if row and all(re.fullmatch(r":?-{3,}:?", c.replace(" ", "")) for c in row):
                    i += 1
                    continue
                grid.append(row)
                i += 1
            if not grid:
                continue
            ncol = max(map(len, grid))
            grid = [row + [""] * (ncol - len(row)) for row in grid]
            widths_weight = []
            headers = [x.lower() for x in grid[0]]
            for h in headers:
                if any(x in h for x in ("category", "component", "p-value")):
                    widths_weight.append(1.55 if "p-value" not in h else 1.35)
                elif any(x in h for x in ("test", "proportion")):
                    widths_weight.append(1.35)
                else:
                    widths_weight.append(0.75)
            available = doc.width
            total = sum(widths_weight)
            widths = [available * weight / total for weight in widths_weight]
            rendered = []
            for r_index, row in enumerate(grid):
                sty = styles["CellHeadx"] if r_index == 0 else styles["Cellx"]
                rendered.append([Paragraph(inline(cell), sty) for cell in row])
            table = Table(rendered, colWidths=widths, repeatRows=1, hAlign="LEFT", splitByRow=1, spaceBefore=2, spaceAfter=7)
            table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#194b68")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#bdcbd5")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f1f5f8")]),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 3),
                ("RIGHTPADDING", (0, 0), (-1, -1), 3),
                ("TOPPADDING", (0, 0), (-1, -1), 1.5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 1.5),
            ]))
            story.append(table)
            continue
        if stripped.startswith("# "):
            story.append(Paragraph(inline(stripped[2:]), styles["ReportTitle"]))
        elif stripped.startswith("## "):
            story.append(Paragraph(inline(stripped[3:]), styles["H2x"]))
        elif stripped.startswith("### "):
            story.append(Paragraph(inline(stripped[4:]), styles["H3x"]))
        elif stripped.startswith("- "):
            story.append(KeepTogether([Paragraph("&#8226; " + inline(stripped[2:]), styles["Bulletx"])]))
        else:
            story.append(Paragraph(inline(stripped), styles["Bodyx"]))
        i += 1
    doc.build(story)


if __name__ == "__main__":
    create_pdf()
