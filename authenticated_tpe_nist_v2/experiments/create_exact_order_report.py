#!/usr/bin/env python3
"""Build a new professor-facing Word report; never overwrite prior reports."""
from __future__ import annotations
import csv
from pathlib import Path
from docx import Document
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT, WD_CELL_VERTICAL_ALIGNMENT
from docx.shared import Inches, Pt, RGBColor
from docx.oxml import OxmlElement
from docx.oxml.ns import qn

ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'output'/'metrics'/'flowchart_exact_order_compensated'
METRICS=list(csv.DictReader((OUT/'metrics.csv').open(encoding='utf-8',newline='')))
DOCX=OUT/'professor_32x32_block_effect_gallery_exact_flowchart.docx'
NAVY='1F4E79'; BLUE='5B9BD5'; PALE='D9EAF7'; GRAY='F2F2F2'; WHITE='FFFFFF'


def set_cell_shading(cell, fill):
    tcPr=cell._tc.get_or_add_tcPr()
    shd=OxmlElement('w:shd'); shd.set(qn('w:fill'),fill); tcPr.append(shd)


def set_cell_margins(cell,top=65,start=65,bottom=65,end=65):
    tc=cell._tc; tcPr=tc.get_or_add_tcPr(); mar=OxmlElement('w:tcMar')
    for side,value in [('top',top),('start',start),('bottom',bottom),('end',end)]:
        node=OxmlElement('w:'+side); node.set(qn('w:w'),str(value)); node.set(qn('w:type'),'dxa'); mar.append(node)
    tcPr.append(mar)


def set_repeat_table_header(row):
    trPr=row._tr.get_or_add_trPr(); repeat=OxmlElement('w:tblHeader'); repeat.set(qn('w:val'),'true'); trPr.append(repeat)


def page_field(paragraph):
    paragraph.alignment=WD_ALIGN_PARAGRAPH.CENTER
    r=paragraph.add_run('Page '); r.font.size=Pt(8); r.font.color.rgb=RGBColor(90,90,90)
    fld=OxmlElement('w:fldSimple'); fld.set(qn('w:instr'),'PAGE'); paragraph._p.append(fld)


def setup(doc):
    sec=doc.sections[0]
    sec.top_margin=Inches(.58); sec.bottom_margin=Inches(.58)
    sec.left_margin=Inches(.62); sec.right_margin=Inches(.62)
    normal=doc.styles['Normal']; normal.font.name='Arial'; normal.font.size=Pt(9.5)
    normal.font.color.rgb=RGBColor(35,35,35)
    normal.paragraph_format.space_after=Pt(5)
    normal.paragraph_format.line_spacing=1.08
    for sty,size in [('Title',23),('Heading 1',16),('Heading 2',12),('Heading 3',10.5)]:
        s=doc.styles[sty]; s.font.name='Arial'; s.font.size=Pt(size); s.font.bold=True
        s.font.color.rgb=RGBColor.from_string(NAVY if sty!='Heading 3' else BLUE)
        s.paragraph_format.space_before=Pt(8 if sty!='Title' else 0)
        s.paragraph_format.space_after=Pt(5)
    footer=sec.footer.paragraphs[0]; page_field(footer)


def add_bullet(doc,text):
    p=doc.add_paragraph(style='List Bullet'); p.paragraph_format.space_after=Pt(2); p.add_run(text); return p


def format_table(table,header=True,font_size=8.2):
    table.alignment=WD_TABLE_ALIGNMENT.CENTER
    table.style='Table Grid'
    for ri,row in enumerate(table.rows):
        if ri==0 and header: set_repeat_table_header(row)
        for cell in row.cells:
            cell.vertical_alignment=WD_CELL_VERTICAL_ALIGNMENT.CENTER
            set_cell_margins(cell)
            if ri==0 and header:set_cell_shading(cell,NAVY)
            elif ri%2==0:set_cell_shading(cell,GRAY)
            for p in cell.paragraphs:
                p.paragraph_format.space_after=Pt(0); p.paragraph_format.line_spacing=1.0
                for r in p.runs:
                    r.font.name='Arial';r.font.size=Pt(font_size)
                    if ri==0 and header:r.font.bold=True;r.font.color.rgb=RGBColor.from_string(WHITE)


def add_table(doc,headers,rows,font=8.2):
    table=doc.add_table(rows=1,cols=len(headers))
    for cell,text in zip(table.rows[0].cells,headers):cell.text=str(text)
    for values in rows:
        cells=table.add_row().cells
        for cell,text in zip(cells,values):cell.text=str(text)
    format_table(table,font_size=font)
    return table


def add_gallery_item(doc,row):
    title=doc.add_paragraph(style='Heading 2')
    title.paragraph_format.keep_with_next=True
    title.add_run(row['image'].capitalize()+' — original, b=32 TPE, and authenticated output')
    cap=doc.add_paragraph()
    cap.paragraph_format.space_after=Pt(3);cap.paragraph_format.keep_with_next=True
    cap.add_run(
        f"Full RGB PSNR (original→final): {float(row['final_full_rgb_psnr_db']):.2f} dB | "
        f"32×32 thumbnail PSNR: {float(row['final_32x32_thumbnail_psnr_db']):.2f} dB | "
        f"thumbnail SSIM: {float(row['final_32x32_thumbnail_ssim']):.6f} | "
        f"four-block tags: {row['group_tags']} | min capacity: {row['minimum_group_capacity_bits']} bits | "
        f"exact recovery: {row['exact_recovery']}"
    )
    table=doc.add_table(rows=2,cols=3);table.alignment=WD_TABLE_ALIGNMENT.CENTER
    labels=['Original input','Block TPE before authentication','Final authenticated TPE']
    paths=[OUT/row['original_png'],OUT/row['base_tpe_png'],OUT/row['authenticated_png']]
    for i,(label,path) in enumerate(zip(labels,paths)):
        p=table.cell(0,i).paragraphs[0];p.alignment=WD_ALIGN_PARAGRAPH.CENTER
        r=p.add_run(label);r.bold=True;r.font.size=Pt(8);r.font.color.rgb=RGBColor.from_string(NAVY)
        pic=table.cell(1,i).paragraphs[0];pic.alignment=WD_ALIGN_PARAGRAPH.CENTER
        pic.add_run().add_picture(str(path),width=Inches(2.15))
        table.cell(0,i).vertical_alignment=WD_CELL_VERTICAL_ALIGNMENT.CENTER
        table.cell(1,i).vertical_alignment=WD_CELL_VERTICAL_ALIGNMENT.CENTER
        set_cell_margins(table.cell(0,i),25,20,25,20);set_cell_margins(table.cell(1,i),20,20,20,20)
    table.style='Table Grid'
    doc.add_paragraph().paragraph_format.space_after=Pt(1)


def build():
    doc=Document();setup(doc)
    p=doc.add_paragraph(style='Title');p.alignment=WD_ALIGN_PARAGRAPH.CENTER
    p.add_run('Exact-Order Authenticated 32×32 Block-TPE Results')
    p=doc.add_paragraph();p.alignment=WD_ALIGN_PARAGRAPH.CENTER
    r=p.add_run('Professor flowchart order, localized four-block HMAC tags, and corrected thumbnail-fidelity measurements')
    r.italic=True;r.font.size=Pt(10);r.font.color.rgb=RGBColor.from_string(BLUE)
    p=doc.add_paragraph();p.alignment=WD_ALIGN_PARAGRAPH.CENTER
    p.add_run('Six real color images · 32×32 blocks · 11 October 2026').font.size=Pt(9)

    doc.add_heading('Result at a glance',level=1)
    add_bullet(doc,'All six images followed the flowchart’s processing order: legacy block TPE/RDH → reversible Step-1/Step-2 processing → HMAC_DRBG four-block group selection → per-group HMAC-SHA256 → RCM tag embedding.')
    add_bullet(doc,'All 864 expected per-channel/four-block tags were embedded and verified; every group had at least 1,150 net RCM bits for its 256-bit tag. No whole-image fallback was used.')
    add_bullet(doc,'All six images and embedded RDH payloads recovered exactly. A selected one-pixel tamper was rejected and localized to its selected four-block group.')
    add_bullet(doc,'After reversible block-sum compensation, the final authenticated image preserves each pre-authentication 32×32 per-channel block sum exactly. Final original-to-ciphertext block-thumbnail PSNR is 49.82–54.84 dB.')

    doc.add_heading('Implementation sequence and necessary additions',level=1)
    stages=[
        ('1. Block TPE/RDH','Existing b=32 TPE pipeline creates the encrypted block image and embeds the reversible payload.'),
        ('2. Reversible pair transforms','Authentication Step-1 and Step-2 run on the TPE ciphertext after it is produced.'),
        ('3. HMAC_DRBG grouping','The keyed DRBG determines the four-block membership/order independently for each color channel.'),
        ('4. Group authentication','HMAC-SHA256 is calculated over each post-Step-2 four-block group and its logical pairing map.'),
        ('5. RCM marking','A 256-bit group HMAC is inserted using reversible contrast mapping. Groups are capacity-preflighted; failure is closed, not silently downgraded.'),
        ('6. Reversible fidelity wrapper','A protected sidecar stores the data-dependent within-block pairing map and per-pixel sum-correction vector. The correction restores the pre-auth block sum exactly; verification reverses it before extracting the RCM tags.'),
    ]
    add_table(doc,['Flowchart stage','What this run does'],stages,font=8.4)
    p=doc.add_paragraph()
    p.add_run('Important format limitation: ').bold=True
    p.add_run('The RGB image is not self-contained. A companion ChaCha20-Poly1305-protected sidecar is required; it is about 1.20 MB for 512×512 inputs and 0.29 MB for 256×256 inputs. This is a research prototype, not a compact deployment format.')

    doc.add_page_break()
    doc.add_heading('Measured fidelity, capacity, and recovery',level=1)
    rows=[]
    for r in METRICS:
        rows.append([r['image'].capitalize(),r['group_tags'],r['minimum_group_capacity_bits'],
                     f"{float(r['final_full_rgb_psnr_db']):.2f}",
                     f"{float(r['final_32x32_thumbnail_psnr_db']):.2f}",
                     f"{float(r['final_32x32_thumbnail_ssim']):.6f}",
                     r['max_abs_block_sum_delta_auth_vs_base'],
                     'Yes' if r['authentication_accepted']=='True' and r['exact_recovery']=='True' and r['payload_recovered']=='True' else 'No'])
    add_table(doc,['Image','Group tags','Min. net capacity (bits)','Full RGB PSNR dB','32×32 thumbnail PSNR dB','Thumbnail SSIM','Max block-sum delta','Auth + exact recovery'],rows,font=7.5)
    p=doc.add_paragraph()
    p.add_run('PSNR definitions. ').bold=True
    p.add_run('Full RGB PSNR compares the original full-resolution pixels with the final authenticated ciphertext; low values are expected for an encrypted image. Thumbnail PSNR compares rounded RGB means for every corresponding 32×32 block in the original and final ciphertext—the task-relevant thumbnail metric. The authenticated image’s thumbnail equals its pre-authentication TPE thumbnail because each block sum is exactly restored. All six full-resolution inputs are included; no test image was dropped.')

    doc.add_heading('Before / after the exact-order correction',level=2)
    before_after=[
        ('Ordering','RCM authentication was inserted before the legacy substitution, which was then wrapped around it.','Authentication Step-1/Step-2 and HMAC/RCM run after the complete legacy TPE ciphertext, in flowchart order.'),
        ('Localization','The prior six outputs used one whole-image fallback tag; no four-block localization.','All 864 expected four-block tags pass capacity and verify; one-pixel tamper test localizes to the affected group.'),
        ('Thumbnail PSNR','Prior final range: 36.46–51.47 dB; marking changed block sums.','Final range: 49.82–54.84 dB; final authenticated per-block sums match pre-auth TPE exactly.'),
        ('Recovery','Exact image and payload recovery passed.','Exact image and payload recovery still pass; no whole-image fallback.'),
    ]
    add_table(doc,['Measure','Previous hybrid (preserved, not overwritten)','Exact-order compensated run'],before_after,font=8.0)
    p=doc.add_paragraph()
    p.add_run('Scope note. ').bold=True
    p.add_run('This experiment validates the exact-order image pipeline and its reversibility. It does not re-run NIST STS 2.1.2. Previously reported NIST tests cover the defined cryptographic-component streams; they are not image-fidelity scores, and they are not newly claimed as a validation of this layout/compensation wrapper.')

    for start in range(0,len(METRICS),2):
        doc.add_page_break()
        add_gallery_item(doc,METRICS[start])
        if start+1<len(METRICS):add_gallery_item(doc,METRICS[start+1])
    doc.save(DOCX)
    print(DOCX)

if __name__=='__main__':build()
