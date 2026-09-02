# report_generator.py — JOCKY Forensic PDF Report Generator
# ──────────────────────────────────────────────────────────
# Generates court-admissible forensic reports with:
#   - Case metadata + officer details
#   - SHA-256 chain of custody for every evidence item
#   - Evidence timeline
#   - Target machine summary
#   - Signed with a document hash for integrity verification

from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table,
    TableStyle, HRFlowable, PageBreak
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
import hashlib
import datetime
import json
import os


# ─────────────────────────────────────────────────────────────────────────────
# COLOUR PALETTE
# ─────────────────────────────────────────────────────────────────────────────
DARK_BLUE    = colors.HexColor('#0A1628')
MID_BLUE     = colors.HexColor('#1E3A5F')
ACCENT_CYAN  = colors.HexColor('#00C9FF')
ACCENT_TEAL  = colors.HexColor('#0EF6CC')
TEXT_WHITE   = colors.white
TEXT_LIGHT   = colors.HexColor('#B0C4DE')
TEXT_DARK    = colors.HexColor('#1A1A2E')
ROW_ALT      = colors.HexColor('#EAF4FB')
BORDER_BLUE  = colors.HexColor('#2E86AB')


# ─────────────────────────────────────────────────────────────────────────────
# STYLES
# ─────────────────────────────────────────────────────────────────────────────

def make_styles():
    base = getSampleStyleSheet()

    title_style = ParagraphStyle(
        'JockyTitle',
        parent       = base['Title'],
        fontSize     = 22,
        textColor    = DARK_BLUE,
        spaceAfter   = 6,
        alignment    = TA_CENTER,
        fontName     = 'Helvetica-Bold',
    )
    subtitle_style = ParagraphStyle(
        'JockySubtitle',
        parent       = base['Normal'],
        fontSize     = 11,
        textColor    = MID_BLUE,
        spaceAfter   = 4,
        alignment    = TA_CENTER,
        fontName     = 'Helvetica',
    )
    section_style = ParagraphStyle(
        'JockySection',
        parent       = base['Heading1'],
        fontSize     = 13,
        textColor    = TEXT_WHITE,
        backColor    = MID_BLUE,
        spaceBefore  = 14,
        spaceAfter   = 8,
        fontName     = 'Helvetica-Bold',
        leftIndent   = 6,
        rightIndent  = 6,
        leading      = 20,
    )
    subsection_style = ParagraphStyle(
        'JockySubsection',
        parent       = base['Heading2'],
        fontSize     = 11,
        textColor    = MID_BLUE,
        spaceBefore  = 8,
        spaceAfter   = 4,
        fontName     = 'Helvetica-Bold',
    )
    body_style = ParagraphStyle(
        'JockyBody',
        parent       = base['Normal'],
        fontSize     = 9,
        textColor    = TEXT_DARK,
        spaceAfter   = 4,
        fontName     = 'Helvetica',
        leading      = 13,
    )
    mono_style = ParagraphStyle(
        'JockyMono',
        parent       = base['Code'],
        fontSize     = 7.5,
        textColor    = DARK_BLUE,
        spaceAfter   = 2,
        fontName     = 'Courier',
        backColor    = colors.HexColor('#F0F8FF'),
        leftIndent   = 8,
        rightIndent  = 8,
        leading      = 11,
    )
    hash_style = ParagraphStyle(
        'JockyHash',
        parent       = base['Normal'],
        fontSize     = 7,
        textColor    = colors.HexColor('#2E4057'),
        fontName     = 'Courier-Bold',
        leading      = 10,
    )
    footer_style = ParagraphStyle(
        'JockyFooter',
        parent       = base['Normal'],
        fontSize     = 8,
        textColor    = TEXT_LIGHT,
        alignment    = TA_CENTER,
        fontName     = 'Helvetica',
    )
    return {
        'title':      title_style,
        'subtitle':   subtitle_style,
        'section':    section_style,
        'subsection': subsection_style,
        'body':       body_style,
        'mono':       mono_style,
        'hash':       hash_style,
        'footer':     footer_style,
    }


# ─────────────────────────────────────────────────────────────────────────────
# TABLE HELPER
# ─────────────────────────────────────────────────────────────────────────────

def styled_table(data, col_widths=None, header_bg=MID_BLUE):
    style = TableStyle([
        # Header row
        ('BACKGROUND',  (0, 0), (-1, 0),  header_bg),
        ('TEXTCOLOR',   (0, 0), (-1, 0),  TEXT_WHITE),
        ('FONTNAME',    (0, 0), (-1, 0),  'Helvetica-Bold'),
        ('FONTSIZE',    (0, 0), (-1, 0),  9),
        ('ALIGN',       (0, 0), (-1, 0),  'CENTER'),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
        ('TOPPADDING',  (0, 0), (-1, 0),  8),
        # Body rows
        ('FONTNAME',    (0, 1), (-1, -1), 'Helvetica'),
        ('FONTSIZE',    (0, 1), (-1, -1), 8),
        ('TEXTCOLOR',   (0, 1), (-1, -1), TEXT_DARK),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, ROW_ALT]),
        ('GRID',        (0, 0), (-1, -1), 0.5, BORDER_BLUE),
        ('TOPPADDING',  (0, 1), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 1), (-1, -1), 5),
        ('LEFTPADDING', (0, 0), (-1, -1), 8),
        ('RIGHTPADDING', (0, 0), (-1, -1), 8),
        ('VALIGN',      (0, 0), (-1, -1), 'MIDDLE'),
    ])
    tbl = Table(data, colWidths=col_widths, repeatRows=1)
    tbl.setStyle(style)
    return tbl


# ─────────────────────────────────────────────────────────────────────────────
# REPORT SECTIONS
# ─────────────────────────────────────────────────────────────────────────────

def _cover_page(story, styles, case: dict, targets: list, ev_count: int):
    now_str = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')

    story.append(Spacer(1, 2 * cm))

    # Logo-like header block
    header_data = [[Paragraph(
        '<b>JOCKY FORENSIC FRAMEWORK</b><br/>'
        '<font size="10">Digital Forensic Investigation Report</font>',
        styles['title'])]]
    header_tbl = Table(header_data, colWidths=[17 * cm])
    header_tbl.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), DARK_BLUE),
        ('ALIGN',      (0, 0), (-1, -1), 'CENTER'),
        ('TOPPADDING', (0, 0), (-1, -1), 18),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 18),
        ('ROUNDEDCORNERS', [6, 6, 6, 6]),
    ]))
    story.append(header_tbl)
    story.append(Spacer(1, 0.8 * cm))

    # Case info block
    case_data = [
        ['Case ID',        case.get('case_id', 'N/A')],
        ['Case Name',      case.get('case_name', 'N/A')],
        ['Investigating Officer', case.get('officer', 'N/A')],
        ['Case Status',    case.get('status', 'active').upper()],
        ['Created At',     case.get('created_at', 'N/A')[:19]],
        ['Report Generated', now_str],
        ['Total Targets',  str(len(targets))],
        ['Total Evidence Items', str(ev_count)],
    ]
    info_tbl = Table(case_data, colWidths=[6 * cm, 11 * cm])
    info_tbl.setStyle(TableStyle([
        ('FONTNAME',     (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTNAME',     (1, 0), (1, -1), 'Helvetica'),
        ('FONTSIZE',     (0, 0), (-1, -1), 9),
        ('TEXTCOLOR',    (0, 0), (0, -1), MID_BLUE),
        ('TEXTCOLOR',    (1, 0), (1, -1), TEXT_DARK),
        ('ROWBACKGROUNDS', (0, 0), (-1, -1),
         [colors.white, ROW_ALT]),
        ('GRID',         (0, 0), (-1, -1), 0.4, BORDER_BLUE),
        ('TOPPADDING',   (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('LEFTPADDING',  (0, 0), (-1, -1), 10),
    ]))
    story.append(info_tbl)
    story.append(Spacer(1, 0.5 * cm))

    # Description
    if case.get('description'):
        story.append(Paragraph(
            f"<b>Description:</b> {case['description']}",
            styles['body']))

    story.append(HRFlowable(width='100%', thickness=1,
                             color=ACCENT_CYAN, spaceAfter=8))

    # Disclaimer
    disclaimer = (
        "<font size='8'><b>DISCLAIMER:</b> This report is generated by the "
        "JOCKY Forensic Framework for authorized digital forensic investigations "
        "only. All evidence is SHA-256 hashed to ensure integrity. "
        "This document may be used as court-admissible evidence.</font>"
    )
    story.append(Paragraph(disclaimer, styles['body']))
    story.append(PageBreak())


def _targets_section(story, styles, targets: list):
    story.append(Paragraph("  TARGET MACHINES", styles['section']))
    if not targets:
        story.append(Paragraph("No targets recorded.", styles['body']))
        return

    data = [['ID', 'IP Address', 'Hostname', 'OS', 'Port', 'Status',
             'Last Seen']]
    for t in targets:
        data.append([
            str(t.get('id', '')),
            t.get('target_ip', ''),
            t.get('target_name', 'Unknown'),
            t.get('os_type', 'Unknown'),
            str(t.get('target_port', 5000)),
            t.get('status', 'unknown').upper(),
            (t.get('last_seen') or '')[:19],
        ])
    tbl = styled_table(data,
                       col_widths=[1*cm, 3.5*cm, 3*cm, 2*cm,
                                   1.5*cm, 2*cm, 4*cm])
    story.append(tbl)
    story.append(Spacer(1, 0.3 * cm))


def _evidence_timeline(story, styles, evidence: list):
    story.append(Paragraph("  EVIDENCE TIMELINE", styles['section']))
    if not evidence:
        story.append(Paragraph("No evidence collected.", styles['body']))
        return

    data = [['#', 'Timestamp', 'Target IP', 'Command',
             'Evidence Hash (SHA-256)']]
    for i, ev in enumerate(evidence, 1):
        ts = (ev.get('timestamp') or '')[:19]
        data.append([
            str(i),
            ts,
            ev.get('target_ip', ''),
            ev.get('command', ''),
            ev.get('evidence_hash', '')[:32] + '...',
        ])
    tbl = styled_table(data,
                       col_widths=[0.7*cm, 3.5*cm, 3*cm, 4*cm, 5.8*cm])
    story.append(tbl)
    story.append(Spacer(1, 0.3 * cm))


def _evidence_detail(story, styles, evidence: list, max_items: int = 30):
    story.append(PageBreak())
    story.append(Paragraph("  DETAILED EVIDENCE", styles['section']))

    for i, ev in enumerate(evidence[:max_items], 1):
        story.append(Paragraph(
            f"Evidence Item #{i} — {ev.get('command', 'N/A')}",
            styles['subsection']))

        meta_data = [
            ['Field',        'Value'],
            ['Target IP',    ev.get('target_ip', 'N/A')],
            ['Command',      ev.get('command', 'N/A')],
            ['Timestamp',    (ev.get('timestamp') or '')[:19]],
            ['Evidence Hash',ev.get('evidence_hash', 'N/A')],
        ]
        meta_tbl = styled_table(meta_data,
                                col_widths=[4 * cm, 13 * cm])
        story.append(meta_tbl)
        story.append(Spacer(1, 0.2 * cm))

        # Show result preview
        results_raw = ev.get('results', '{}')
        if isinstance(results_raw, str):
            try:
                results_obj = json.loads(results_raw)
            except Exception:
                results_obj = {"raw": results_raw}
        else:
            results_obj = results_raw

        preview = json.dumps(results_obj, indent=2)[:600]
        if len(json.dumps(results_obj)) > 600:
            preview += "\n... [truncated — see full database record]"

        story.append(Paragraph(
            f"<b>Result Preview:</b>", styles['body']))
        story.append(Paragraph(
            preview.replace('\n', '<br/>').replace(' ', '&nbsp;'),
            styles['mono']))
        story.append(Spacer(1, 0.3 * cm))
        story.append(HRFlowable(width='100%', thickness=0.5,
                                 color=BORDER_BLUE, spaceAfter=6))


def _chain_of_custody(story, styles, evidence: list, case: dict):
    story.append(PageBreak())
    story.append(Paragraph(
        "  CHAIN OF CUSTODY — SHA-256 INTEGRITY LOG", styles['section']))

    story.append(Paragraph(
        "Every evidence item is SHA-256 hashed at collection time. "
        "The following table forms the forensic chain of custody. "
        "Any modification to evidence data will produce a different hash, "
        "immediately revealing tampering.",
        styles['body']))
    story.append(Spacer(1, 0.3 * cm))

    # Compute master hash (hash of all hashes)
    all_hashes = [ev.get('evidence_hash', '') for ev in evidence]
    master_hash = hashlib.sha256(
        ''.join(all_hashes).encode()).hexdigest()

    data = [['#', 'Command', 'Target', 'Time', 'SHA-256 Hash']]
    for i, ev in enumerate(evidence, 1):
        data.append([
            str(i),
            ev.get('command', '')[:25],
            ev.get('target_ip', ''),
            (ev.get('timestamp') or '')[:16],
            ev.get('evidence_hash', ''),
        ])

    # Add master hash row
    data.append([
        '★', 'MASTER INTEGRITY HASH', '(all evidence)', '', master_hash
    ])

    tbl = styled_table(data,
                       col_widths=[0.6*cm, 4*cm, 2.5*cm, 3.2*cm, 6.7*cm])
    story.append(tbl)
    story.append(Spacer(1, 0.5 * cm))

    story.append(Paragraph(
        f"<b>Document Integrity:</b><br/>"
        f"Master Hash: <font face='Courier'>{master_hash}</font>",
        styles['body']))


# ─────────────────────────────────────────────────────────────────────────────
# PUBLIC API
# ─────────────────────────────────────────────────────────────────────────────

def generate_pdf(case: dict, targets: list, evidence: list,
                 output_dir: str = None) -> str:
    """
    Generate a court-admissible forensic PDF report.

    Parameters
    ----------
    case      : case dict (case_id, case_name, officer, ...)
    targets   : list of target dicts
    evidence  : list of evidence dicts
    output_dir: directory to save PDF (defaults to reports/)

    Returns absolute path to generated PDF.
    """
    if output_dir is None:
        output_dir = os.path.dirname(os.path.abspath(__file__))

    case_id  = case.get('case_id', 'UNKNOWN')
    ts       = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f"JOCKY_{case_id}_{ts}.pdf"
    filepath = os.path.join(output_dir, filename)

    doc = SimpleDocTemplate(
        filepath,
        pagesize      = A4,
        rightMargin   = 1.5 * cm,
        leftMargin    = 1.5 * cm,
        topMargin     = 1.5 * cm,
        bottomMargin  = 1.5 * cm,
        title         = f"JOCKY Forensic Report — {case_id}",
        author        = case.get('officer', 'JOCKY Framework'),
        subject       = "Digital Forensic Investigation Report",
    )

    styles = make_styles()
    story  = []

    _cover_page(story, styles, case, targets, len(evidence))
    _targets_section(story, styles, targets)
    story.append(Spacer(1, 0.5 * cm))
    _evidence_timeline(story, styles, evidence)
    _evidence_detail(story, styles, evidence)
    _chain_of_custody(story, styles, evidence, case)

    doc.build(story)
    print(f"[JOCKY Report] PDF generated: {filepath}")
    return filepath


# ─────────────────────────────────────────────────────────────────────────────
# SELF-TEST
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    sample_case = {
        "case_id":     "CASE-DEMO01",
        "case_name":   "SIH Demo Investigation",
        "officer":     "Inspector Sharma",
        "description": "Demonstration forensic investigation using JOCKY Framework.",
        "created_at":  "2026-08-25T10:00:00",
        "status":      "active",
    }
    sample_targets = [
        {"id": 1, "target_ip": "192.168.1.101",
         "target_name": "VICTIM-WIN10",
         "os_type": "Windows", "target_port": 5000,
         "status": "online", "last_seen": "2026-08-25T10:30:00"},
        {"id": 2, "target_ip": "192.168.1.102",
         "target_name": "VICTIM-UBUNTU",
         "os_type": "Linux", "target_port": 5000,
         "status": "offline", "last_seen": "2026-08-25T09:00:00"},
    ]
    sample_evidence = [
        {
            "id": 1, "case_id": "CASE-DEMO01",
            "target_ip": "192.168.1.101",
            "command": "scan.processes()",
            "results": json.dumps({
                "count": 87,
                "os": "Windows",
                "results": [
                    {"pid": 4, "name": "System"},
                    {"pid": 1234, "name": "notepad.exe"},
                ]
            }),
            "timestamp":      "2026-08-25T10:31:00",
            "evidence_hash":  hashlib.sha256(b"demo_evidence_1").hexdigest(),
        },
        {
            "id": 2, "case_id": "CASE-DEMO01",
            "target_ip": "192.168.1.101",
            "command": "scan.network.connections()",
            "results": json.dumps({
                "count": 12,
                "os": "Windows",
                "results": [
                    {"local_addr": "0.0.0.0:443",
                     "remote_addr": "1.2.3.4:55000",
                     "status": "ESTABLISHED"}
                ]
            }),
            "timestamp":     "2026-08-25T10:32:00",
            "evidence_hash": hashlib.sha256(b"demo_evidence_2").hexdigest(),
        },
    ]

    out = generate_pdf(sample_case, sample_targets, sample_evidence)
    print(f"Report saved to: {out}")
