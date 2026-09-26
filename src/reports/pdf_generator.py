import os
from io import BytesIO
from datetime import datetime
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable, KeepTogether

def generate_pdf_report(cases):
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        'TitleStyle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=18,
        leading=22,
        textColor=colors.HexColor("#1E293B")
    )
    subtitle_style = ParagraphStyle(
        'SubTitleStyle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#64748B")
    )
    section_style = ParagraphStyle(
        'SectionHeading',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=13,
        leading=16,
        textColor=colors.HexColor("#0F172A"),
        spaceBefore=10,
        spaceAfter=6
    )
    body_style = ParagraphStyle(
        'BodyDark',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8.5,
        leading=11.5,
        textColor=colors.HexColor("#334155")
    )
    table_header_style = ParagraphStyle(
        'TableHeader',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=8.5,
        leading=10.5,
        textColor=colors.white
    )
    table_cell_style = ParagraphStyle(
        'TableCell',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8,
        leading=10,
        textColor=colors.HexColor("#1E293B")
    )

    elements = []

    # Title Banner (clean text without unrenderable emoji glyphs)
    elements.append(Paragraph("SOC Investigation Platform — Security Executive Report", title_style))
    elements.append(Paragraph(f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} UTC | Status: Verified Triage", subtitle_style))
    elements.append(Spacer(1, 8))
    elements.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#2563EB"), spaceAfter=10))

    # Metric Highlights Table
    total_cases = len(cases)
    high_sev = len([c for c in cases if c.get("severity") == "HIGH"])
    critical_sev = len([c for c in cases if c.get("severity") == "CRITICAL"])
    tp = len([c for c in cases if c.get("verdict") == "TRUE_POSITIVE"])

    metric_data = [
        [
            Paragraph(f"<b>Total Cases:</b> {total_cases}", body_style),
            Paragraph(f"<b>High Severity:</b> {high_sev}", body_style),
            Paragraph(f"<b>Critical Severity:</b> {critical_sev}", body_style),
            Paragraph(f"<b>True Positives:</b> {tp}", body_style),
        ]
    ]
    metric_table = Table(metric_data, colWidths=[1.75*inch]*4)
    metric_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#F1F5F9")),
        ('PADDING', (0, 0), (-1, -1), 6),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
    ]))
    elements.append(metric_table)
    elements.append(Spacer(1, 10))

    # Executive Summary Table
    elements.append(Paragraph("Executive Incident Overview", section_style))
    
    summary_headers = ["Case ID", "Account", "Source IP", "Detections", "Score", "Severity", "Verdict", "ServiceNow SysID"]
    summary_rows = [[Paragraph(h, table_header_style) for h in summary_headers]]

    for c in cases:
        sys_id = c.get("servicenow_sys_id") or "N/A"
        if len(sys_id) > 12:
            sys_id = sys_id[:10] + "..."
        row = [
            Paragraph(f"<b>{c.get('case_id')}</b>", table_cell_style),
            Paragraph(str(c.get('account')), table_cell_style),
            Paragraph(str(c.get('source_ip')), table_cell_style),
            Paragraph(", ".join(c.get('detections', [])), table_cell_style),
            Paragraph(str(c.get('risk_score')), table_cell_style),
            Paragraph(f"<b>{c.get('severity')}</b>", table_cell_style),
            Paragraph(str(c.get('verdict')), table_cell_style),
            Paragraph(sys_id, table_cell_style)
        ]
        summary_rows.append(row)

    summary_table = Table(summary_rows, colWidths=[0.7*inch, 0.7*inch, 0.9*inch, 1.8*inch, 0.5*inch, 0.75*inch, 0.85*inch, 1.1*inch])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#1E293B")),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor("#F8FAFC")]),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
        ('PADDING', (0, 0), (-1, -1), 4),
    ]))
    elements.append(summary_table)
    elements.append(Spacer(1, 12))

    # Detailed Case Breakdown
    elements.append(Paragraph("Detailed Incident Investigation Breakdowns", section_style))

    for c in cases:
        case_elements = []
        case_header = f"Case {c.get('case_id')} — Target Account: {c.get('account')} ({c.get('source_ip')})"
        case_elements.append(Paragraph(case_header, ParagraphStyle('CaseHead', parent=section_style, fontSize=11, textColor=colors.HexColor("#1E40AF"))))
        
        detail_text = (
            f"<b>Risk Score:</b> {c.get('risk_score')} &nbsp;&nbsp;|&nbsp;&nbsp; "
            f"<b>Severity:</b> {c.get('severity')} &nbsp;&nbsp;|&nbsp;&nbsp; "
            f"<b>Verdict:</b> {c.get('verdict')}<br/>"
            f"<b>MITRE ATT&CK Techniques:</b> {', '.join(c.get('mitre', []))}<br/>"
            f"<b>ServiceNow SysID:</b> {c.get('servicenow_sys_id') or 'None'}"
        )
        case_elements.append(Paragraph(detail_text, body_style))
        case_elements.append(Spacer(1, 4))

        # Timeline
        timeline = c.get("timeline", [])
        if timeline:
            t_rows = [[Paragraph("<b>Timestamp</b>", table_header_style), Paragraph("<b>Host</b>", table_header_style), Paragraph("<b>Event Description</b>", table_header_style)]]
            for ev in timeline:
                t_rows.append([
                    Paragraph(str(ev.get("time")), table_cell_style),
                    Paragraph(str(ev.get("host")), table_cell_style),
                    Paragraph(str(ev.get("event")), table_cell_style)
                ])
            t_table = Table(t_rows, colWidths=[1.8*inch, 1.0*inch, 4.4*inch])
            t_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#334155")),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                ('PADDING', (0, 0), (-1, -1), 3),
            ]))
            case_elements.append(t_table)
        
        case_elements.append(Spacer(1, 8))
        elements.append(KeepTogether(case_elements))

    doc.build(elements)
    buffer.seek(0)
    return buffer.getvalue()
