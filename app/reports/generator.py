from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table,
    TableStyle, HRFlowable
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from datetime import datetime, timedelta
import io
IST = timedelta(hours=5, minutes=30)

# -------------------------
# Color Palette
# -------------------------
DARK       = colors.HexColor('#1a1a2e')
BLUE       = colors.HexColor('#1a56db')
GREEN      = colors.HexColor('#057a55')
RED        = colors.HexColor('#c81e1e')
YELLOW     = colors.HexColor('#92400e')
MUTED      = colors.HexColor('#6b7280')
LIGHT_BG   = colors.HexColor('#f9fafb')
BORDER     = colors.HexColor('#e5e7eb')
TABLE_HEADER = colors.HexColor('#1e3a5f')
WHITE      = colors.white
BLACK      = colors.HexColor('#111827')
ORANGE     = colors.HexColor('#b45309')
EXPLOIT_BG = colors.HexColor('#fff5f5')   # light red tint for exploit rows
EXPLOIT_BORDER = colors.HexColor('#c81e1e')


def risk_color(label):
    if 'Critical' in label: return RED
    elif 'High'   in label: return RED
    elif 'Medium' in label: return colors.HexColor('#b45309')
    else:                   return GREEN


def severity_color(severity):
    s = (severity or '').upper()
    if s == 'CRITICAL': return RED
    elif s == 'HIGH':   return ORANGE
    elif s == 'MEDIUM': return BLUE
    elif s == 'LOW':    return GREEN
    return MUTED


def get_styles():
    styles = getSampleStyleSheet()

    styles.add(ParagraphStyle(
        name='VTitle', fontSize=32, textColor=BLUE,
        alignment=TA_CENTER, fontName='Helvetica-Bold',
        spaceAfter=4, spaceBefore=0
    ))
    styles.add(ParagraphStyle(
        name='VSubtitle', fontSize=13, textColor=MUTED,
        alignment=TA_CENTER, fontName='Helvetica', spaceAfter=8
    ))
    styles.add(ParagraphStyle(
        name='VHeading', fontSize=13, textColor=TABLE_HEADER,
        fontName='Helvetica-Bold', spaceBefore=14, spaceAfter=4
    ))
    styles.add(ParagraphStyle(
        name='VBody', fontSize=10, textColor=BLACK,
        fontName='Helvetica', spaceAfter=4, leading=15
    ))
    styles.add(ParagraphStyle(
        name='VMuted', fontSize=9, textColor=MUTED,
        fontName='Helvetica', spaceAfter=4, leading=13
    ))
    styles.add(ParagraphStyle(
        name='VCenter', fontSize=10, textColor=BLACK,
        fontName='Helvetica', alignment=TA_CENTER
    ))
    styles.add(ParagraphStyle(
        name='VSmall', fontSize=8, textColor=MUTED,
        fontName='Helvetica', alignment=TA_CENTER, leading=12
    ))
    styles.add(ParagraphStyle(
        name='VGreen', fontSize=10, textColor=GREEN,
        fontName='Helvetica', spaceAfter=3, leftIndent=15
    ))
    styles.add(ParagraphStyle(
        name='VRed', fontSize=10, textColor=RED,
        fontName='Helvetica', spaceAfter=3, leftIndent=15
    ))
    styles.add(ParagraphStyle(
        name='VImpact', fontSize=8, textColor=MUTED,
        fontName='Helvetica', spaceAfter=6, leftIndent=25
    ))
    # NEW — for exploit section
    styles.add(ParagraphStyle(
        name='VExploit', fontSize=9, textColor=RED,
        fontName='Helvetica-Bold', spaceAfter=3, leftIndent=0
    ))
    styles.add(ParagraphStyle(
        name='VExploitNote', fontSize=8, textColor=MUTED,
        fontName='Helvetica', spaceAfter=2, leftIndent=12, leading=12
    ))

    return styles


def divider(story):
    story.append(Spacer(1, 0.2 * cm))
    story.append(HRFlowable(width='100%', thickness=1, color=BORDER, spaceAfter=4))


def generate_report(scan_data, username='User'):
    buffer = io.BytesIO()

    doc = SimpleDocTemplate(
        buffer, pagesize=A4,
        rightMargin=2*cm, leftMargin=2*cm,
        topMargin=2*cm,   bottomMargin=2*cm,
        title='VulnWatch Report', author='VulnWatch'
    )

    styles = get_styles()
    story  = []

    domain     = scan_data.get('domain', 'Unknown')
    scanned_at = scan_data.get('scanned_at', datetime.utcnow())
    headers    = scan_data.get('headers')    or {}
    tech_stack = scan_data.get('tech_stack') or {}
    subdomains = scan_data.get('subdomains') or {}
    cves       = scan_data.get('cves')       or {}
    risk_score = scan_data.get('risk_score') or {}

    if isinstance(scanned_at, datetime):
        scan_date = (scanned_at + IST).strftime('%Y-%m-%d %H:%M IST')
    elif isinstance(scanned_at, str):
        try:
            scan_date = (datetime.fromisoformat(scanned_at) + IST).strftime('%Y-%m-%d %H:%M IST')
        except Exception:
            scan_date = scanned_at
    else:
        scan_date = str(scanned_at)

    score          = risk_score.get('score', 0)
    label          = risk_score.get('label', 'Unknown')
    r_color        = risk_color(label)
    missing_headers = headers.get('missing_headers', [])
    verified_cves  = cves.get('high_confidence', 0)
    all_cves       = cves.get('cves', [])
    verified       = [c for c in all_cves if c.get('confidence') == 'high']
    possible       = [c for c in all_cves if c.get('confidence') in ['medium', 'low']]
    exploitable    = [c for c in all_cves if c.get('exploit_available')]
    subs           = subdomains.get('subdomains', [])
    total_subs     = subdomains.get('total_found', 0)
    techs          = tech_stack.get('technologies', [])

    SENSITIVE_KEYWORDS = [
        'admin','api','dev','staging','test','vpn','login','secure',
        'internal','portal','remote','cpanel','webmail','mail',
        'autodiscover','erp'
    ]
    HEADER_IMPACTS = {
        'Content-Security-Policy':   'No CSP - Increased XSS risk',
        'Strict-Transport-Security': 'No HSTS - HTTPS downgrade attack possible',
        'X-Frame-Options':           'No X-Frame-Options - Clickjacking risk',
        'X-Content-Type-Options':    'No X-Content-Type-Options - MIME sniffing possible',
        'Referrer-Policy':           'No Referrer-Policy - Sensitive URL data may leak',
        'Permissions-Policy':        'No Permissions-Policy - Browser features uncontrolled',
    }
    HEADER_RECS = {
        'Strict-Transport-Security': 'Enable HSTS to prevent HTTPS downgrade attacks.',
        'Content-Security-Policy':   'Implement CSP to reduce XSS attack surface.',
        'X-Frame-Options':           'Add X-Frame-Options to prevent clickjacking.',
        'X-Content-Type-Options':    'Set X-Content-Type-Options to prevent MIME sniffing.',
        'Referrer-Policy':           'Configure Referrer-Policy to protect sensitive URL data.',
        'Permissions-Policy':        'Set Permissions-Policy to restrict browser feature access.',
    }
    HIGH_RISK_TECHS   = ['WordPress','Joomla','Drupal','PHP','jQuery']
    MEDIUM_RISK_TECHS = ['Apache','Nginx','MySQL','MongoDB','Laravel']

    # =========================================================
    # COVER
    # =========================================================
    story.append(Paragraph('VulnWatch', styles['VTitle']))
    story.append(Spacer(1, 0.5*cm))
    story.append(Paragraph('Security Vulnerability Report', styles['VSubtitle']))
    story.append(Spacer(1, 0.3*cm))
    story.append(HRFlowable(width='100%', thickness=2, color=BLUE, spaceAfter=12))

    meta_table = Table([
        ['Target Domain', domain],
        ['Scan Date',     scan_date],
        ['Generated For', username],
        ['Scan Type',     'Full Scan (Headers + Tech Stack + Subdomains + CVE Matching)'],
        ['Report Tool',   'VulnWatch v1.0'],
    ], colWidths=[4.5*cm, 12*cm])
    meta_table.setStyle(TableStyle([
        ('FONTNAME',   (0,0), (0,-1), 'Helvetica-Bold'),
        ('FONTNAME',   (1,0), (1,-1), 'Helvetica'),
        ('FONTSIZE',   (0,0), (-1,-1), 10),
        ('TEXTCOLOR',  (0,0), (0,-1), TABLE_HEADER),
        ('TEXTCOLOR',  (1,0), (1,-1), BLACK),
        ('BACKGROUND', (0,0), (-1,-1), LIGHT_BG),
        ('ROWBACKGROUND', (0,1), (-1,-1), WHITE),
        ('GRID',       (0,0), (-1,-1), 0.5, BORDER),
        ('TOPPADDING', (0,0), (-1,-1), 7),
        ('BOTTOMPADDING', (0,0), (-1,-1), 7),
        ('LEFTPADDING', (0,0), (-1,-1), 10),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 0.6*cm))

    risk_table = Table([[
        Paragraph(f'<font size="18" color="{r_color.hexval()}"><b>{score}/100</b></font>', styles['VCenter']),
        Paragraph(f'<font size="16" color="{r_color.hexval()}"><b>{label}</b></font>',     styles['VCenter']),
        Paragraph(f'<font size="11">Header Grade: <b>{headers.get("header_grade","N/A")}</b></font>', styles['VCenter']),
    ]], colWidths=[5.5*cm, 6*cm, 5*cm])
    risk_table.setStyle(TableStyle([
        ('ALIGN',     (0,0), (-1,-1), 'CENTER'),
        ('VALIGN',    (0,0), (-1,-1), 'MIDDLE'),
        ('BACKGROUND',(0,0), (-1,-1), LIGHT_BG),
        ('BOX',       (0,0), (-1,-1), 2, r_color),
        ('INNERGRID', (0,0), (-1,-1), 0.5, BORDER),
        ('TOPPADDING',(0,0), (-1,-1), 18),
        ('BOTTOMPADDING', (0,0), (-1,-1), 18),
    ]))
    story.append(risk_table)
    story.append(Spacer(1, 0.4*cm))
    story.append(Paragraph(
        'This report is generated automatically by VulnWatch and should be used as a security overview, '
        'not a substitute for a full penetration test.',
        styles['VSmall']
    ))

    # =========================================================
    # EXECUTIVE SUMMARY
    # =========================================================
    story.append(Paragraph('Executive Summary', styles['VHeading']))
    divider(story)

    https_status  = "HTTPS is properly configured" if headers.get('https') else "HTTPS is NOT enabled"
    missing_count = len(missing_headers)
    header_note   = (
        "All security headers are properly configured." if missing_count == 0 else
        f"Missing {missing_count} security header(s) may expose users to injection and downgrade attacks." if missing_count <= 2 else
        f"{missing_count} security headers are missing, significantly increasing web attack exposure."
    )
    cve_note = (
        f"{verified_cves} verified vulnerabilit{'y' if verified_cves==1 else 'ies'} found."
        if verified_cves > 0 else
        "No verified vulnerabilities matched to detected technology versions."
    )
    exploit_note = (
        f" {len(exploitable)} CVE(s) have publicly available exploit code. "
        f"However, vulnerability may not be fully verified — confirm applicability before remediation."
        if exploitable else ""
    )

    story.append(Paragraph(
        f"This domain presents a <b>{label}</b> security risk ({score}/100). "
        f"{https_status}. {header_note} {cve_note}{exploit_note} "
        f"{total_subs} subdomains were discovered, expanding the potential attack surface.",
        styles['VBody']
    ))
    story.append(Spacer(1, 0.3*cm))

    summary_stats = Table([
        ['Metric',          'Value',                               'Status'],
        ['Risk Score',      f'{score}/100',                        label],
        ['Header Grade',    headers.get('header_grade','N/A'),     f"{headers.get('header_score',0)}%"],
        ['HTTPS',           'Enabled' if headers.get('https') else 'Disabled', 'Good' if headers.get('https') else 'Risk'],
        ['HTTPS Redirect',  'Yes' if headers.get('https_redirect') else 'No',  'Good' if headers.get('https_redirect') else 'Check'],
        ['SSL Issue',       'Detected' if headers.get('ssl_issue') else 'None','Risk' if headers.get('ssl_issue') else 'Good'],
        ['Verified CVEs',   str(verified_cves),                    'Risk' if verified_cves > 0 else 'Good'],
        ['Exploitable CVEs',str(len(exploitable)),                 'Critical' if exploitable else 'Good'],
        ['Technologies',    str(len(techs)),                       'Info'],
        ['Subdomains',      str(total_subs),                       'Info'],
        ['Missing Headers', str(missing_count),                    'Risk' if missing_count > 0 else 'Good'],
    ], colWidths=[6*cm, 5*cm, 5.5*cm])
    summary_stats.setStyle(TableStyle([
        ('BACKGROUND',    (0,0), (-1,0), TABLE_HEADER),
        ('TEXTCOLOR',     (0,0), (-1,0), WHITE),
        ('FONTNAME',      (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTNAME',      (0,1), (-1,-1), 'Helvetica'),
        ('FONTSIZE',      (0,0), (-1,-1), 9),
        ('TEXTCOLOR',     (0,1), (-1,-1), BLACK),
        ('GRID',          (0,0), (-1,-1), 0.5, BORDER),
        ('ROWBACKGROUND', (0,1), (-1,-1), WHITE),
        ('ROWBACKGROUND', (0,2), (-1,2),  LIGHT_BG),
        ('ROWBACKGROUND', (0,4), (-1,4),  LIGHT_BG),
        ('ROWBACKGROUND', (0,6), (-1,6),  LIGHT_BG),
        ('ROWBACKGROUND', (0,8), (-1,8),  LIGHT_BG),
        ('ROWBACKGROUND', (0,10),(-1,10), LIGHT_BG),
        # Highlight exploitable row if any
        ('TEXTCOLOR',     (2,7), (2,7),   RED if exploitable else GREEN),
        ('TOPPADDING',    (0,0), (-1,-1), 6),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ('LEFTPADDING',   (0,0), (-1,-1), 10),
    ]))
    story.append(summary_stats)

    # =========================================================
    # SECURITY HEADERS
    # =========================================================
    story.append(Paragraph('Security Headers Analysis', styles['VHeading']))
    divider(story)

    story.append(Paragraph(
        f'Grade: <b>{headers.get("header_grade","N/A")}</b> — Score: <b>{headers.get("header_score",0)}%</b>',
        styles['VBody']
    ))
    story.append(Paragraph(
        'Grade Interpretation: A (90-100) Strong  |  B (70-89) Good  |  C (50-69) Needs Improvement  |  D/F (below 50) Poor',
        styles['VMuted']
    ))
    story.append(Spacer(1, 0.2*cm))

    present = headers.get('security_headers', {})
    if present:
        story.append(Paragraph('<b>Present Headers</b>', styles['VBody']))
        for h in present:
            story.append(Paragraph(f'  ✓  {h}', styles['VGreen']))

    if missing_headers:
        story.append(Spacer(1, 0.2*cm))
        story.append(Paragraph('<b>Missing Headers</b>', styles['VBody']))
        for h in missing_headers:
            story.append(Paragraph(f'  ✗  {h}', styles['VRed']))
            impact = HEADER_IMPACTS.get(h, '')
            if impact:
                story.append(Paragraph(f'      {impact}', styles['VImpact']))

    # =========================================================
    # TECH STACK
    # =========================================================
    story.append(Paragraph('Technology Stack', styles['VHeading']))
    divider(story)

    if techs:
        tech_rows = [['Technology', 'Version', 'Category', 'Risk Note']]
        for tech in techs:
            name     = tech.get('name', '')
            version  = tech.get('version') or 'Not detected'
            category = tech.get('category', 'unknown')
            risk_note = ('Common attack target' if name in HIGH_RISK_TECHS
                         else 'Monitor' if name in MEDIUM_RISK_TECHS else '-')
            tech_rows.append([name, version, category, risk_note])

        tech_table = Table(tech_rows, colWidths=[4.5*cm, 3.5*cm, 5*cm, 3.5*cm])
        tech_table.setStyle(TableStyle([
            ('BACKGROUND',    (0,0), (-1,0), TABLE_HEADER),
            ('TEXTCOLOR',     (0,0), (-1,0), WHITE),
            ('FONTNAME',      (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTNAME',      (0,1), (-1,-1), 'Helvetica'),
            ('FONTSIZE',      (0,0), (-1,-1), 9),
            ('TEXTCOLOR',     (0,1), (-1,-1), BLACK),
            ('GRID',          (0,0), (-1,-1), 0.5, BORDER),
            ('ROWBACKGROUND', (0,1), (-1,-1), WHITE),
            ('ROWBACKGROUND', (0,2), (-1,2),  LIGHT_BG),
            ('ROWBACKGROUND', (0,4), (-1,4),  LIGHT_BG),
            ('ROWBACKGROUND', (0,6), (-1,6),  LIGHT_BG),
            ('TOPPADDING',    (0,0), (-1,-1), 6),
            ('BOTTOMPADDING', (0,0), (-1,-1), 6),
            ('LEFTPADDING',   (0,0), (-1,-1), 8),
        ]))
        story.append(tech_table)
    else:
        story.append(Paragraph('No technologies detected.', styles['VMuted']))

    # =========================================================
    # VULNERABILITIES
    # =========================================================
    story.append(Paragraph('Vulnerability Assessment', styles['VHeading']))
    divider(story)

    story.append(Paragraph(
        'Verified CVEs are version-matched via CPE and are high confidence. '
        'Possible CVEs are keyword-based matches and may include false positives due to unknown versions.',
        styles['VMuted']
    ))
    story.append(Spacer(1, 0.2*cm))

    counts_table = Table([
        ['Critical', 'High', 'Medium', 'Low', 'Verified', 'Possible'],
        [
            str(cves.get('critical', 0)),
            str(cves.get('high',     0)),
            str(cves.get('medium',   0)),
            str(cves.get('low',      0)),
            str(len(verified)),
            str(len(possible)),
        ]
    ], colWidths=[2.7*cm]*6)
    counts_table.setStyle(TableStyle([
        ('ALIGN',       (0,0), (-1,-1), 'CENTER'),
        ('FONTNAME',    (0,0), (-1,0),  'Helvetica-Bold'),
        ('FONTSIZE',    (0,0), (-1,0),  9),
        ('FONTSIZE',    (0,1), (-1,1),  14),
        ('FONTNAME',    (0,1), (-1,1),  'Helvetica-Bold'),
        ('TEXTCOLOR',   (0,0), (0,-1),  RED),
        ('TEXTCOLOR',   (1,0), (1,-1),  ORANGE),
        ('TEXTCOLOR',   (2,0), (2,-1),  BLUE),
        ('TEXTCOLOR',   (3,0), (3,-1),  GREEN),
        ('TEXTCOLOR',   (4,0), (4,-1),  GREEN),
        ('TEXTCOLOR',   (5,0), (5,-1),  MUTED),
        ('GRID',        (0,0), (-1,-1), 0.5, BORDER),
        ('BACKGROUND',  (0,0), (-1,-1), LIGHT_BG),
        ('TOPPADDING',  (0,0), (-1,-1), 8),
        ('BOTTOMPADDING',(0,0),(-1,-1), 8),
    ]))
    story.append(counts_table)
    story.append(Spacer(1, 0.3*cm))

    # Verified CVEs table
    if verified:
        story.append(Paragraph('<b>Verified CVEs</b>', styles['VBody']))
        cve_rows = [['CVE ID', 'Technology', 'Score', 'Severity', 'KEV', 'Exploit']]
        for cve in verified:
            has_exploit = bool(cve.get('exploit_available'))
            cve_rows.append([
                cve.get('id', ''),
                cve.get('technology', ''),
                str(cve.get('score', 'N/A')),
                cve.get('severity', 'UNKNOWN'),
                'Yes' if cve.get('kev') else 'No',
                'Yes' if has_exploit else '-',
            ])

        cve_table = Table(cve_rows, colWidths=[4*cm, 3.5*cm, 1.8*cm, 3*cm, 1.8*cm, 2.4*cm])
        style_cmds = [
            ('BACKGROUND',    (0,0), (-1,0), TABLE_HEADER),
            ('TEXTCOLOR',     (0,0), (-1,0), WHITE),
            ('FONTNAME',      (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTNAME',      (0,1), (-1,-1), 'Helvetica'),
            ('FONTSIZE',      (0,0), (-1,-1), 8),
            ('TEXTCOLOR',     (0,1), (-1,-1), BLACK),
            ('GRID',          (0,0), (-1,-1), 0.5, BORDER),
            ('ROWBACKGROUND', (0,1), (-1,-1), WHITE),
            ('ROWBACKGROUND', (0,2), (-1,2),  LIGHT_BG),
            ('TOPPADDING',    (0,0), (-1,-1), 5),
            ('BOTTOMPADDING', (0,0), (-1,-1), 5),
            ('LEFTPADDING',   (0,0), (-1,-1), 6),
        ]
        # Highlight rows with exploits in red tint
        for i, cve in enumerate(verified, start=1):
            if cve.get('exploit_available'):
                style_cmds.append(('BACKGROUND', (0,i), (-1,i), EXPLOIT_BG))
                style_cmds.append(('TEXTCOLOR',  (5,i), (5,i),  RED))
                style_cmds.append(('FONTNAME',   (5,i), (5,i),  'Helvetica-Bold'))

        cve_table.setStyle(TableStyle(style_cmds))
        story.append(cve_table)
        story.append(Spacer(1, 0.3*cm))
    else:
        story.append(Paragraph('No verified CVEs found for detected technology versions.', styles['VMuted']))
        story.append(Spacer(1, 0.2*cm))

    # ── EXPLOIT SECTION (NEW) ─────────────────────────────────────────
    if exploitable:
        story.append(Spacer(1, 0.2*cm))
        story.append(HRFlowable(width='100%', thickness=1.5, color=RED, spaceAfter=6))
        story.append(Paragraph(
            f'Public Exploits Detected — {len(exploitable)} CVE(s) Have Known Exploit Code',
            ParagraphStyle(
                'ExploitHeading', parent=styles['VBody'],
                textColor=RED, fontName='Helvetica-Bold',
                fontSize=11, spaceAfter=4
            )
        ))
        story.append(Paragraph(
            'The following CVEs have publicly available exploit code on Exploit-DB. '
            'Exploit code is publicly available. Vulnerability should be confirmed before prioritizing remediation.',
            styles['VMuted']
        ))
        story.append(Spacer(1, 0.2*cm))

        exp_rows = [['CVE ID', 'Type', 'Technology', 'Severity', 'Score', 'Exploit Title']]
        for cve in exploitable:
            conf     = cve.get('confidence', 'low')
            conf_label = 'Verified' if conf == 'high' else 'Possible (Unconfirmed)'
            urls     = cve.get('exploit_urls', [])
            title    = urls[0].get('title', '-') if urls else '-'
            
            if len(title) > 55:
                title = title[:52] + '...'
            exp_rows.append([
                cve.get('id', ''),
                conf_label,
                cve.get('technology', ''),
                cve.get('severity', 'UNKNOWN'),
                str(cve.get('score', 'N/A')),
                title,
            ])

        exp_table = Table(exp_rows, colWidths=[3.5*cm, 1.8*cm, 2.8*cm, 2*cm, 1.4*cm, 5*cm])
        exp_style = [
            ('BACKGROUND',    (0,0), (-1,0),  RED),
            ('TEXTCOLOR',     (0,0), (-1,0),  WHITE),
            ('FONTNAME',      (0,0), (-1,0),  'Helvetica-Bold'),
            ('FONTNAME',      (0,1), (-1,-1), 'Helvetica'),
            ('FONTSIZE',      (0,0), (-1,-1), 8),
            ('TEXTCOLOR',     (0,1), (-1,-1), BLACK),
            ('GRID',          (0,0), (-1,-1), 0.5, EXPLOIT_BORDER),
            ('ROWBACKGROUND', (0,1), (-1,-1), EXPLOIT_BG),
            ('TOPPADDING',    (0,0), (-1,-1), 5),
            ('BOTTOMPADDING', (0,0), (-1,-1), 5),
            ('LEFTPADDING',   (0,0), (-1,-1), 6),
        ]
        # Alternate row shading
        for i in range(1, len(exp_rows)):
            if i % 2 == 0:
                exp_style.append(('BACKGROUND', (0,i), (-1,i), WHITE))

        exp_table.setStyle(TableStyle(exp_style))
        story.append(exp_table)

        # Exploit-DB URLs listed below the table
        story.append(Spacer(1, 0.2*cm))
        story.append(Paragraph('<b>Exploit-DB References</b>', styles['VBody']))
        for cve in exploitable:
            urls = cve.get('exploit_urls', [])
            for url_entry in urls:
                story.append(Paragraph(
                    f"  {cve.get('id')}  —  {url_entry.get('url', '')}",
                    styles['VExploitNote']
                ))

        story.append(HRFlowable(width='100%', thickness=1, color=BORDER, spaceAfter=4))
        story.append(Spacer(1, 0.2*cm))
    # ── END EXPLOIT SECTION ───────────────────────────────────────────

    if possible:
        story.append(Paragraph(
            f'<b>Top 10 Possible CVEs</b> (out of {len(possible)} keyword-matched, version not confirmed)',
            styles['VBody']
        ))
        pos_rows = [['CVE ID', 'Technology', 'Score', 'Severity']]
        for cve in possible[:10]:
            pos_rows.append([
                cve.get('id', ''),
                cve.get('technology', ''),
                str(cve.get('score', 'N/A')),
                cve.get('severity', 'UNKNOWN'),
            ])
        pos_table = Table(pos_rows, colWidths=[4.5*cm, 5.5*cm, 2.5*cm, 4*cm])
        pos_table.setStyle(TableStyle([
            ('BACKGROUND',    (0,0), (-1,0), colors.HexColor('#374151')),
            ('TEXTCOLOR',     (0,0), (-1,0), WHITE),
            ('FONTNAME',      (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTNAME',      (0,1), (-1,-1), 'Helvetica'),
            ('FONTSIZE',      (0,0), (-1,-1), 8),
            ('TEXTCOLOR',     (0,1), (-1,-1), MUTED),
            ('GRID',          (0,0), (-1,-1), 0.5, BORDER),
            ('ROWBACKGROUND', (0,1), (-1,-1), WHITE),
            ('ROWBACKGROUND', (0,2), (-1,2),  LIGHT_BG),
            ('TOPPADDING',    (0,0), (-1,-1), 5),
            ('BOTTOMPADDING', (0,0), (-1,-1), 5),
            ('LEFTPADDING',   (0,0), (-1,-1), 6),
        ]))
        story.append(pos_table)

    # =========================================================
    # SUBDOMAINS
    # =========================================================
    story.append(Paragraph('Subdomain Discovery', styles['VHeading']))
    divider(story)

    story.append(Paragraph(
        f'Total subdomains discovered: <b>{total_subs}</b>. '
        'Public-facing subdomains may increase attack surface if not properly secured.',
        styles['VBody']
    ))
    story.append(Spacer(1, 0.2*cm))

    if subs:
        sub_rows = [['Subdomain', 'Risk Flag']]
        for sub in subs:
            prefix       = sub.split('.')[0]
            is_sensitive = any(k in prefix for k in SENSITIVE_KEYWORDS)
            sub_rows.append([sub, 'Sensitive' if is_sensitive else '-'])

        sub_table = Table(sub_rows, colWidths=[13.5*cm, 3*cm])
        sub_table.setStyle(TableStyle([
            ('BACKGROUND',    (0,0), (-1,0), TABLE_HEADER),
            ('TEXTCOLOR',     (0,0), (-1,0), WHITE),
            ('FONTNAME',      (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTNAME',      (0,1), (-1,-1), 'Helvetica'),
            ('FONTSIZE',      (0,0), (-1,-1), 8),
            ('TEXTCOLOR',     (0,1), (0,-1),  BLACK),
            ('GRID',          (0,0), (-1,-1), 0.5, BORDER),
            ('ROWBACKGROUND', (0,1), (-1,-1), WHITE),
            ('TOPPADDING',    (0,0), (-1,-1), 4),
            ('BOTTOMPADDING', (0,0), (-1,-1), 4),
            ('LEFTPADDING',   (0,0), (-1,-1), 8),
        ]))
        for i, sub in enumerate(subs, start=1):
            prefix = sub.split('.')[0]
            if any(k in prefix for k in SENSITIVE_KEYWORDS):
                sub_table.setStyle(TableStyle([
                    ('TEXTCOLOR',  (1,i), (1,i), RED),
                    ('BACKGROUND', (0,i), (-1,i), colors.HexColor('#fff5f5')),
                ]))
        story.append(sub_table)

    # =========================================================
    # RECOMMENDATIONS
    # =========================================================
    story.append(Paragraph('Recommendations', styles['VHeading']))
    divider(story)

    high_priority   = []
    medium_priority = []
    general = [
        'Keep all dependencies and frameworks updated regularly.',
        'Monitor server and application logs for unusual activity.',
        'Conduct periodic security audits and penetration tests.',
        'Implement a Web Application Firewall (WAF).',
    ]

    # Exploit-specific recommendations go first
    if exploitable:
        high_priority.append(
            f'Review {len(exploitable)} CVE(s) with public exploit code - '
            f'Confirm version applicability before prioritizing remediation.'
        )

    for h in missing_headers:
        if h in HEADER_RECS:
            high_priority.append(HEADER_RECS[h])

    if verified_cves > 0:
        high_priority.append(f'Patch or update technologies with {verified_cves} verified CVE(s).')

    if not headers.get('https'):
        high_priority.insert(0, 'Enable HTTPS immediately — traffic is currently unencrypted.')
    elif not headers.get('https_redirect'):
        medium_priority.append('Enable HTTP to HTTPS redirect to ensure all traffic is encrypted.')

    sensitive_subs = [s for s in subs if any(k in s.split('.')[0] for k in SENSITIVE_KEYWORDS)]
    if sensitive_subs:
        medium_priority.append(
            f'Restrict or review access to {len(sensitive_subs)} sensitive subdomain(s) '
            f'(e.g. {", ".join(sensitive_subs[:3])}).'
        )

    def rec_table(items, color, label):
        if not items:
            return
        story.append(Paragraph(f'<b>{label}</b>', ParagraphStyle(
            f'Pri_{label}', parent=styles['VBody'],
            textColor=color, spaceAfter=4
        )))
        for item in items:
            story.append(Paragraph(f'  •  {item}', ParagraphStyle(
                f'Rec_{label}', parent=styles['VBody'],
                leftIndent=12, textColor=BLACK, spaceAfter=3
            )))
        story.append(Spacer(1, 0.2*cm))

    rec_table(high_priority,   RED,    'High Priority')
    rec_table(medium_priority, ORANGE, 'Medium Priority')
    rec_table(general,         BLUE,   'General')

    # Footer
    story.append(Spacer(1, 0.8*cm))
    story.append(HRFlowable(width='100%', thickness=0.5, color=BORDER))
    story.append(Spacer(1, 0.2*cm))
    story.append(Paragraph(
        'This report is generated automatically by VulnWatch v1.0. '
        'It should be used as a security overview only and is not a substitute for a full penetration test. '
        'Results may include false positives. Always verify findings before taking action.',
        styles['VSmall']
    ))

    doc.build(story)
    buffer.seek(0)
    return buffer