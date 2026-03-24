from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from datetime import datetime


def map_to_cis(issue):
    i = issue.lower()

    if "rdp" in i:
        return "CIS Control 12"
    elif "ftp" in i or "telnet" in i:
        return "CIS Control 4"
    elif "http" in i:
        return "CIS Control 3"
    elif "smb" in i:
        return "CIS Control 13"
    elif "password" in i:
        return "CIS Control 5"
    elif "firewall" in i:
        return "CIS Control 12"
    elif "vulnerable" in i:
        return "CIS Control 7"
    else:
        return "CIS Control 1"


def classify_risk(issue):
    u = issue.upper()
    if "CRITICAL" in u:
        return "CRITICAL"
    elif "HIGH" in u:
        return "HIGH"
    elif "MEDIUM" in u:
        return "MEDIUM"
    else:
        return "LOW"


def generate_pdf(targets, scan_data, all_issues, filename):

    doc = SimpleDocTemplate(filename)
    styles = getSampleStyleSheet()
    content = []

    content.append(Paragraph("MULTI-SERVER SECURITY REPORT", styles['Title']))
    content.append(Spacer(1, 10))

    content.append(Paragraph(f"Targets: {len(targets)}", styles['Normal']))
    content.append(Paragraph(f"Date: {datetime.now()}", styles['Normal']))
    content.append(Spacer(1, 10))

    for host in scan_data:

        content.append(Paragraph(f"Target: {host['target']}", styles['Heading2']))
        content.append(Paragraph(f"OS: {host['results']['os']}", styles['Normal']))
        content.append(Paragraph(f"Ports: {host['results']['open_ports']}", styles['Normal']))

        for issue in host["issues"]:
            content.append(Paragraph(f"- {issue}", styles['Normal']))

        content.append(Spacer(1, 10))

    content.append(Paragraph("SUMMARY", styles['Heading2']))
    content.append(Paragraph(f"Total Issues: {len(all_issues)}", styles['Normal']))

    doc.build(content)