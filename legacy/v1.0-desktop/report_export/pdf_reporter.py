from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib import colors
from datetime import datetime

def export_scan_to_pdf(scan_data, output_path="scan_report.pdf"):
    """
    Generates a PDF report from scan results.

    Parameters:
    - scan_data (dict): {
        'target': '192.168.1.1',
        'scan_type': 'TCP',
        'start_time': '2025-07-17 22:34:00',
        'open_ports': [22, 80, 443],
        'duration': '5.21s',
    }
    - output_path (str): path to save the PDF file
    """
    c = canvas.Canvas(output_path, pagesize=A4)
    width, height = A4

    c.setFont("Helvetica-Bold", 18)
    c.drawString(50, height - 50, "ShadowPortX Scan Report")

    c.setFont("Helvetica", 12)
    y = height - 100

    for key, value in scan_data.items():
        label = key.replace("_", " ").capitalize()
        val = ", ".join(map(str, value)) if isinstance(value, list) else str(value)
        c.drawString(50, y, f"{label}: {val}")
        y -= 20

    # Footer
    c.setStrokeColor(colors.grey)
    c.setLineWidth(0.3)
    c.line(50, 50, width - 50, 50)
    c.setFont("Helvetica-Oblique", 8)
    c.drawRightString(width - 50, 35, f"Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    c.save()
    print(f"[+] PDF report saved to: {output_path}")
