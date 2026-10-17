
import os
from io import BytesIO
from datetime import datetime
from urllib.parse import urlparse
from xml.sax.saxutils import escape

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    send_file,
)

from scanner import scan_security_headers

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import (
    getSampleStyleSheet,
    ParagraphStyle,
)
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    HRFlowable,
)


# --------------------------------------------------
# APPLICATION CONFIGURATION
# --------------------------------------------------

app = Flask(__name__)

# Never hard-code a secret key in a public repository.
app.secret_key = os.environ.get("FLASK_SECRET_KEY")

if not app.secret_key:
    raise RuntimeError(
        "FLASK_SECRET_KEY is missing. Set it in your terminal "
        "before starting WebVulnLab."
    )

# Demo storage: scan history resets when Flask restarts.
scan_history = []
latest_scan = None


# --------------------------------------------------
# THEME COLORS
# --------------------------------------------------

BROWN = colors.HexColor("#6F4E37")
DARK_BROWN = colors.HexColor("#493629")
LIGHT_BROWN = colors.HexColor("#E8DDD1")
CREAM = colors.HexColor("#FFFAF5")
MUTED = colors.HexColor("#806B5B")
GREEN = colors.HexColor("#DCEBDD")
RED = colors.HexColor("#F5DFD2")
GREY = colors.HexColor("#E8E1DA")


# --------------------------------------------------
# HELPER FUNCTIONS
# --------------------------------------------------

def valid_target_url(value):
    """Basic URL validation for the student demonstration."""
    try:
        parsed = urlparse(value.strip())

        return (
            parsed.scheme in ("http", "https")
            and bool(parsed.hostname)
            and not parsed.username
            and not parsed.password
        )

    except (ValueError, AttributeError):
        return False


def count_findings(results):
    """Count checks that need review."""
    return sum(
        1
        for item in results
        if item.get("present") is False
    )


def make_paragraph(value, style):
    """Escape text before inserting it into a PDF paragraph."""
    return Paragraph(
        escape(str(value if value is not None else "N/A")),
        style,
    )


# --------------------------------------------------
# DASHBOARD
# --------------------------------------------------

@app.route("/")
def index():
    total_scans = len(scan_history)

    results = (
        latest_scan.get("results", [])
        if latest_scan and latest_scan.get("success")
        else []
    )

    total_findings = count_findings(results)

    risk_score = (
        latest_scan.get("risk_score", 0)
        if latest_scan and latest_scan.get("success")
        else 0
    )

    risk_level = (
        latest_scan.get("risk_level", "Not assessed")
        if latest_scan and latest_scan.get("success")
        else "Not assessed"
    )

    return render_template(
        "index.html",
        latest_scan=latest_scan,
        scan_history=scan_history,
        total_scans=total_scans,
        total_findings=total_findings,
        risk_score=risk_score,
        risk_level=risk_level,
    )


# --------------------------------------------------
# SCANNER
# --------------------------------------------------

@app.route("/scanner", methods=["GET", "POST"])
def scanner_page():
    global latest_scan

    scan_result = None

    if request.method == "POST":
        target_url = request.form.get("url", "").strip()

        if not valid_target_url(target_url):
            scan_result = {
                "success": False,
                "url": target_url,
                "error": (
                    "Enter a valid URL beginning with "
                    "http:// or https://."
                ),
                "results": [],
                "risk_score": 0,
                "risk_level": "Scan failed",
                "recommendations": [],
            }

        else:
            scan_result = scan_security_headers(target_url)

            if scan_result.get("success"):
                latest_scan = scan_result
                scan_history.insert(0, scan_result)

                # Keep the latest 50 successful scans.
                del scan_history[50:]

            else:
                flash(
                    scan_result.get(
                        "error",
                        "The scan could not be completed.",
                    ),
                    "error",
                )

    return render_template(
        "scanner.html",
        scan_result=scan_result,
        latest_scan=latest_scan,
        scan_history=scan_history,
    )


# --------------------------------------------------
# FINDINGS
# --------------------------------------------------

@app.route("/findings")
def findings():
    results = (
        latest_scan.get("results", [])
        if latest_scan and latest_scan.get("success")
        else []
    )

    return render_template(
        "findings.html",
        findings=results,
        results=results,
        latest_scan=latest_scan,
        scan_history=scan_history,
    )


# --------------------------------------------------
# REPORTS PAGE
# --------------------------------------------------

@app.route("/reports")
def reports():
    return render_template(
        "reports.html",
        latest_scan=latest_scan,
        scan_history=scan_history,
        reports=scan_history,
    )


# --------------------------------------------------
# PROFESSIONAL PDF REPORT
# --------------------------------------------------

@app.route("/export-report")
def export_report():
    """Export the latest successful scan as a PDF."""

    if not latest_scan or not latest_scan.get("success"):
        flash(
            "Please complete a successful scan before exporting a report.",
            "error",
        )
        return redirect(url_for("reports"))

    buffer = BytesIO()

    pdf = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=25 * mm,
        bottomMargin=22 * mm,
        title="WebVulnLab Security Assessment Report",
        author="WebVulnLab",
    )

    styles = getSampleStyleSheet()

    styles.add(
        ParagraphStyle(
            name="ReportTitle",
            parent=styles["Title"],
            fontName="Helvetica-Bold",
            fontSize=22,
            leading=27,
            textColor=DARK_BROWN,
            alignment=0,
            spaceAfter=8,
        )
    )

    styles.add(
        ParagraphStyle(
            name="ReportSubtitle",
            parent=styles["Normal"],
            fontSize=10,
            leading=15,
            textColor=MUTED,
            spaceAfter=12,
        )
    )

    styles.add(
        ParagraphStyle(
            name="SectionHeading",
            parent=styles["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=13,
            leading=17,
            textColor=BROWN,
            spaceBefore=13,
            spaceAfter=8,
        )
    )

    styles.add(
        ParagraphStyle(
            name="CellText",
            parent=styles["BodyText"],
            fontSize=8,
            leading=11,
            textColor=DARK_BROWN,
            wordWrap="CJK",
        )
    )

    styles.add(
        ParagraphStyle(
            name="SmallMuted",
            parent=styles["Normal"],
            fontSize=8,
            leading=11,
            textColor=MUTED,
        )
    )

    styles.add(
        ParagraphStyle(
            name="Recommendation",
            parent=styles["BodyText"],
            fontSize=9,
            leading=13,
            leftIndent=10,
            firstLineIndent=-10,
            spaceAfter=6,
            textColor=DARK_BROWN,
        )
    )

    content = []

    target_url = latest_scan.get("url", "N/A")
    generated_at = datetime.now().strftime(
        "%d %B %Y, %I:%M %p"
    )
    risk_score = latest_scan.get("risk_score", 0)
    risk_level = latest_scan.get("risk_level", "Not assessed")
    http_status = latest_scan.get("http_status", "N/A")

    results = latest_scan.get("results", [])
    recommendations = latest_scan.get("recommendations", [])

    passed = sum(
        1 for item in results
        if item.get("present") is True
    )

    needs_review = sum(
        1 for item in results
        if item.get("present") is False
    )

    not_assessed = sum(
        1 for item in results
        if item.get("present") is None
    )

    # Report header
    content.append(
        Paragraph("WebVulnLab", styles["ReportTitle"])
    )

    content.append(
        Paragraph(
            "SECURITY ASSESSMENT REPORT",
            styles["ReportSubtitle"],
        )
    )

    content.append(
        HRFlowable(
            width="100%",
            thickness=2,
            color=BROWN,
            spaceAfter=14,
        )
    )

    # Scan overview
    content.append(
        Paragraph("Scan Overview", styles["SectionHeading"])
    )

    details = [
        [
            make_paragraph("<b>Target URL</b>", styles["CellText"]),
            make_paragraph(target_url, styles["CellText"]),
        ],
        [
            make_paragraph("<b>Generated</b>", styles["CellText"]),
            make_paragraph(generated_at, styles["CellText"]),
        ],
        [
            make_paragraph("<b>HTTP Status</b>", styles["CellText"]),
            make_paragraph(http_status, styles["CellText"]),
        ],
    ]

    details_table = Table(
        details,
        colWidths=[38 * mm, 132 * mm],
    )

    details_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), LIGHT_BROWN),
            ("BACKGROUND", (1, 0), (1, -1), CREAM),
            ("GRID", (0, 0), (-1, -1), 0.5, LIGHT_BROWN),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 9),
            ("RIGHTPADDING", (0, 0), (-1, -1), 9),
            ("TOPPADDING", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ])
    )

    content.append(details_table)
    content.append(Spacer(1, 12))

    # Risk summary
    content.append(
        Paragraph("Risk Summary", styles["SectionHeading"])
    )

    summary_data = [[
        make_paragraph(
            "<b>Risk Score</b><br/>"
            + escape(str(risk_score)) + "/100",
            styles["CellText"],
        ),
        make_paragraph(
            "<b>Risk Level</b><br/>"
            + escape(str(risk_level)),
            styles["CellText"],
        ),
        make_paragraph(
            "<b>Needs Review</b><br/>"
            + str(needs_review),
            styles["CellText"],
        ),
        make_paragraph(
            "<b>Passed</b><br/>" + str(passed),
            styles["CellText"],
        ),
    ]]

    summary_table = Table(
        summary_data,
        colWidths=[42.5 * mm] * 4,
    )

    summary_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), CREAM),
            ("BOX", (0, 0), (-1, -1), 0.8, LIGHT_BROWN),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, LIGHT_BROWN),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ("TOPPADDING", (0, 0), (-1, -1), 12),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
        ])
    )

    content.append(summary_table)
    content.append(
        Paragraph(
            f"Not assessed checks: {not_assessed}",
            styles["SmallMuted"],
        )
    )

    # Detailed findings
    content.append(
        Paragraph(
            "Detailed Security Findings",
            styles["SectionHeading"],
        )
    )

    findings_rows = [[
        make_paragraph("<b>Security Check</b>", styles["CellText"]),
        make_paragraph("<b>Status</b>", styles["CellText"]),
        make_paragraph("<b>Description</b>", styles["CellText"]),
    ]]

    for item in results:
        name = item.get("name", "Unnamed check")
        description = item.get("description", "")

        if item.get("present") is True:
            status = "Passed"
        elif item.get("present") is False:
            status = "Needs review"
        else:
            status = "Not assessed"

        findings_rows.append([
            make_paragraph(name, styles["CellText"]),
            make_paragraph(status, styles["CellText"]),
            make_paragraph(description, styles["CellText"]),
        ])

    if len(findings_rows) == 1:
        findings_rows.append([
            make_paragraph("No findings available", styles["CellText"]),
            make_paragraph("N/A", styles["CellText"]),
            make_paragraph(
                "No scan checks were returned.",
                styles["CellText"],
            ),
        ])

    findings_table = Table(
        findings_rows,
        colWidths=[43 * mm, 32 * mm, 95 * mm],
        repeatRows=1,
        hAlign="LEFT",
    )

    table_style = [
        ("BACKGROUND", (0, 0), (-1, 0), BROWN),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.4, LIGHT_BROWN),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
    ]

    for row_number, item in enumerate(results, start=1):
        if item.get("present") is True:
            row_color = GREEN
        elif item.get("present") is False:
            row_color = RED
        else:
            row_color = GREY

        table_style.append(
            (
                "BACKGROUND",
                (1, row_number),
                (1, row_number),
                row_color,
            )
        )

    findings_table.setStyle(TableStyle(table_style))
    content.append(findings_table)

    # Recommendations
    content.append(
        Paragraph("Recommended Actions", styles["SectionHeading"])
    )

    if recommendations:
        for number, recommendation in enumerate(
            recommendations,
            start=1,
        ):
            content.append(
                Paragraph(
                    f"{number}. {escape(str(recommendation))}",
                    styles["Recommendation"],
                )
            )
    else:
        content.append(
            Paragraph(
                "No recommendations were returned by this scan.",
                styles["SmallMuted"],
            )
        )

    # Disclaimer
    content.append(Spacer(1, 12))

    content.append(
        HRFlowable(
            width="100%",
            thickness=0.7,
            color=LIGHT_BROWN,
            spaceAfter=8,
        )
    )

    content.append(
        Paragraph(
            "<b>Important:</b> This report contains results from "
            "automated checks performed by WebVulnLab. A passing "
            "check does not prove that a website is secure. The risk "
            "score is an educational estimate, not a formal security "
            "rating. Verify findings manually and scan only systems "
            "you own or have permission to assess.",
            styles["SmallMuted"],
        )
    )

    # Header and footer on each PDF page
    def draw_page(canvas, document):
        canvas.saveState()

        page_width, page_height = A4

        canvas.setStrokeColor(LIGHT_BROWN)
        canvas.setLineWidth(0.7)

        canvas.line(
            document.leftMargin,
            page_height - 16 * mm,
            page_width - document.rightMargin,
            page_height - 16 * mm,
        )

        canvas.setFont("Helvetica-Bold", 8)
        canvas.setFillColor(BROWN)

        canvas.drawString(
            document.leftMargin,
            page_height - 12 * mm,
            "WEBVULNLAB | SECURITY STUDIO",
        )

        canvas.line(
            document.leftMargin,
            15 * mm,
            page_width - document.rightMargin,
            15 * mm,
        )

        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(MUTED)

        canvas.drawString(
            document.leftMargin,
            10 * mm,
            "For authorized assessment use",
        )

        canvas.drawRightString(
            page_width - document.rightMargin,
            10 * mm,
            f"Page {document.page}",
        )

        canvas.restoreState()

    pdf.build(
        content,
        onFirstPage=draw_page,
        onLaterPages=draw_page,
    )

    buffer.seek(0)

    filename = (
        "WebVulnLab_Report_"
        + datetime.now().strftime("%Y%m%d_%H%M%S")
        + ".pdf"
    )

    return send_file(
        buffer,
        as_attachment=True,
        download_name=filename,
        mimetype="application/pdf",
    )


# --------------------------------------------------
# SETTINGS
# --------------------------------------------------

@app.route("/settings", methods=["GET", "POST"])
def settings():
    if request.method == "POST":
        flash(
            "Settings page is available. No settings were changed.",
            "success",
        )
        return redirect(url_for("settings"))

    return render_template("settings.html")


# --------------------------------------------------
# ERROR HANDLING
# --------------------------------------------------

@app.errorhandler(404)
def page_not_found(error):
    return "Page not found. Check the URL.", 404


# --------------------------------------------------
# START APPLICATION
# --------------------------------------------------

if __name__ == "__main__":
    app.run(debug=True, port=5000)
