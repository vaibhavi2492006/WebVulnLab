
# WebVulnLab | Security Studio

A Flask-based educational web security scanner that checks common website security configurations and generates PDF assessment reports.

## Overview

WebVulnLab is a student project designed to help users understand basic website security checks through a dashboard, scan results, findings, and downloadable reports.

## Features

- **Security Scanner:** Checks selected HTTP security headers and other configured security indicators.
- **Dashboard:** Displays scan statistics and the latest risk summary.
- **Findings Page:** Presents security checks, statuses, and descriptions.
- **Scan History:** Shows recent successful scans during the current application session.
- **PDF Reports:** Generates downloadable security assessment reports.
- **Web Interface:** Flask templates with a beige-and-brown visual theme.

## Technology Stack

- Python
- Flask
- Requests
- ReportLab
- HTML and CSS
- Git and GitHub

## Project Structure

```text
WebVulnLab/
├── app.py
├── scanner.py
├── test_scanner.py
├── test_site.py
├── templates/
│   ├── base.html
│   ├── index.html
│   ├── scanner.html
│   ├── findings.html
│   ├── reports.html
│   └── settings.html
├── static/
│   └── style.css
├── reports/
├── .gitignore
└── README.md
```

## Requirements

- Python 3.10 or later recommended
- pip
- Git

## Installation

Clone the repository:

```bash
git clone https://github.com/vaibhavi2492006/WebVulnLab.git
cd WebVulnLab
```

Create a virtual environment:

**Windows PowerShell**

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

Install dependencies:

```powershell
python -m pip install Flask requests reportlab
```

## Configuration

Set a Flask secret key in your terminal before launching the app.

**Windows PowerShell:**

```powershell
$env:FLASK_SECRET_KEY = python -c "import secrets; print(secrets.token_hex(32))"
```

This generates a temporary key for the current terminal session.

## Run the Application

Start the Flask application:

```powershell
python app.py
```

Open this address in your browser:

```text
http://127.0.0.1:5000/
```

## Local Testing

The project includes a local test site in `test_site.py`.

In a separate terminal, start it with:

```powershell
python test_site.py
```

If configured to use port 5001, the local test site is available at:

```text
http://127.0.0.1:5001/
```

Use only systems you own or have explicit permission to test. The scanner currently requires additional hardening before use against arbitrary targets.

## Important Limitations

- Scan history is stored in memory and resets when the Flask application restarts.
- The risk score is an educational estimate, not a formal security rating.
- Automated checks cannot prove that a website is secure.
- URL validation alone is not sufficient SSRF protection.
- This project is intended for educational use and controlled testing.

## Future Improvements

- Add SSRF-resistant destination validation.
- Improve TLS and redirect analysis.
- Add automated tests for scanner edge cases.
- Store scan history in a database.
- Improve report filtering and severity classification.

## Responsible Use

Use WebVulnLab only on websites and systems you own or have explicit authorization to assess. Do not use it to access private infrastructure or conduct unauthorized security testing.

## Author

**Vaibhavi Pathak**

Developed as an educational web security project.
