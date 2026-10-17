
import requests
from urllib.parse import urlparse, urljoin


SECURITY_HEADERS = {
    "Content-Security-Policy": "Helps reduce cross-site scripting (XSS) risks.",
    "Strict-Transport-Security": "Tells browsers to use HTTPS for future connections.",
    "X-Content-Type-Options": "Helps prevent MIME-type sniffing.",
    "X-Frame-Options": "Helps protect against clickjacking.",
    "Referrer-Policy": "Controls how much referrer information browsers send.",
    "Permissions-Policy": "Controls access to certain browser features.",
}


def scan_security_headers(url):
    """Run WebVulnLab security checks on a URL."""

    try:
        response = requests.get(
            url,
            timeout=10,
            allow_redirects=True,
            headers={"User-Agent": "WebVulnLab/1.0"},
        )
        response.raise_for_status()

        results = []

        # 1. Security headers
        for header, explanation in SECURITY_HEADERS.items():
            value = response.headers.get(header)
            results.append({
                "name": header,
                "present": bool(value),
                "description": (
                    f"Detected value: {value}" if value else explanation
                ),
            })

        # 2. HTTPS and certificate checks
        results.append(check_https(response.url))
        results.append(check_ssl_certificate(response.url))

        # 3. HTTP-to-HTTPS redirect
        results.append(check_https_redirect(url))

        # 4. Cookie security
        results.extend(check_cookie_security(response.url))

        # 5. Redirect security
        results.append(check_redirect_security(url))

        # 6. Information disclosure
        results.extend(check_information_disclosure(response.url))

        # 7. Website configuration files
        results.extend(check_website_configuration(response.url))

        # Calculate risk BEFORE returning the results.
        risk = calculate_risk_score(results)

        return {
            "success": True,
            "url": response.url,
            "http_status": response.status_code,
            "results": results,
            "risk_score": risk["score"],
            "risk_level": risk["level"],
            "recommendations": risk["recommendations"],
        }

    except requests.RequestException as error:
        return {
            "success": False,
            "url": url,
            "error": str(error),
            "results": [],
            "risk_score": 0,
            "risk_level": "Scan failed",
            "recommendations": [],
        }


def check_https(url):
    """Check whether the final URL uses HTTPS."""

    is_https = urlparse(url).scheme.lower() == "https"

    return {
        "name": "HTTPS Usage",
        "present": is_https,
        "description": (
            "The website URL uses HTTPS."
            if is_https
            else "The website URL uses HTTP. Use HTTPS to encrypt data in transit."
        ),
    }


def check_ssl_certificate(url):
    """Check whether the HTTPS connection certificate can be verified."""

    if urlparse(url).scheme.lower() != "https":
        return {
            "name": "SSL/TLS Certificate",
            "present": None,
            "description": "Not assessed because the final URL does not use HTTPS.",
        }

    try:
        requests.get(url, timeout=10, verify=True, allow_redirects=True)
        return {
            "name": "SSL/TLS Certificate",
            "present": True,
            "description": "HTTPS connection succeeded with certificate verification enabled.",
        }
    except requests.exceptions.SSLError:
        return {
            "name": "SSL/TLS Certificate",
            "present": False,
            "description": "Certificate verification failed. Review certificate validity and configuration.",
        }
    except requests.RequestException as error:
        return {
            "name": "SSL/TLS Certificate",
            "present": None,
            "description": f"Certificate check could not complete: {error}",
        }


def check_https_redirect(url):
    """Check whether an HTTP URL redirects to HTTPS."""

    if urlparse(url).scheme.lower() != "http":
        return {
            "name": "HTTP to HTTPS Redirect",
            "present": None,
            "description": "Not assessed because the supplied URL does not use HTTP.",
        }

    try:
        response = requests.get(url, timeout=10, allow_redirects=True)
        redirected_to_https = (
            urlparse(response.url).scheme.lower() == "https"
        )

        return {
            "name": "HTTP to HTTPS Redirect",
            "present": redirected_to_https,
            "description": (
                "The HTTP request ended at an HTTPS URL."
                if redirected_to_https
                else "The HTTP request did not end at an HTTPS URL."
            ),
        }
    except requests.RequestException as error:
        return {
            "name": "HTTP to HTTPS Redirect",
            "present": None,
            "description": f"Redirect check could not complete: {error}",
        }


def check_cookie_security(url):
    """Inspect cookie security attributes from Set-Cookie headers."""

    try:
        response = requests.get(url, timeout=10, allow_redirects=True)
        set_cookie_headers = response.raw.headers.getlist("Set-Cookie")

        if not set_cookie_headers:
            return [{
                "name": "Cookie Security",
                "present": None,
                "description": "No Set-Cookie headers were detected; cookie security could not be assessed.",
            }]

        results = []
        is_https = urlparse(response.url).scheme.lower() == "https"

        for header in set_cookie_headers:
            parts = [part.strip() for part in header.split(";")]
            cookie_name = parts[0].split("=", 1)[0] if parts else "Unknown"
            attributes = {
                part.split("=", 1)[0].strip().lower(): (
                    part.split("=", 1)[1].strip()
                    if "=" in part else True
                )
                for part in parts[1:]
            }

            issues = []

            if is_https and "secure" not in attributes:
                issues.append("Secure flag is missing")
            if "httponly" not in attributes:
                issues.append("HttpOnly flag is missing")
            if "samesite" not in attributes:
                issues.append("SameSite attribute is missing")

            results.append({
                "name": f"Cookie: {cookie_name}",
                "present": not issues,
                "description": (
                    "Cookie security attributes look good."
                    if not issues
                    else "; ".join(issues)
                ),
            })

        return results

    except (requests.RequestException, AttributeError) as error:
        return [{
            "name": "Cookie Security",
            "present": None,
            "description": f"Cookie check could not complete: {error}",
        }]


def check_redirect_security(url):
    """Inspect redirect chains and HTTPS downgrades."""

    try:
        response = requests.get(url, timeout=10, allow_redirects=True)
        redirect_count = len(response.history)
        original_scheme = urlparse(url).scheme.lower()
        final_scheme = urlparse(response.url).scheme.lower()

        issues = []

        if redirect_count > 5:
            issues.append(f"Long redirect chain detected ({redirect_count} redirects)")

        if original_scheme == "https" and final_scheme == "http":
            issues.append("HTTPS-to-HTTP downgrade detected")

        return {
            "name": "Redirect Security",
            "present": not issues,
            "description": (
                "; ".join(issues)
                if issues
                else f"No listed redirect issue detected ({redirect_count} redirects)."
            ),
        }

    except requests.RequestException as error:
        return {
            "name": "Redirect Security",
            "present": None,
            "description": f"Redirect check could not complete: {error}",
        }


def check_information_disclosure(url):
    """Check for technology-identifying response headers."""

    disclosure_headers = {
        "Server": "May reveal web server software.",
        "X-Powered-By": "May reveal backend technology.",
        "X-AspNet-Version": "May reveal the ASP.NET version.",
        "X-AspNetMvc-Version": "May reveal the ASP.NET MVC version.",
    }

    try:
        response = requests.get(url, timeout=10, allow_redirects=True)
        results = []

        for header, explanation in disclosure_headers.items():
            value = response.headers.get(header)
            results.append({
                "name": f"Information Disclosure: {header}",
                "present": not bool(value),
                "description": (
                    f"Header reveals: {value}"
                    if value
                    else f"No {header} header detected. {explanation}"
                ),
            })

        return results

    except requests.RequestException as error:
        return [{
            "name": "Information Disclosure",
            "present": None,
            "description": f"Check could not complete: {error}",
        }]


def check_website_configuration(url):
    """Check whether robots.txt and sitemap.xml are publicly accessible."""

    parsed = urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}/"

    checks = [
        ("robots.txt", "Can provide information about paths intended for crawlers."),
        ("sitemap.xml", "Can list publicly discoverable website URLs."),
    ]

    results = []

    for path, explanation in checks:
        try:
            file_url = urljoin(base_url, path)
            response = requests.get(file_url, timeout=10, allow_redirects=True)
            accessible = response.status_code == 200

            results.append({
                "name": f"Configuration File: {path}",
                "present": accessible,
                "description": (
                    f"{path} is publicly accessible. This is not automatically a vulnerability. {explanation}"
                    if accessible
                    else f"{path} was not found with HTTP 200."
                ),
            })

        except requests.RequestException as error:
            results.append({
                "name": f"Configuration File: {path}",
                "present": None,
                "description": f"Check could not complete: {error}",
            })

    return results


def calculate_risk_score(results):
    """Calculate a simple educational risk estimate, not a formal rating."""

    score = 0
    recommendations = []

    for item in results:
        name = item.get("name", "")
        present = item.get("present")
        severity = "Informational"
        points = 0
        recommendation = "Review this result if relevant."

        # Unknown or unassessed results should not increase the score.
        if present is False:
            if name in (
                "Content-Security-Policy",
                "Strict-Transport-Security",
                "X-Content-Type-Options",
                "X-Frame-Options",
            ):
                severity = "Medium"
                points = 10
                recommendation = f"Review and configure the {name} header."

            elif name == "HTTPS Usage":
                severity = "High"
                points = 25
                recommendation = "Enable HTTPS and redirect HTTP requests to HTTPS."

            elif name == "SSL/TLS Certificate":
                severity = "High"
                points = 25
                recommendation = "Check certificate validity and HTTPS configuration."

            elif name == "HTTP to HTTPS Redirect":
                severity = "Medium"
                points = 10
                recommendation = "Configure HTTP requests to redirect to HTTPS."

            elif name.startswith("Cookie:") or name == "Cookie Security":
                severity = "Medium"
                points = 10
                recommendation = "Review Secure, HttpOnly, and SameSite cookie attributes."

            elif name == "Redirect Security":
                severity = "Medium"
                points = 10
                recommendation = "Review the redirect chain and avoid HTTPS downgrades."

            elif name.startswith("Information Disclosure:"):
                severity = "Low"
                points = 5
                recommendation = "Consider removing unnecessary technology-identifying headers."

        item["severity"] = severity
        item["risk_points"] = points
        item["recommendation"] = recommendation

        score += points

        if points > 0:
            recommendations.append({
                "name": name,
                "severity": severity,
                "recommendation": recommendation,
            })

    score = min(score, 100)

    if score >= 50:
        level = "High"
    elif score >= 20:
        level = "Medium"
    elif score > 0:
        level = "Low"
    else:
        level = "No detected issues"

    return {
        "score": score,
        "level": level,
        "recommendations": recommendations,
    }
