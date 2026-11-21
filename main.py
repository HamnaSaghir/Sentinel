import requests
from urllib.parse import urlparse

ONE_YEAR = 31536000
SEVERITY_ORDER = {"High": 0, "Medium": 1, "Low": 2}
SESSION_HINTS = ["sess", "sid", "token", "auth"]

HEADER_RULES = {
    "Strict-Transport-Security": {
        "severity": "Medium",
        "impact": "Browsers are not told to always use HTTPS, so a first visit could be downgraded to HTTP.",
        "fix": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains",
    },
    "Content-Security-Policy": {
        "severity": "Medium",
        "impact": "The browser has no rules about which scripts and resources may load, which makes script injection easier.",
        "fix": "Define a Content-Security-Policy, starting with default-src 'self' and adding only what the site needs.",
    },
    "X-Frame-Options": {
        "severity": "Low",
        "impact": "Other sites may be able to show this page in a hidden frame (clickjacking).",
        "fix": "Add: X-Frame-Options: DENY (or use CSP frame-ancestors).",
    },
    "X-Content-Type-Options": {
        "severity": "Low",
        "impact": "Browsers may guess the content type of a file, which can make a harmless file run as a script.",
        "fix": "Add: X-Content-Type-Options: nosniff",
    },
    "Referrer-Policy": {
        "severity": "Low",
        "impact": "Full page addresses may be shared with other sites.",
        "fix": "Add: Referrer-Policy: strict-origin-when-cross-origin",
    },
}
def make_finding(issue, severity, evidence, impact, fix):
    return {
        "issue": issue,
        "severity": severity,
        "evidence": evidence,
        "impact": impact,
        "fix": fix,
    }

def severity_rank(finding):
    return SEVERITY_ORDER[finding["severity"]]

def fetch(url):
    try:
        response = requests.get(url, timeout=10)
        return response
    except requests.exceptions.RequestException as e:
        print("Could not reach the site:", e)
        return None
def check_security_headers(headers):
    findings = []
    csp = headers.get("Content-Security-Policy")
    for name, rule in HEADER_RULES.items():
        if name in headers:
            continue
        if name == "X-Frame-Options" and csp and "frame-ancestors" in csp.lower():
            continue
        findings.append(make_finding(
            "Missing " + name,
            rule["severity"],
            "The response did not contain a " + name + " header.",
            rule["impact"],
            rule["fix"],
        ))
    return findings
def check_hsts_quality(headers):
    value = headers.get("Strict-Transport-Security")
    if value is None:
        return []

    max_age = None
    for part in value.split(";"):
        part = part.strip().lower()
        if part.startswith("max-age="):
            number = part.split("=")[1].strip()
            if number.isdigit():
                max_age = int(number)

    if max_age is None:
        return [make_finding(
            "HSTS header has no valid max-age",
            "Low",
            "The header value was: " + value,
            "Browsers may ignore the policy.",
            "Use: Strict-Transport-Security: max-age=31536000; includeSubDomains",
        )]

    if max_age < ONE_YEAR:
        return [make_finding(
            "HSTS max-age is short",
            "Low",
            "max-age is " + str(max_age) + " seconds, less than one year (31536000).",
            "The browser forgets the HTTPS-only rule quickly, so protection is weak.",
            "Increase max-age to at least 31536000 once HTTPS works everywhere.",
        )]

    return []
def get_cookie_lines(response):
    try:
        return response.raw.headers.getlist("Set-Cookie")
    except AttributeError:
        return []

def check_cookies(cookie_lines):
    findings = []
    for line in cookie_lines:
        parts = line.split(";")
        name = parts[0].split("=")[0].strip()

        flags = []
        for p in parts[1:]:
            flags.append(p.strip().lower())

        has_secure = "secure" in flags
        has_httponly = "httponly" in flags
        has_samesite = False
        for f in flags:
            if f.startswith("samesite="):
                has_samesite = True

        is_session = False
        for hint in SESSION_HINTS:
            if hint in name.lower():
                is_session = True

        if is_session:
            important = "Medium"
        else:
            important = "Low"

        if not has_secure:
            findings.append(make_finding(
                "Cookie '" + name + "' has no Secure flag",
                important,
                "The Set-Cookie line for '" + name + "' did not include Secure.",
                "The cookie may be sent over plain HTTP, where it can be read.",
                "Add the Secure attribute to this cookie.",
            ))
        if not has_httponly:
            findings.append(make_finding(
                "Cookie '" + name + "' has no HttpOnly flag",
                important,
                "The Set-Cookie line for '" + name + "' did not include HttpOnly.",
                "If the site has an XSS bug, a script could read this cookie.",
                "Add the HttpOnly attribute to this cookie.",
            ))
        if not has_samesite:
            findings.append(make_finding(
                "Cookie '" + name + "' has no SameSite attribute",
                "Low",
                "The Set-Cookie line for '" + name + "' did not include SameSite.",
                "Other sites may be able to trigger requests that carry this cookie (CSRF).",
                "Add SameSite=Lax (or Strict) to this cookie.",
            ))
    return findings
def run_scan(url):
    response = fetch(url)
    if response is None:
        print("Scan stopped: could not reach the site.")
        return

    print("Status code:", response.status_code)
    print("Final URL:", response.url)

    findings = []
    findings += check_security_headers(response.headers)
    findings += check_hsts_quality(response.headers)
    findings += check_cookies(get_cookie_lines(response))
    findings.sort(key=severity_rank)

    if not findings:
        print("No findings.")
    for f in findings:
        print()
        print("[" + f["severity"] + "]", f["issue"])
        print("Evidence:", f["evidence"])
        print("Impact:", f["impact"])
        print("Fix:", f["fix"])


def validate_url(raw):
    raw=raw.strip()
    if raw=="":
        return None, " The url is empty. "
    if " " in raw:
        return None, "The URL contains spaces."
    if"://" not in raw:
        raw= "https://"+ raw

    parsed = urlparse(raw)
    if parsed.scheme not in ("http", "https"):
        return None, "Only http and https URLs are allowed."
    if not parsed.hostname:
        return None, " The URL has no website name."
    try:
        parsed.port
    except ValueError:
        return None, " The port number is not valid."
    return raw,None

def ask_permission(url):
    print("Target: ",url)
    answer =input("Do you have permission to scan this site? (yes/no): ")
    return answer.strip().lower() == "yes"

def main():
    raw = input("Enter the website to scan:")
    url,error= validate_url(raw)
    if error:
        print("Invalidate URL : ", error)
        return
    if not ask_permission(url):
         print("Scan cancelled. Only scan sites you have permission to test.")
         return
    run_scan(url)

if __name__ =="__main__":
    main()

print(validate_url("github.com"))
print(validate_url("ftp://x.com"))
