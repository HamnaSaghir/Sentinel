import requests

HEADER_RULES = {
    "Strict-Transport-Security": {
        "severity": "Medium",
        "impact": "Browsers are not told to always use HTTPS, so a first visit could be downgraded to HTTP.",
        "fix": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains",
    },
    "Content-Security-Policy": {
        "severity": "Medium",
        "impact": "Browser has no rules about which scripts and resources may load which makes script injection easier.",
        "fix": "Define a Content-Security-Policy, starting with default-src 'self' and adding what the site only needs",
    },
    "X-Frame-Options": {
        "severity": "Low",
        "impact": "Other sites may be able to show this page in a hidden frame (clickjacking).",
        "fix": "Add: X-Frame-Options: DENY (or use CSP frame-ancestors)",
    },
    "X-Content-Type-Options": {
        "severity": "Low",
        "impact": "Browsers may try to guess the content type of a file, which can make a harmless file run as a script.",
        "fix": "Add: X-Content-Type-Options: nosniff",
    },
    "Referrer-Policy": {
        "severity": "Low",
        "impact": "Full page addresses may be shared with other sites",
        "fix": "Add: Referrer-Policy: no-referrer (or use strict-origin-when-cross-origin)",
    },
}

def fetch(url):
    try:
        response = requests.get(url, timeout=10)
        return response
    except requests.exceptions.RequestException as e:
        print("Could not reach the site:", e)
        return None

def check_hsts(headers):
    if "Strict-Transport-Security" in headers:
        return "HSTS is present: " + headers["Strict-Transport-Security"]
    else:
        return "HSTS header is missing"

url = "https://github.com"
response = fetch(url)

if response is not None:
    print()
    print(check_hsts(response.headers))
    print("Status code:", response.status_code)
    print("Final URL:", response.url)
    print()

def check_security_headers(headers):
    findings = []
    csp = headers.get("Content-Security-Policy")
    for name, rule in HEADER_RULES.items():
        if name in headers: 
            continue
        if name == "X-Frame-Options" and csp and "frame-ancestors" in csp:
            continue
        findings.append({
            "issue": "Missing " + name,
            "severity": rule["severity"],
            "impact": rule["impact"],
            "evidence": "The response did not contain a " + name + " header.",
            "fix": rule["fix"],
        })
    return findings

findings = check_security_headers(response.headers)
if not findings:
    print("No missing security headers found.")
for f in findings:
    print()
    print("[" + f["severity"] + "]", f["issue"])
    print("Impact:", f["impact"])
    print("Evidence:", f["evidence"])
    print("Fix:", f["fix"])