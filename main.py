import requests

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
    required=[
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Referrer-Policy",
    ]
    results=[]
    for name in required:
        results.append({"header":name,"present":name in headers})
    return results
results = check_security_headers(response.headers)
for item in results:
    if item["present"]:
        print("PRESENT:", item["header"])
    else:
        print("MISSING:", item["header"])