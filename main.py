import requests

def fetch(url):
    try:
        response = requests.get(url, timeout=10)
        return response
    except requests.exceptions.RequestException as e:
        print("Could not reach the site:", e)
        return None

url = "https://example.com"
response = fetch(url)

if response is not None:
    print("Status code:", response.status_code)
    print("Final URL:", response.url)
    print()
    for name, value in response.headers.items():
        print(name, ":", value)
