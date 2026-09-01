import urllib.request
import json

try:
    print("Sending GET to http://127.0.0.1:8000/health using urllib...")
    with urllib.request.urlopen("http://127.0.0.1:8000/health", timeout=3.0) as response:
        html = response.read()
        print("Status Code:", response.status)
        print("Response JSON:", json.loads(html.decode('utf-8')))
except Exception as e:
    print("Connection failed with exception:", e)
