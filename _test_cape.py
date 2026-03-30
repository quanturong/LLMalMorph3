import urllib.request
import urllib.error
import os
import json

# Load .env
from dotenv import load_dotenv
load_dotenv()

cape_url = os.getenv('CAPE_BASE_URL', 'http://192.168.1.12:8000').rstrip('/')
print(f"Testing CAPE URL: {cape_url}")
print()

def test_url(path, label):
    url = cape_url + path
    print(f"{label}")
    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=5) as response:
            data = response.read().decode('utf-8')
            print(f"  Status: {response.status}")
            print(f"  Response (first 300 chars): {data[:300]}")
    except urllib.error.URLError as e:
        print(f"  ERROR: {e.reason}")
    except Exception as e:
        print(f"  ERROR: {type(e).__name__} - {str(e)[:200]}")
    print()

test_url("/", "Test 1: GET /")
test_url("/api/task/list", "Test 2: GET /api/task/list")
test_url("/api/task/98", "Test 3: GET /api/task/98")
