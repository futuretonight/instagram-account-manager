import base64
import concurrent.futures
import platform  # For OS detection
import shutil    # For directory operations like rmtree (cleanup)
import requests  # For downloading from JSON endpoint
import zipfile   # For extracting zip files
import io        # For in-memory zip file handling
import csv
import ctypes # For DPI awareness
import datetime # Not used in the provided snippet, but kept if needed elsewhere
import hashlib
import uuid
import json
import logging
import os
import queue
import random
import re
import string
import sys
import threading
import time
import subprocess
import traceback
import urllib.parse
import urllib3  # For disabling warnings# GUI Imports (Tkinter)
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from urllib3.exceptions import MaxRetryError 
#from fake_useragent import UserAgent
from faker import Faker
# Utility Imports
from pathlib import Path

# --- Selenium Imports --- Needed across the board
from selenium import webdriver
from selenium.common.exceptions import (
    TimeoutException, NoSuchElementException, WebDriverException,
    SessionNotCreatedException, ElementNotInteractableException,
    ElementClickInterceptedException, StaleElementReferenceException
)
from selenium.webdriver.chrome.options import Options as ChromeOptions
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import Select  # Needed for birthday
from selenium.webdriver.support.ui import WebDriverWait
from selenium_stealth import stealth
from webdriver_manager.chrome import ChromeDriverManager

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
# --- Third-Party Library Imports ---
try:
    import colorama
    colorama.init(autoreset=True)
    COLORAMA_AVAILABLE = True
except ImportError:
    print("Warning: colorama not found (pip install colorama). Terminal colors disabled.")
    COLORAMA_AVAILABLE = False

critical_imports = {
    "selenium": "pip install selenium",
    "selenium_stealth": "pip install selenium-stealth",
    "webdriver_manager.chrome": "pip install webdriver-manager",
    #"fake_useragent": "pip install fake-useragent",
    "requests": "pip install requests",
    "urllib3": "pip install urllib3",
}
missing_critical = []
for lib, install_cmd in critical_imports.items():
    try:
        if '.' in lib:
            base_lib = lib.split('.')[0]
            __import__(base_lib)
        else:
            __import__(lib)
    except ImportError:
        missing_critical.append(f"- {lib} ({install_cmd})")

if missing_critical:
    print("\nERROR: Critical dependencies missing. Install them before running:")
    for item in missing_critical:
        print(item)
    sys.exit(1)

# No longer need DesiredCapabilities for logging prefs with Selenium 4+
# from selenium.webdriver.common.desired_capabilities import DesiredCapabilities

try:
    import geoip2.database
    import geoip2.errors
    GEOIP_AVAILABLE = True
except ImportError:
    GEOIP_AVAILABLE = False

# === Constants ===
START_TIME = time.monotonic()
CONFIG_FILENAME = "config.json"
ACCOUNT_CSV_FILENAME = "generated_accounts_enhanced.csv"
LOG_FILENAME = "instagram_manager_enhanced.log"
SCREENSHOT_DIR = Path("screenshots")
LOG_DIR = Path("logs")
GEOIP_DB_FILENAME = "GeoLite2-Country.mmdb"

# === NEW: Predefined Desktop User-Agents (Windows & Linux, Chrome & Firefox) ===
# This list should be periodically updated with current browser versions.
DESKTOP_USER_AGENTS = [
    # Windows 10/11 + Chrome (Recent versions)
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",

    # Windows 10/11 + Firefox (Recent versions)
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",

    # Linux (Ubuntu) + Chrome (Recent versions)
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",

    # Linux (Ubuntu) + Firefox (Recent versions)
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0"
]

DEFAULT_SETTINGS = {
    # Core Behavior
    "max_accounts": 100, 
    "headless": True, 
    "enable_stealth": True, 
    "browser_type": "chrome",
    "save_screenshots": False,
    "debug_mode": False,
    "force_direct_connection": False,
    "enable_username_url_precheck": True,  # New: Toggle for fast HTTP check
    "max_prechecks_per_signup": 2,         # New: How many HTTP pre-checks per signup attempt
    # Timing & Delays
    "random_delay_min": 0.8, 
    "random_delay_max": 2.5,
    "account_creation_delay_min": 4.0,
    "account_creation_delay_max": 10.0,
    "report_interval_seconds": 1800, 
    "webdriver_wait_timeout": 15,
    "proxy_timeout": 5,
    # Limits & Attempts
    "max_login_attempts": 2, 
    "max_reports_per_day": 15,
    # Concurrency
    "proxy_test_threads": 200, 
    "max_mass_report_workers": 5,
    # Paths (Persistent)
    "chrome_binary_path": "", 
    "chrome_driver_path": "", 
    "geoip_db_path": "",
    # Misc
    "use_direct_connection_fallback": True,
    "use_persistent_browser_profiles": False, # When True, uses unique user-data-dirs for each driver launch.
    "cleanup_persistent_profiles": True,      # When True, deletes user-data-dirs after use (or on exit)
    "debug_pause_duration_on_fail": 0, # Seconds to pause on failure; 0=no pause, <0=indefinite (manual resume)
# === NEW ACCOUNT AGING/BEHAVIOR SETTINGS ===
    "enable_account_aging": True,      # Whether to perform aging actions after creation
    "min_age_action_delay_sec": 3.0,   # Min delay between individual aging actions
    "max_age_action_delay_sec": 8.0,   # Max delay
    "num_explore_scroll_loops": 3,     # How many times to scroll down the Explore feed
    "num_profiles_to_follow": 3,       # Number of random profiles to try following
    "num_posts_to_like": 5,            # Number of posts to like on explore feed
    # ============================================
}

GUI_LOG_TAGS = {
    logging.DEBUG: "log_debug", 
    logging.INFO: "log_info",
    logging.WARNING: "log_warning", 
    logging.ERROR: "log_error",
    logging.CRITICAL: "log_critical",
}
LOG_COLORS = {
    logging.DEBUG: 'DIM', 
    logging.INFO: 'GREEN', 
    logging.WARNING: 'YELLOW',
    logging.ERROR: 'RED', 
    logging.CRITICAL: 'RED',
}

# === Logging Setup ===
logger = logging.getLogger(__name__)


class ColorizingFormatter(logging.Formatter):
    def format(self, record):
        log_message = super().format(record)
        if COLORAMA_AVAILABLE:
            color = LOG_COLORS.get(record.levelno)
            if color:
                color_attr = getattr(colorama.Fore, color,
                                     getattr(colorama.Style, color, None))
                if color_attr:
                    log_message = color_attr + log_message + colorama.Style.RESET_ALL
        return log_message


class QueueHandler(logging.Handler):
    def __init__(self, log_queue):
        super().__init__()
        self.log_queue = log_queue

    def emit(self, record):
        try:
            self.log_queue.put((record.levelno, self.format(record)))
        except Exception:
            self.handleError(record)


def setup_global_logging(level=logging.INFO, queue_ref=None):
    global logger
    if logger.hasHandlers():
        for handler in logger.handlers[:]:
            try:
                handler.close(); logger.removeHandler(handler)
            except Exception: pass
    if queue_ref:
        while not queue_ref.empty():
            try:
                queue_ref.get_nowait()
            except queue.Empty: break
    logger.setLevel(level)
    gui_format = '%(asctime)s - %(levelname)s - %(message)s'
    console_file_format = '%(asctime)s - %(levelname)-8s - [%(threadName)s:%(filename)s:%(lineno)d] - %(message)s' if level == logging.DEBUG else gui_format
    try:
        LOG_DIR.mkdir(exist_ok=True)
        file_handler = logging.FileHandler(
            LOG_DIR / LOG_FILENAME, encoding='utf-8', mode='a')
        file_handler.setFormatter(logging.Formatter(console_file_format))
        file_handler.setLevel(level)
        logger.addHandler(file_handler)
    except Exception as e:
        print(f"CRITICAL: Failed to set up file logger: {e}", file=sys.stderr)
    console_handler = logging.StreamHandler(sys.stdout)
    console_formatter = ColorizingFormatter(
        console_file_format) if COLORAMA_AVAILABLE else logging.Formatter(console_file_format)
    console_handler.setFormatter(console_formatter)
    console_handler.setLevel(level)
    logger.addHandler(console_handler)
    if queue_ref:
        gui_formatter = logging.Formatter(gui_format)
        queue_handler = QueueHandler(queue_ref)
        queue_handler.setFormatter(gui_formatter)
        queue_handler.setLevel(level)
        logger.addHandler(queue_handler)
    logger.propagate = False
    logger.debug(
        f"Global logging setup complete. Level: {logging.getLevelName(level)}")

# === Helper Classes ===


class EnhancedEmailCreator:
    """
    Generates temporary email addresses using various online services
    and attempts to read confirmation codes from some of them.
    """

    def __init__(self):
        self.session = requests.Session()
        _session_ua = random.choice(DESKTOP_USER_AGENTS)
        self.session.headers.update({'User-Agent': _session_ua})
        # Will store {'address': ..., 'provider': ..., 'details': ...}
        self.last_email_details = {}
        logger.debug("Email Creator initialized.")

    def _parse_code_from_text(self, text_content):
        """Extracts a 6-8 digit code from email text."""
        if not text_content:
            return None
        patterns = [
            r"(?i)(?:instagram\s+code\s*(?:is|:)?)?\s*(\d{3}[-\s]?\d{3})\b",
            r"(?i)\b(\d{6,8})\b(?=\s*(?:is|is your|to confirm|code|for instagram))",
            r"(?i)(?:confirmation code|security code|verification code|your code)\s*(?:is|:)?\s*(\d{6,8})\b",
            r"\b(\d{6,8})\b"
        ]
        for pattern in patterns:
            match = re.search(pattern, text_content)
            if match:
                code = match.group(1).replace("-", "").replace(" ", "")
                if 6 <= len(code) <= 8:
                    return code
        logger.debug(f"No 6-8 digit code found in text.")
        return None

    def create_temporary_email(self):
        logger.debug("Attempting to create temporary email...")
        self.last_email_details = {}

        email_methods = [
            (self._create_1secmail_email, "1secmail"),
            (self._create_guerrillamail_email_v2, "guerrillamail"),
            (self._create_mailtm_email, "mailtm"),
            (self._create_tempmail_lol_manual, "tempmail_lol"),
            (self._create_maildrop_email, "maildrop"),
        ]
        random.shuffle(email_methods)
        email_methods.append(
            (self._create_generic_fallback_email, "generic_fallback"))

        for method_func, provider_tag in email_methods:
            email_info = None
            method_name_display = method_func.__name__.replace(
                '_create_', '').replace('_email', '')
            try:
                logger.debug(f"Trying email provider: {method_name_display}")
                email_info = method_func()

                if email_info and isinstance(email_info, tuple) and email_info[0] and '@' in email_info[0]:
                    email_address, provider_details = email_info[0], email_info[1] if len(
                        email_info) > 1 else None
                    self.last_email_details = {
                        'address': email_address, 'provider': provider_tag, 'details': provider_details}
                    logger.info(
                        f"Successfully created email via {method_name_display}: {email_address}")
                    return self.last_email_details
                elif email_info:
                    logger.warning(
                        f"Provider {method_name_display} returned invalid format: {email_info}")
            except Exception as e:
                logger.warning(
                    f"Failed to create email with {method_name_display}: {e}", exc_info=False)
                time.sleep(random.uniform(0.3, 0.8))

        logger.error("Failed to create temporary email with ANY service.")
        return None

    # --- REWORKED: Provider-Specific Email Methods ---

    def _create_1secmail_email(self):
        # 1secmail blocks simple requests. We must simulate a browser visit.
        with requests.Session() as s:
            s.headers.update({  # Send convincing browser headers
                'User-Agent': random.choice(DESKTOP_USER_AGENTS),
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Sec-Fetch-Dest': 'document',
                'Sec-Fetch-Mode': 'navigate',
                'Sec-Fetch-Site': 'none',
                'Sec-Fetch-User': '?1',
                'Upgrade-Insecure-Requests': '1'
            })

            # "Warm up" the session by visiting the main page first.
            try:
                logger.debug(
                    "1secmail: Warming up session by visiting main page...")
                warmup_resp = s.get("https://www.1secmail.com/", timeout=15)
                warmup_resp.raise_for_status()
                time.sleep(random.uniform(0.5, 1.5))
            except Exception as e_warm:
                raise Exception(
                    f"1secmail warm-up visit failed: {e_warm}") from e_warm

            try:
                api_url = "https://www.1secmail.com/api/v1/?action=genRandomMailbox&count=1"
                # Make the API call with the same session (which now has cookies from the warm-up)
                response = s.get(api_url, timeout=10)
                response.raise_for_status()
                data = response.json()
                if isinstance(data, list) and data and isinstance(data[0], str) and '@' in data[0]:
                    email = data[0]
                    login, domain = email.split('@')
                    return email, {"login": login, "domain": domain}
                else:
                    raise ValueError(
                        f"1secmail unexpected JSON response: {data}")
            except (requests.RequestException, json.JSONDecodeError, ValueError) as e_api:
                raise Exception(
                    f"1secmail API call failed: {e_api}") from e_api

    def _read_from_1secmail(self, login, domain):
        if not login or not domain:
            return None
        logger.debug(f"Read-1secmail: Checking inbox for {login}@{domain}")
        with requests.Session() as s:  # Use a fresh session for reading
            s.headers.update({
                'User-Agent': random.choice(DESKTOP_USER_AGENTS),
                'Accept': 'application/json, text/plain, */*'
            })
            try:
                list_url = f"https://www.1secmail.com/api/v1/?action=getMessages&login={login}&domain={domain}"
                response = s.get(list_url, timeout=15)
                response.raise_for_status()
                messages = response.json()
                if not messages:
                    return None

                # Newest first
                for msg_header in sorted(messages, key=lambda m: m.get('id'), reverse=True):
                    subject_lower = msg_header.get('subject', '').lower()
                    if any(kw in subject_lower for kw in ["instagram", "confirm", "code", "secure"]):
                        msg_id = msg_header['id']
                        read_url = f"https://www.1secmail.com/api/v1/?action=readMessage&login={login}&domain={domain}&id={msg_id}"
                        msg_resp = s.get(read_url, timeout=10)
                        msg_resp.raise_for_status()
                        msg_data = msg_resp.json()
                        content = msg_data.get(
                            'textBody') or msg_data.get('body') or ""
                        code = self._parse_code_from_text(content)
                        if code:
                            return code
            except Exception as e:
                logger.warning(
                    f"Read-1secmail: Error during API call: {e}", exc_info=False)
        return None

    # The other email creation methods remain the same as the previous response.
    # I have condensed them here for brevity.
    def _create_guerrillamail_email_v2(self):  # (Unchanged)
        try:
            with requests.Session() as s:
                s.headers.update(
                    {'User-Agent': random.choice(DESKTOP_USER_AGENTS)})
                s.get("https://www.guerrillamail.com/",
                      timeout=15).raise_for_status()
                email_resp = s.get("https://www.guerrillamail.com/ajax.php", params={
                                   'f': 'get_email_address'}, headers={'Referer': "https://www.guerrillamail.com/"}, timeout=15)
                email_resp.raise_for_status()
                email_data = email_resp.json()
                if not email_data or 'email_addr' not in email_data or 'sid_token' not in email_data:
                    raise ValueError("Invalid response")
                return email_data['email_addr'], {"sid_token": email_data['sid_token']}
        except Exception as e:
            raise Exception(f"GuerrillaMail error: {e}") from e

    # (Unchanged, cannot be read automatically)
    def _create_tempmail_lol_manual(self):
        email = f"{''.join(random.choices(string.ascii_lowercase + string.digits, k=12))}@{random.choice(['tempmail.lol', 'tempr.email', 'mailisku.com', 'spam.care'])}"
        return email, None

    def _read_from_guerrillamail(self, email_address, sid_token):  # Logic improved
        if not sid_token:
            return None
        logger.debug(
            f"Read-Guerrilla: Checking inbox for {email_address} with SID {sid_token[:10]}...")
        with requests.Session() as gm_session:
            gm_session.headers.update(
                {'User-Agent': random.choice(DESKTOP_USER_AGENTS)})
            gm_session.cookies.set(
                "PHPSESSID", sid_token, domain="www.guerrillamail.com")
            try:
                check_params = {'f': 'check_email', 'seq': int(
                    time.time()), 'sid_token': sid_token}  # Use timestamp for seq
                inbox_resp = gm_session.get(
                    "https://www.guerrillamail.com/ajax.php", params=check_params, timeout=15)
                inbox_resp.raise_for_status()
                inbox_data = inbox_resp.json()
                if 'list' in inbox_data and inbox_data['list']:
                    for email_header in sorted(inbox_data['list'], key=lambda m: m.get('mail_id'), reverse=True):
                        if any(kw in email_header.get('mail_subject', '').lower() for kw in ["instagram", "confirm", "code"]):
                            logger.debug(
                                f"Read-Guerrilla: Found potential email (ID: {email_header.get('mail_id')}). Fetching...")
                            fetch_params = {'f': 'fetch_email', 'email_id': email_header.get(
                                'mail_id'), 'sid_token': sid_token}
                            content_resp = gm_session.get(
                                "https://www.guerrillamail.com/ajax.php", params=fetch_params, timeout=15)
                            content_resp.raise_for_status()
                            content_data = content_resp.json()
                            code = self._parse_code_from_text(
                                content_data.get('mail_body', ''))
                            if code:
                                return code
            except Exception as e:
                logger.warning(f"Read-Guerrilla: Error: {e}", exc_info=False)
        return None

    def _create_mailtm_email(self):  # (Unchanged)
        # Your existing _create_mailtm_email logic here
        pass

    def _create_maildrop_email(self):  # (Unchanged)
        email = f"{''.join(random.choices(string.ascii_lowercase + string.digits, k=10))}@maildrop.cc"
        return email, None

    def _create_generic_fallback_email(self):  # (Unchanged)
        email = f"{''.join(random.choices(string.ascii_lowercase + string.digits, k=12))}@{random.choice(['mailinator.com', 'yopmail.com', 'inboxkitten.com', 'tempmail.net'])}"
        return email, None

    # --- NEW: Automated Email Code Reader ---
    def read_confirmation_code(self, email_details_dict, wait_timeout_sec=180, poll_interval_sec=15):
        if not email_details_dict or not isinstance(email_details_dict, dict):
            logger.error("ReadCode: Invalid email_details_dict provided.")
            return None

        email_address = email_details_dict.get('address')
        provider = email_details_dict.get('provider')
        # Provider-specific, e.g., login, domain, sid_token, api_token
        details = email_details_dict.get('details')

        if not email_address or not provider:
            logger.error(
                f"ReadCode: Missing email address or provider in details: {email_details_dict}")
            return None

        logger.info(
            f"ReadCode: Attempting to read confirmation code for {email_address} (Provider: {provider}). Will poll for {wait_timeout_sec}s.")

        start_time = time.monotonic()

        while time.monotonic() - start_time < wait_timeout_sec:
            code = None
            try:
                if provider == "1secmail" and details:
                    code = self._read_from_1secmail(
                        details.get("login"), details.get("domain"))
                elif provider == "guerrillamail" and details:
                    code = self._read_from_guerrillamail(
                        email_address, details.get("sid_token"))
                elif provider == "mailtm" and details:
                    code = self._read_from_mailtm(details.get("token"))
                # Add elif blocks for other providers here if you implement their readers
                else:
                    logger.warning(
                        f"ReadCode: No automated reader implemented for provider '{provider}'. Cannot fetch code for {email_address}.")
                    return None  # Stop trying if no reader exists

                if code:
                    logger.info(
                        f"ReadCode: Successfully found confirmation code '{code}' for {email_address}.")
                    return code

                logger.debug(
                    f"ReadCode: No code found yet for {email_address}. Waiting {poll_interval_sec}s before retrying.")
                time.sleep(poll_interval_sec)

            except Exception as e:
                logger.error(
                    f"ReadCode: Error during attempt to read email for {email_address} (Provider: {provider}): {e}", exc_info=logger.level == logging.DEBUG)
                # Don't immediately give up on one error, poll again
                time.sleep(poll_interval_sec)

        logger.error(
            f"ReadCode: Timed out waiting for confirmation code for {email_address} after {wait_timeout_sec}s.")
        return None

    # --- Provider-Specific Email Reading Helpers ---
    def _read_from_1secmail(self, login, domain):
        if not login or not domain:
            return None
        logger.debug(f"ReadCode-1secmail: Checking inbox for {login}@{domain}")
        # Use global requests for this, as 1secmail is often blocked by typical proxy/UA combos from self.session
        try:
            list_url = f"https://www.1secmail.com/api/v1/?action=getMessages&login={login}&domain={domain}"
            response = requests.get(list_url, headers={
                                    'User-Agent': random.choice(DESKTOP_USER_AGENTS)}, timeout=10)
            response.raise_for_status()
            messages = response.json()
            if not messages:
                return None

            # Check newest first
            for message_header in sorted(messages, key=lambda m: m.get('id'), reverse=True):
                msg_id = message_header.get('id')
                subject = message_header.get('subject', '').lower()
                # Instagram emails often contain the code in subject or are about confirmation
                if "instagram" in subject or "confirm" in subject or "code" in subject or "secure" in subject:
                    read_url = f"https://www.1secmail.com/api/v1/?action=readMessage&login={login}&domain={domain}&id={msg_id}"
                    msg_response = requests.get(read_url, headers={
                                                'User-Agent': random.choice(DESKTOP_USER_AGENTS)}, timeout=10)
                    msg_response.raise_for_status()
                    msg_data = msg_response.json()
                    content_to_parse = msg_data.get('textBody') or msg_data.get(
                        'htmlBody') or msg_data.get('body')  # Prefer textBody
                    if content_to_parse:
                        code = self._parse_code_from_text(content_to_parse)
                        if code:
                            return code
        except Exception as e:
            logger.warning(f"ReadCode-1secmail: Error fetching/parsing: {e}")
        return None

    def _read_from_guerrillamail(self, email_address, sid_token):
        if not sid_token:
            logger.error(
                "ReadCode-GuerrillaMail: SID token missing. Cannot read emails.")
            return None
        logger.debug(
            f"ReadCode-GuerrillaMail: Checking inbox for {email_address} with SID {sid_token[:10]}...")

        # Guerrilla Mail needs a session that has the SID token set.
        # We use a temporary session here to avoid interfering with self.session if it's proxied.
        with requests.Session() as gm_session:
            gm_session.headers.update(
                {'User-Agent': random.choice(DESKTOP_USER_AGENTS)})
            # Crucial: Set SID as cookie
            gm_session.cookies.set(
                "PHPSESSID", sid_token, domain="www.guerrillamail.com")

            try:
                # seq can be incremental or 1
                check_params = {'f': 'check_email',
                                'seq': 1, 'sid_token': sid_token}
                inbox_response = gm_session.get(
                    "https://www.guerrillamail.com/ajax.php", params=check_params, timeout=15)
                inbox_response.raise_for_status()
                inbox_data = inbox_response.json()

                if 'list' in inbox_data and inbox_data['list']:
                    for email_header in sorted(inbox_data['list'], key=lambda m: m.get('mail_id'), reverse=True):
                        email_id = email_header.get('mail_id')
                        subject = email_header.get('mail_subject', '').lower()
                        # Filter for likely confirmation emails
                        if "instagram" in subject or "confirm" in subject or "code" in subject or "secure" in subject:
                            logger.debug(
                                f"ReadCode-GuerrillaMail: Found potential email (ID: {email_id}, Subject: '{subject}'). Fetching content.")
                            fetch_params = {
                                'f': 'fetch_email', 'email_id': email_id, 'sid_token': sid_token}
                            email_content_response = gm_session.get(
                                "https://www.guerrillamail.com/ajax.php", params=fetch_params, timeout=15)
                            email_content_response.raise_for_status()
                            email_content_data = email_content_response.json()

                            body_to_parse = email_content_data.get(
                                'mail_body')  # Usually HTML
                            if body_to_parse:
                                code = self._parse_code_from_text(
                                    body_to_parse)
                                if code:
                                    return code
                else:
                    logger.debug(
                        f"ReadCode-GuerrillaMail: Inbox for {email_address} appears empty or no new mail.")
            except Exception as e:
                logger.warning(
                    f"ReadCode-GuerrillaMail: Error fetching/parsing for {email_address}: {e}")
        return None

    # Requires JWT token obtained during email creation
    def _read_from_mailtm(self, auth_token):
        if not auth_token:
            logger.error(
                "ReadCode-MailTm: Auth token missing. Cannot read emails.")
            return None
        logger.debug(f"ReadCode-MailTm: Checking inbox using auth token...")
        mailtm_headers = {
            'Authorization': f'Bearer {auth_token}', 'Accept': 'application/json'}
        try:
            # Use self.session for consistency with creation (proxies etc.)
            messages_resp = self.session.get(
                "https://api.mail.tm/messages", headers=mailtm_headers, timeout=15)
            messages_resp.raise_for_status()
            messages_data = messages_resp.json()

            if messages_data and 'hydra:member' in messages_data and messages_data['hydra:member']:
                # Messages are usually sorted newest first by API, but explicitly sort if needed
                for message_header in sorted(messages_data['hydra:member'], key=lambda m: m.get('createdAt'), reverse=True):
                    msg_id = message_header.get('id')
                    subject = message_header.get('subject', '').lower()

                    if "instagram" in subject or "confirm" in subject or "code" in subject or "secure" in subject:
                        logger.debug(
                            f"ReadCode-MailTm: Found potential email (ID: {msg_id}, Subject: '{subject}'). Fetching content.")
                        message_detail_resp = self.session.get(
                            f"https://api.mail.tm/messages/{msg_id}", headers=mailtm_headers, timeout=15)
                        message_detail_resp.raise_for_status()
                        message_detail_data = message_detail_resp.json()

                        body_to_parse = message_detail_data.get('text') or message_detail_data.get(
                            'html', [""])[0]  # Prefer text if available
                        if body_to_parse:
                            code = self._parse_code_from_text(body_to_parse)
                            if code:
                                return code
            else:
                logger.debug("ReadCode-MailTm: Inbox appears empty.")
        except Exception as e:
            logger.warning(f"ReadCode-MailTm: Error fetching/parsing: {e}")
        return None

    # Static method for generating password, unchanged
    @staticmethod
    def generate_password(length=14):
        length = max(12, min(length, 20))
        chars = string.ascii_lowercase + string.ascii_uppercase + \
            string.digits + "!@#$%^&*()_+-=[]{}|;:,.<>?"
        while True:
            password = ''.join(random.choice(chars) for _ in range(length))
            if (any(c.islower() for c in password) and any(c.isupper() for c in password) and
                    any(c.isdigit() for c in password) and any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)):
                return password

# === Core Logic: Instagram Manager ===
class EnhancedInstagramManager:
    """
    Manages Instagram accounts, proxies, and actions with persistence and GUI linkage.
    """
    # initialisation:-

    def __init__(self, settings_override=None):
        # State
        self.proxies = []
        self.proxies_lock = threading.Lock()
        self.accounts = []
        self.account_lock = threading.Lock()
        self._csv_lock = threading.Lock()
        self._config_lock = threading.Lock()

        # WebDriver/Session
        self.driver = None
        self.current_proxy_address = None
        self.current_account = None 
        self.session = requests.Session()

        # Utils
        # --- CRITICAL OVERHAUL: HARDCODED, GUARANTEED DESKTOP CHROME USER AGENT ---
        # Bypassing fake_useragent for this critical setting due to past inconsistencies.
        # This ensures a consistent desktop identity.
        self.current_user_agent = random.choice(DESKTOP_USER_AGENTS)
        logger.info(
            f"Assigned Desktop User Agent for current Selenium session: {self.current_user_agent}")
        # --- END CRITICAL OVERHAUL FOR UA IN INIT ---

        # fake_useragent is still used elsewhere for proxy verification, etc., so keep its generator:
        #self.user_agent_generator = UserAgent() 

        self.email_creator = EnhancedEmailCreator()
        self.fake = Faker()
        self.username_pattern = re.compile(r"^[a-zA-Z0-9._]+$")
        self.geoip_reader = None
        self.gui = None

        # Background Tasks
        self.proxy_load_thread_active = threading.Event()
        self.first_proxy_available = threading.Event()

        # Settings Management
        self.settings = DEFAULT_SETTINGS.copy()  # Start with defaults
        self._load_persistent_settings()  # Load paths from config.json
        
        # Ensure numeric settings are valid types/ranges after load
        self._validate_numeric_settings()
        if settings_override:  # Apply runtime overrides LAST
            self.settings.update(settings_override)
            self._validate_numeric_settings()  # Re-validate after override

        # Platform URLs
        self.platform_urls = {"base": "https://www.instagram.com/", "login": "https://www.instagram.com/accounts/login/",
            "signup": "https://www.instagram.com/accounts/emailsignup/", "graphql": "https://www.instagram.com/graphql/query/"}

        # Setup Dirs
        LOG_DIR.mkdir(exist_ok=True)
        SCREENSHOT_DIR.mkdir(exist_ok=True)

        logger.info(
            f"Initializing Enhanced Instagram Manager... PID: {os.getpid()}")
        log_level = logging.DEBUG if self.settings.get(
            "debug_mode") else logging.INFO
        if logger.getEffectiveLevel() != log_level:
            setup_global_logging(level=log_level, queue_ref=None)

        # Init components
        self.load_geoip_database()
        self.load_accounts_from_csv()
        self.start_background_proxy_load()

     # end of initialising

    def _load_persistent_settings(self):
        config_path = Path(CONFIG_FILENAME)
        if not config_path.is_file():
            logger.info(f"'{CONFIG_FILENAME}' not found. Using default settings.")
            return

        logger.debug(f"Loading persistent settings from '{config_path.name}'...")
        try:
            with self._config_lock, open(config_path, 'r', encoding='utf-8') as f:
                loaded_config = json.load(f)

            # Only update persistent keys
            keys_to_persist = ["chrome_binary_path",
                            "chrome_driver_path", 
                            "geoip_db_path"]
            updated_count = 0
            for key in keys_to_persist:
                if key in loaded_config and key in self.settings:
                    self.settings[key] = loaded_config[key]
                    updated_count += 1

            logger.info(
                f"Loaded {updated_count} persistent settings from '{config_path.name}'.")
        except (json.JSONDecodeError, IOError) as e:
            logger.error(
                f"Error loading '{config_path.name}': {e}. Using defaults for affected settings.",
                exc_info=True
            )

    def save_persistent_settings(self):
        """
        Save all current settings to a persistent configuration file.

        Handles IO and permission errors gracefully.
        Uses thread-safe locking and shows GUI error dialogs if applicable.
        """
        config_path = Path(CONFIG_FILENAME)
        logger.debug(f"Saving persistent settings to '{config_path.name}'...")

        settings_to_save = self.settings.copy()

        try:
            with self._config_lock, open(config_path, 'w', encoding='utf-8') as f:
                json.dump(settings_to_save, f, indent=2, sort_keys=True)

            logger.info(f"Successfully saved {len(settings_to_save)} settings to '{config_path.name}'.")

        except (PermissionError, IOError) as e:
            logger.error(f"Permission/IO denied saving config file '{config_path.name}': {e}")

            if getattr(self, 'gui', None) and getattr(self.gui, 'root', None):
                if self.gui.root.winfo_exists():
                    messagebox.showerror(
                        "Config Save Error",
                        f"Permission/IO error saving config to:\n{config_path.resolve()}\n{e}"
                    )

        except Exception as e:
            logger.error(f"Failed to save settings to '{config_path.name}': {e}", exc_info=True)

            if getattr(self, 'gui', None) and getattr(self.gui, 'root', None):
                if self.gui.root.winfo_exists():
                    messagebox.showerror(
                        "Config Save Error",
                        f"Failed to save config file:\n{e}"
                )


    def _validate_numeric_settings(self):
        """Ensures numeric settings loaded from config are the correct type and within reasonable bounds."""
        validations = {
            "max_accounts": (int, 1, 10000),
            "max_reports_per_day": (int, 1, 1000),
            "report_interval_seconds": (int, 60, 86400),
            "random_delay_min": (float, 0.1, 60.0),
            "random_delay_max": (float, 0.2, 120.0),
            "max_login_attempts": (int, 1, 10),
            "account_creation_delay_min": (float, 1.0, 300.0),
            "account_creation_delay_max": (float, 2.0, 600.0),
            "proxy_timeout": (int, 1, 60),
            "proxy_test_threads": (int, 1, 100),
            "webdriver_wait_timeout": (int, 5, 120),
            "max_mass_report_workers": (int, 1, 50),
        }

        for key, (req_type, min_val, max_val) in validations.items():
            original_value = self.settings.get(key)
            try:
                if req_type is int:
                    converted_value = int(float(original_value))
                elif req_type is float:
                    converted_value = float(original_value)
                else:
                    continue  # Unknown type, skip

                validated_value = max(min_val, min(converted_value, max_val))

                if validated_value != original_value:
                    if converted_value != original_value:
                        logger.warning(
                            f"Setting '{key}': Corrected type from {type(original_value).__name__} to {req_type.__name__} "
                            f"({original_value} -> {validated_value})."
                        )
                    else:
                        logger.warning(
                            f"Setting '{key}': Clamped value {original_value} to range "
                            f"[{min_val}, {max_val}] -> {validated_value}."
                        )
                    self.settings[key] = validated_value

            except (ValueError, TypeError, AttributeError) as e:
                default_val = DEFAULT_SETTINGS[key]
                logger.error(
                    f"Setting '{key}': Invalid value '{original_value}' ({e}). Resetting to default: {default_val}."
                )
                self.settings[key] = default_val

        # Ensure min delay <= max delay
        if self.settings["random_delay_min"] > self.settings["random_delay_max"]:
            logger.warning("Correcting random_delay_min > random_delay_max.")
            self.settings["random_delay_min"] = self.settings["random_delay_max"] / 2
        if self.settings["account_creation_delay_min"] > self.settings["account_creation_delay_max"]:
            logger.warning(
                "Correcting account_creation_delay_min > account_creation_delay_max.")
            self.settings["account_creation_delay_min"] = self.settings["account_creation_delay_max"] / 2

    # --- GeoIP Handling ---
    def load_geoip_database(self):
        if not GEOIP_AVAILABLE:
            logger.debug(
                "GeoIP library not installed, country lookup disabled.")
            self.geoip_reader = None
            return
        db_path_str = self.settings.get("geoip_db_path", "").strip()
        db_path = None
        potential_paths = [Path(db_path_str) if db_path_str else None, Path.cwd(
        ) / GEOIP_DB_FILENAME, LOG_DIR / GEOIP_DB_FILENAME]
        for potential_path in potential_paths:
            if potential_path and potential_path.is_file():
                db_path = potential_path
                resolved_path_str = str(db_path.resolve())
                # Only log if found at a *different* path than explicitly set (or if not set)
                if self.settings.get("geoip_db_path") != resolved_path_str:
                    logger.info(
                        f"Found GeoIP DB at inferred location: {resolved_path_str}")
                    # Don't auto-update setting here unless user explicitly saves in GUI
                break
        if self.geoip_reader:
            try:
                self.geoip_reader.close(); 
                self.geoip_reader = None
            except Exception: pass
        if db_path:
            try:
                self.geoip_reader = geoip2.database.Reader(str(db_path))
                logger.info(
                    f"GeoIP database loaded successfully from: {db_path}")
            except Exception as e:
                logger.error(
                    f"Failed to load GeoIP database from {db_path}: {e}")
                self.geoip_reader = None
        elif db_path_str:  # If path was explicitly set but not found
            logger.warning(
                f"Specified GeoIP DB path not found: {db_path_str}. Country lookup disabled.")
        else:  # No path set, and not found in default locations
            logger.info(
                f"GeoIP DB ('{GEOIP_DB_FILENAME}') not specified or found. Country lookup disabled.")

    def get_proxy_country(self, ip_address):
        if not self.geoip_reader or not ip_address:
            return None
        try:
            response = self.geoip_reader.country(ip_address)
            return response.country.iso_code
        except geoip2.errors.AddressNotFoundError:
            logger.debug(f"GeoIP: Address {ip_address} not found.")
            return None
        except Exception as e:
            logger.error(
                f"GeoIP lookup error for {ip_address}: {e}", exc_info=logger.level == logging.DEBUG)
            return None

    # --- Proxy Handling ---
    def start_background_proxy_load(self, gui_elements=None):
        if self.proxy_load_thread_active.is_set():
            logger.warning(
                "Proxy load requested, but already running. Ignoring.")
            return
        logger.info("Starting background proxy fetch and verification...")
        self.proxy_load_thread_active.set()
        self.first_proxy_available.clear()
        with self.proxies_lock:
            self.proxies.clear(); 
            logger.debug("Previous proxy list cleared.")
        thread = threading.Thread(target=self._load_and_verify_proxies_background, args=(
            gui_elements,), daemon=True, name="ProxyLoader")
        thread.start()

    def _load_and_verify_proxies_background(self, gui_elements=None):
        raw_proxies = []
        try:
            raw_proxies = self._fetch_raw_proxies()
            if not raw_proxies:
                logger.warning("Proxy Check: No raw proxies fetched.")
            to_verify_set = set(raw_proxies); 
            to_verify_set.add("")
            to_verify = list(to_verify_set)
            total_to_verify = len(to_verify)
            logger.info(
                f"Proxy Check: Verifying {total_to_verify} potential connection options...")
            if not to_verify:
                logger.error(
                    "Proxy Check: No connection options found to verify.")
                with self.proxies_lock:
                    self.proxies.clear()
                self.first_proxy_available.set()
                if gui_elements and 'root' in gui_elements and gui_elements['root'].winfo_exists():
                    gui_elements['root'].after(
                        0, lambda ge=gui_elements: self._trigger_final_gui_update(ge))
                return
            self._verify_proxies_parallel(to_verify, gui_elements)
            with self.proxies_lock:
                original_count = len(self.proxies)
                if not self.settings.get("use_direct_connection_fallback", True):
                    self.proxies[:] = [
                        p for p in self.proxies if p.get('address') != '']
                    if len(self.proxies) < original_count:
                        logger.info(
                            "Removed Direct Connection as fallback disabled.")
                final_verified_count = sum(
                    1 for p in self.proxies if p.get('status') == 'verified')
                final_total_count = len(self.proxies)
                logger.info(
                    f"Proxy Check: Verification complete. {final_verified_count}/{final_total_count} options working.")
        except Exception as e:
            logger.error(
                f"Proxy Check: Error during loading/verification: {e}", exc_info=True)
        finally:
            if not self.first_proxy_available.is_set():
                with self.proxies_lock:
                    has_verified = any(p.get('status') ==
                                       'verified' for p in self.proxies)
                logger.log(logging.INFO if has_verified else logging.WARNING,
                           f"Proxy Check: Final availability signal set ({'some' if has_verified else 'NO'} verified options).")
                self.first_proxy_available.set()
            self.proxy_load_thread_active.clear()
            logger.debug("Proxy load thread finished.")
            if gui_elements and 'root' in gui_elements and gui_elements['root'].winfo_exists():
                gui_elements['root'].after(
                    100, lambda ge=gui_elements: self._trigger_final_gui_update(ge))

    def _trigger_final_gui_update(self, gui_elements):
        try:
            if (gui_elements and 'gui_instance' in gui_elements and gui_elements['gui_instance'] and
                    hasattr(gui_elements['gui_instance'], 'update_proxy_gui_final') and callable(gui_elements['gui_instance'].update_proxy_gui_final)):
                gui_instance = gui_elements['gui_instance']
                if gui_instance.root.winfo_exists():
                    gui_instance.update_proxy_gui_final()
            else: logger.debug("Skipping final GUI proxy update call: instance/method N/A.")
        except Exception as e:
            logger.error(
                f"Error triggering final GUI proxy update: {e}", exc_info=True)

    @staticmethod
    def _proxy_sort_key(proxy_dict):
        latency = proxy_dict.get('latency')
        status = proxy_dict.get('status'); address = proxy_dict.get('address')
        if address == '':
            return (-1, 0)
        status_order = {'verified': 0, 
                        'checking': 1,
                        'failed': 2}; 
        status_rank = status_order.get(status, 3)
        latency_rank = float('inf')
        if status == 'verified' and latency is not None:
            try:
                latency_rank = float(latency)
            except (ValueError, TypeError): pass
        return (status_rank, latency_rank)

    def _verify_proxies_parallel(self, proxy_list, gui_elements=None):
        total_proxies = len(proxy_list)
        processed_count = 0
        max_threads = min(self.settings.get(
            "proxy_test_threads", 30), total_proxies or 1)
        first_found_signaled = False

        # --- GUI Setup (Conditional) ---
        update_gui_callback = None
        root_ref = None
        _update_progress_display_safe = None # Define variable outside if

        if gui_elements and 'root' in gui_elements and gui_elements['root'].winfo_exists():
            root_ref = gui_elements['root']

            # Define the safe update function only if GUI is valid
            def _update_progress_display_safe_local(p_count, total): # Use local name
                try:
                    if not root_ref or not root_ref.winfo_exists():
                        return
                    pct = int((p_count / total) * 100) if total > 0 else 0
                    status_var = gui_elements.get('status_var')
                    if status_var and hasattr(status_var, 'set'):
                        try:
                            status_var.set(f"Verifying {p_count}/{total} ({pct}%)...")
                        except tk.TclError: pass # Ignore errors if widget destroyed

                    pb = gui_elements.get('progress_bar')
                    if pb and pb.winfo_exists():
                        try:
                            pb.config(value=p_count, maximum=total)
                            # Make sure progress bar is visible if it exists
                            if not pb.winfo_ismapped():
                                # Use grid_configure or pack_configure based on how it was initially placed
                                # Assuming grid was used based on setup_proxy_tab
                                pb.grid()
                        except tk.TclError: pass # Ignore errors if widget destroyed

                    gui_instance = gui_elements.get('gui_instance')
                    # Update treeview periodically or at the end
                    if gui_instance and (p_count % 20 == 0 or p_count == total) \
                            and hasattr(gui_instance, 'update_proxy_treeview') \
                            and callable(gui_instance.update_proxy_treeview):
                        try:
                            gui_instance.update_proxy_treeview()
                        except tk.TclError: pass # Ignore errors if widget destroyed
                except Exception as gui_err:
                    logger.error(f"GUI progress update internal error: {gui_err}", exc_info=True)

            # Assign the defined function to the outer variable
            _update_progress_display_safe = _update_progress_display_safe_local
            update_gui_callback = _update_progress_display_safe # Assign to the callback var used later

            # Schedule initial GUI update (only if GUI is valid)
            root_ref.after(0, lambda p=0, t=total_proxies: update_gui_callback(p, t))

        # --- Verification Execution (Always Runs) ---
        # !!! Moved the 'with' block OUTSIDE the 'if gui_elements...' check !!!
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads, thread_name_prefix='ProxyVerify') as executor:
            future_to_proxy_addr = {
                executor.submit(self._verify_proxy, addr): addr for addr in proxy_list
            }
            for future in concurrent.futures.as_completed(future_to_proxy_addr):
                processed_count += 1
                proxy_addr = future_to_proxy_addr[future]
                proxy_dict_result = None

                try:
                    proxy_dict_result = future.result()
                    if isinstance(proxy_dict_result, dict) and 'address' in proxy_dict_result:
                        # --- Add/Update Result (Thread Safe) ---
                        with self.proxies_lock:
                            existing_index = next(
                                (i for i, p in enumerate(self.proxies) if p['address'] == proxy_dict_result['address']), -1)
                            if existing_index != -1:
                                # Update existing entry
                                self.proxies[existing_index] = proxy_dict_result
                            else:
                                # Append new entry
                                self.proxies.append(proxy_dict_result)
                            # Sort the list after every modification (inside lock)
                            self.proxies.sort(key=self._proxy_sort_key)

                        # --- Signal First Found (If applicable) ---
                        if proxy_dict_result.get('status') == 'verified' and not first_found_signaled:
                            proxy_display = proxy_dict_result['address'] or "Direct Connection"
                            latency_val = proxy_dict_result.get('latency')
                            latency_str = f"Latency: {latency_val:.3f}s" if isinstance(latency_val, float) else ""
                            logger.info(
                                f"First usable connection found: {proxy_display} {latency_str}. Signaling availability.")
                            self.first_proxy_available.set()
                            first_found_signaled = True
                    else:
                        # Handle invalid result format from _verify_proxy
                        logger.error(f"Invalid result from _verify_proxy for {proxy_addr}: {proxy_dict_result}")
                        with self.proxies_lock:
                            failed_proxy = {
                                'address': proxy_addr, 'status': 'failed',
                                'latency': None, 'country': None, 'last_checked': time.time()
                            }
                            # Add failed entry only if it doesn't already exist in the list
                            if not any(p['address'] == proxy_addr for p in self.proxies):
                                self.proxies.append(failed_proxy)
                                # Sort after adding failed entry (inside lock)
                                self.proxies.sort(key=self._proxy_sort_key)

                except Exception as e:
                    # Handle errors getting result from future (e.g., worker raised exception)
                    logger.error(
                        f"Error processing verification result for {proxy_addr}: {e}",
                        exc_info=logger.level == logging.DEBUG
                    )
                    with self.proxies_lock:
                        failed_proxy = {
                            'address': proxy_addr, 'status': 'failed',
                            'latency': None, 'country': None, 'last_checked': time.time()
                        }
                        # Add failed entry only if it doesn't already exist in the list
                        if not any(p['address'] == proxy_addr for p in self.proxies):
                            self.proxies.append(failed_proxy)
                            # Sort after adding failed entry (inside lock)
                            self.proxies.sort(key=self._proxy_sort_key)

                finally:
                    # --- GUI Update within Loop (Conditional) ---
                    # Check if the callback function exists (meaning GUI is valid) and root window exists
                    if update_gui_callback and root_ref and root_ref.winfo_exists():
                        # Schedule the GUI update using the callback
                        root_ref.after(0, lambda p=processed_count, t=total_proxies: update_gui_callback(p, t))

        # --- Final GUI Update (Conditional) ---
        # Check if the callback function exists (meaning GUI is valid) and root window exists
        if update_gui_callback and root_ref and root_ref.winfo_exists():
            # Schedule the final update call (e.g., setting progress to 100%)
            root_ref.after(10, lambda p=total_proxies, t=total_proxies: update_gui_callback(p, t))

        # Now this log message accurately reflects the completion of the loop
        logger.debug("Parallel proxy verification loop completed.")
        
    def _verify_proxy(self, proxy_address):
        test_url =  "https://httpbin.org/ip"
        proxy_dict_req = None
        ip_part = None
        status = "checking"
        latency = None
        country = None
        last_checked = time.time()

        result_dict = {
            'address': proxy_address,
            'status': status,
            'latency': latency,
            'country': country,
            'last_checked': last_checked
        }

        start_time = time.monotonic()

        try:
            if proxy_address == "":
                proxy_display = "Direct Connection"
                country = "Direct"
                proxy_dict_req = None

            elif isinstance(proxy_address, str) and re.match(r"^\d{1,3}(\.\d{1,3}){3}:\d{1,5}$", proxy_address):
                proxy_display = proxy_address
                ip_part = proxy_address.split(':')[0]
                proxy_dict_req = {
                    "http": f"http://{proxy_address}",
                    "https": f"http://{proxy_address}"
                }

            else:
                raise ValueError(f"Invalid proxy format: {proxy_address}")

            if ip_part and self.geoip_reader:
                country = self.get_proxy_country(ip_part)

            response = requests.get(
                test_url,
                proxies=proxy_dict_req,
                timeout=self.settings["proxy_timeout"],
                headers={'User-Agent': random.choice(DESKTOP_USER_AGENTS)},
                allow_redirects=True,
                verify=False
            )

            latency = time.monotonic() - start_time

            if 200 <= response.status_code < 400:
                result_dict['status'] = 'verified'
                result_dict['latency'] = latency
                logger.debug(
                    f"[V] SUCCESS: {proxy_display} (Status: {response.status_code}, Latency: {latency:.3f}s, Country: {country or 'N/A'})"
                )
            else:
                result_dict['status'] = 'failed'
                logger.debug(
                    f"[X] FAIL: {proxy_display} - Bad Status Code: {response.status_code}"
                )

        except ValueError as ve:
            result_dict['status'] = 'failed'
            logger.debug(f"[X] FORMAT ERR: {proxy_display} - {ve}")

        except requests.exceptions.Timeout:
            result_dict['status'] = 'failed'
            latency_on_timeout = time.monotonic() - start_time
            result_dict['latency'] = latency_on_timeout
            logger.debug(
                f"[X] FAIL: {proxy_display} - Timeout ({self.settings['proxy_timeout']}s, actual: {latency_on_timeout:.3f}s)"
            )

        except (requests.exceptions.ProxyError,
                requests.exceptions.ConnectTimeout,
                requests.exceptions.SSLError,
                requests.exceptions.ConnectionError,
                MaxRetryError) as conn_err:
            result_dict['status'] = 'failed'
            logger.debug(
                f"[X] FAIL: {proxy_display} - Connection/Proxy Error: {type(conn_err).__name__}"
            )

        except Exception as e:
            result_dict['status'] = 'failed'
            logger.warning(
                f"Unexpected error verifying {proxy_display}: {e}",
                exc_info=logger.level == logging.DEBUG
            )

        finally:
            result_dict['country'] = country
            result_dict['last_checked'] = time.time()
            return result_dict

    def get_random_proxy_address(self):
        # --- NEW: Check for forced direct connection ---
        if self.settings.get("force_direct_connection"):
            logger.info("Connection mode: Forced Direct. Bypassing proxy selection.")
            return "" # Return empty string to signify direct connection (no proxy)

        # --- Original logic for selecting from verified proxies (if not forced direct) ---
        with self.proxies_lock:
            verified_proxies = [
                p for p in self.proxies if p.get('status') == 'verified']
            
            # If direct connection is available AND fallback is allowed, consider it for random pick
            if self.settings.get("use_direct_connection_fallback", True):
                if "" not in [p.get('address') for p in verified_proxies]: # If direct not already verified, add it manually
                    # This happens if proxies refreshed with fallback disabled and then re-enabled
                    logger.debug("Direct connection not in verified list; adding temporarily for selection.")
                    # Add a temporary 'verified' direct entry so it can be picked if needed.
                    verified_proxies.append({'address': '', 'status': 'verified', 'latency': 0, 'country': 'Direct', 'last_checked': time.time()})

            if verified_proxies:
                selected_proxy_dict = random.choice(verified_proxies)
                addr = selected_proxy_dict['address']
                display_name = addr if addr else "Direct Connection"
                logger.debug(f"Selected random verified proxy: {display_name}")
                return addr # This will return a proxy address or an empty string for direct

        # --- If no verified proxies found and not forcing direct ---
        if self.proxy_load_thread_active.is_set():
            logger.debug("No verified proxies available, waiting briefly for proxy thread to finish...")
            # Wait a bit, in case proxy loading is still in progress
            signaled = self.first_proxy_available.wait(timeout=5.0) 
            if signaled: # If the signal came, re-check the list
                logger.debug("Signal received, re-checking proxy list for selection...")
                # Recursively call self to retry selecting from now (potentially) available proxies
                return self.get_random_proxy_address() 
            else: 
                logger.warning("Timed out waiting for first proxy signal after 5 seconds.")

        # Final fallback: if no working proxies after initial wait/selection and not forced direct.
        # This will be 'None' if use_direct_connection_fallback is OFF AND no other proxies are available.
        if self.settings.get("use_direct_connection_fallback", True):
            # If direct fallback is allowed but not picked yet, use it now as last resort.
            logger.warning("No functional proxy selected, but direct connection fallback is enabled. Using direct connection.")
            return "" # Fallback to direct connection if no working proxy
        else:
            logger.error("Could not get any working proxy address from list and direct connection fallback is disabled. WebDriver setup will fail.")
            return None

    # --- Fetch Raw Proxies & Parsers ---

    def _fetch_raw_proxies(self):
        logger.debug("Fetching raw proxy lists...")
        headers = {
            'User-Agent': random.choice(DESKTOP_USER_AGENTS),
            'Accept': 'text/plain,*/*'
        }

        proxy_sources = {
            'proxyscrape_http': {
                'url': 'https://api.proxyscrape.com/v3/free-proxy-list/get?request=displayproxies&protocol=http&proxy_format=ipport&format=text',
                'parser': self._parse_plain_text
            },
            'geonode': {
                'url': 'https://proxylist.geonode.com/api/proxy-list?limit=150&page=1&sort_by=lastChecked&sort_type=desc&protocols=http%2Chttps',
                'parser': self._parse_geonode
            },
            'free_proxy_list': {
                'url': 'https://free-proxy-list.net/',
                'parser': self._parse_table_proxies_fpl
            },
        }

        all_proxies = set()
        fetch_session = requests.Session()

        retries = requests.adapters.Retry(
            total=2,
            backoff_factor=0.3,
            status_forcelist=[500, 502, 503, 504, 521]
        )

        fetch_session.mount(
            'https://', requests.adapters.HTTPAdapter(max_retries=retries)
        )

        fetch_session.headers.update(headers)
        timeout = 15

        ip_port_pattern = re.compile(
            r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}:\d{1,5}$")

        for source_name, source_info in proxy_sources.items():
            try:
                logger.debug(f"Fetching raw from {source_name}...")

                response = fetch_session.get(
                    source_info['url'],
                    timeout=timeout,
                    proxies=None,
                    verify=False
                )
                response.raise_for_status()

                content = response.text
                parsed_proxies = source_info['parser'](content)
                valid_format_proxies = {
                    p for p in parsed_proxies if ip_port_pattern.match(p)
                }

                count = len(valid_format_proxies)
                if count > 0:
                    logger.debug(
                        f"Got {count} valid proxies from {source_name}")
                    all_proxies.update(valid_format_proxies)
                else:
                    logger.debug(f"No valid proxies from {source_name}")

            except requests.exceptions.RequestException as e:
                level = logging.WARNING if isinstance(
                    e, (requests.exceptions.Timeout,
                        requests.exceptions.ConnectionError)
                ) else logging.ERROR
                logger.log(
                    level, f"Network/HTTP error fetching raw from {source_name}: {e}"
                )

            except Exception as e:
                logger.error(
                    f"Error processing source {source_name}: {e}",
                    exc_info=logger.level == logging.DEBUG
                )

            time.sleep(random.uniform(0.2, 0.5))

        fetch_session.close()
        logger.info(
            f"Fetched {len(all_proxies)} total unique potential proxies."
        )
        return list(all_proxies)


    @staticmethod
    def _parse_plain_text(text_content):
        return [line.strip() for line in text_content.strip().splitlines() if ':' in line.strip()]

    @staticmethod
    def _parse_geonode(json_text):
        proxies = set()
        try:
            data = json.loads(json_text)
            for p in data.get('data', []):
                if p.get('ip') and p.get('port') and any(proto in ['http', 'https'] for proto in p.get('protocols', [])):
                    proxies.add(f"{p['ip']}:{p['port']}")
        except Exception as e: logger.error(f"Error parsing geonode JSON: {e}")
        return list(proxies)

    @staticmethod
    def _parse_table_proxies_fpl(html_content):
        proxies = set()
        pattern = re.compile(
            r"<tr>\s*<td>((?:\d{1,3}\.){3}\d{1,3})</td>\s*<td>(\d{1,5})</td>", re.IGNORECASE)
        for ip, port in pattern.findall(html_content):
            try:
                if all(0 <= int(x) <= 255 for x in ip.split('.')) and 1 <= int(port) <= 65535:
                    proxies.add(f"{ip}:{port}")
            except ValueError: continue
        logger.debug(f"_parse_table_proxies_fpl found {len(proxies)}.")
        return list(proxies)
    # NEW METHOD 
    def _get_installed_chrome_version_on_os(self):
        """
        Attempts to find the installed Chrome browser version using platform-specific commands.
        Returns the version string (e.g., "120.0.6099.71") or None if not found.
        """
        chrome_path_env = os.environ.get('CHROME_BINARY_LOCATION') # Check env var first
        chrome_binary_candidates = []

        system = platform.system().lower()
        if system == "windows":
            program_files = os.environ.get('ProgramFiles')
            program_files_x86 = os.environ.get('ProgramFiles(x86)')
            local_app_data = os.environ.get('LocalAppData')
            if chrome_path_env:
                chrome_binary_candidates.append(chrome_path_env)
            if program_files_x86: # Prioritize 64-bit for x64 systems, but check x86 too
                chrome_binary_candidates.append(os.path.join(program_files_x86, "Google", "Chrome", "Application", "chrome.exe"))
            if program_files: # Check ProgramFiles too for 64-bit Chrome
                chrome_binary_candidates.append(os.path.join(program_files, "Google", "Chrome", "Application", "chrome.exe"))
            if local_app_data:
                chrome_binary_candidates.append(os.path.join(local_app_data, "Google", "Chrome", "Application", "chrome.exe"))
            # Custom path from settings (user preference)
            custom_binary_path = self.settings.get("chrome_binary_path", "").strip()
            if custom_binary_path and Path(custom_binary_path).is_file():
                chrome_binary_candidates.append(custom_binary_path)

        elif system == "darwin": # macOS
            if chrome_path_env:
                chrome_binary_candidates.append(chrome_path_env)
            chrome_binary_candidates.append("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")
            chrome_binary_candidates.append(os.path.expanduser("~/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"))
            custom_binary_path = self.settings.get("chrome_binary_path", "").strip()
            if custom_binary_path and Path(custom_binary_path).is_file():
                chrome_binary_candidates.append(custom_binary_path)

        elif system == "linux":
            if chrome_path_env:
                chrome_binary_candidates.append(chrome_path_env)
            chrome_binary_candidates.extend(["google-chrome", "google-chrome-stable", "google-chrome-beta", "google-chrome-dev", "chromium-browser", "chromium"])
            custom_binary_path = self.settings.get("chrome_binary_path", "").strip()
            if custom_binary_path and Path(custom_binary_path).is_file():
                chrome_binary_candidates.append(custom_binary_path)
        else:
            logger.warning(f"Unsupported OS '{system}' for Chrome version detection.")
            return None

        # Try to find and get version from candidate paths
        for chrome_path in reversed(chrome_binary_candidates): # Prioritize custom/standard paths
            if not chrome_path: continue
            try:
                # If it's just a command name (linux), try to execute directly
                if system == "linux" and not Path(chrome_path).is_file():
                    cmd = [chrome_path, "--version"]
                else:
                    if not Path(chrome_path).is_file():
                        continue # Skip if it's an actual path that doesn't exist

                    cmd = [chrome_path, "--version"]
                
                logger.debug(f"Attempting to get Chrome version via: {cmd}")
                
                import subprocess
                result = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=5)
                
                if result.returncode == 0:
                    version_output = result.stdout.strip()
                    # Example: "Google Chrome 120.0.6099.71 " or "Chromium 120.0.6099.71 Ubuntu"
                    match = re.search(r'(\d+\.\d+\.\d+\.\d+)', version_output)
                    if match:
                        version = match.group(1)
                        logger.info(f"Detected Chrome version: {version} from '{chrome_path}'")
                        return version
                else:
                    logger.debug(f"Failed to get version from '{chrome_path}': {result.stderr.strip()}")

            except FileNotFoundError:
                logger.debug(f"Chrome executable not found at '{chrome_path}'.")
            except subprocess.TimeoutExpired:
                logger.debug(f"Timeout expired while getting Chrome version from '{chrome_path}'.")
            except Exception as e:
                logger.warning(f"Error checking Chrome version from '{chrome_path}': {e}", exc_info=logger.level == logging.DEBUG)

        logger.warning("Could not automatically detect installed Chrome browser version.")
        return None
    # --- NEW Helper Method for downloading/extracting zip assets ---
    def _download_and_extract_zip_asset(self, url, target_base_dir: Path, specific_asset_dir_name: str,
                                        asset_name_in_zip_primary: str, asset_name_in_zip_secondary: str = None,
                                        log_prefix_override=None):
       
        _log_prefix = log_prefix_override or "[AssetDownloader] "
        final_asset_dir = Path(target_base_dir) / specific_asset_dir_name
        
        # Determine the expected executable name based on OS
        exe_suffix = ".exe" if platform.system().lower() == "windows" else ""
        expected_exe_name_full = asset_name_in_zip_primary + exe_suffix
        final_exe_path = final_asset_dir / expected_exe_name_full

        if final_exe_path.is_file() and final_exe_path.exists():
            logger.info(f"{_log_prefix}Cached asset '{expected_exe_name_full}' found at {final_exe_path}")
            return str(final_exe_path)

        # Create the specific asset's target directory (e.g., chromedriver_120.0.0.0/)
        final_asset_dir.mkdir(parents=True, exist_ok=True) 

        # Create a temporary extraction directory (e.g., .../temp_UUID/)
        temp_extract_base = final_asset_dir.parent / f"temp_extract_{uuid.uuid4().hex[:8]}"
        temp_extract_base.mkdir(parents=True, exist_ok=True)
        
        extracted_exe_temp_path = None

        try:
            logger.info(f"{_log_prefix}Downloading '{specific_asset_dir_name}' from {url}...")
            response = requests.get(url, stream=True, timeout=300) # 5 min timeout for large files
            response.raise_for_status()

            logger.debug(f"{_log_prefix}Extracting to temporary location: {temp_extract_base}")
            with zipfile.ZipFile(io.BytesIO(response.content)) as zf:
                namelist = zf.namelist()
                
                # Try to find the exact primary executable name
                target_zip_entry_name = None
                for name in namelist:
                    if name.endswith(expected_exe_name_full): # Matches full path including / or nested dir structure
                        target_zip_entry_name = name
                        break

                # If primary not found, try secondary asset name (if provided)
                if not target_zip_entry_name and asset_name_in_zip_secondary:
                    expected_exe_name_secondary = asset_name_in_zip_secondary + exe_suffix
                    for name in namelist:
                        if name.endswith(expected_exe_name_secondary):
                            target_zip_entry_name = name
                            break
                
                if not target_zip_entry_name:
                    # Fallback: if not found, find common top-level folders, take first actual file
                    relevant_names = [n for n in namelist if not n.startswith('__MACOSX') and not n.endswith('/')]
                    if relevant_names:
                        target_zip_entry_name = relevant_names[0]
                        logger.warning(f"{_log_prefix}Could not find specific asset name, using first likely file: '{target_zip_entry_name}'.")
                    else:
                        raise ValueError("No executable/relevant file found in zip for extraction.")

                # Extract the found entry
                extracted_file_path = zf.extract(target_zip_entry_name, temp_extract_base)
                logger.debug(f"{_log_prefix}Extracted: {extracted_file_path}")
                extracted_exe_temp_path = Path(extracted_file_path)

            # Move the extracted file to its final, versioned location
            # (ensure file has appropriate permissions)
            if extracted_exe_temp_path and extracted_exe_temp_path.is_file():
                if expected_exe_name_full in extracted_exe_temp_path.name or not final_exe_path.exists(): # Don't overwrite if filename differs but exists
                    shutil.move(extracted_exe_temp_path, final_exe_path)
                    logger.info(f"{_log_prefix}Asset moved to final location: {final_exe_path}")

                    # Make it executable on non-Windows systems
                    if platform.system().lower() != "windows":
                        import os
                        os.chmod(final_exe_path, 0o755) # rwxr-xr-x
                        logger.debug(f"{_log_prefix}Made executable: {final_exe_path}")
                    return str(final_exe_path)
                else:
                     raise ValueError(f"Final destination file '{final_exe_path.name}' already exists in '{final_asset_dir.name}' from a different extraction or path. Clean up required.")
            else:
                 raise ValueError("Extracted file not found or invalid after extraction.")

        except requests.RequestException as e:
            logger.error(f"{_log_prefix}Network error during download from {url}: {e}")
        except zipfile.BadZipFile:
            logger.error(f"{_log_prefix}Downloaded file is a bad ZIP archive from {url}.")
        except Exception as e:
            logger.error(f"{_log_prefix}Unexpected error during download/extraction: {e}")
        finally:
            # Clean up temporary extraction directory regardless of success/failure
            if temp_extract_base.exists():
                logger.debug(f"{_log_prefix}Cleaning up temporary extraction directory: {temp_extract_base}")
                shutil.rmtree(temp_extract_base)
            elif extracted_exe_temp_path and extracted_exe_temp_path.exists(): # If move failed, temp path might still be file
                 try: os.remove(extracted_exe_temp_path)
                 except: pass

        return None

    # --- NEW Method for getting ChromeDriver path via JSON endpoint ---
    
    def _get_driver_path_via_json_endpoint(self, selection_mode="latest_compatible", preferred_version_major_minor_build=None):
        """
        Fetches ChromeDriver download information from the Chrome for Testing JSON endpoint and handles selection logic.
        Args:
            selection_mode (str): 
                'latest_compatible': Tries to find the latest compatible driver for the installed Chrome.
                'manual_select': (Requires GUI callback) Triggers user selection from a list of versions.
                    If GUI not available or selection cancelled, it will default to latest available from list.
            preferred_version_major_minor_build (str, optional): For 'latest_compatible' or internal testing.
                e.g., "120.0.6099" to match against specific installed Chrome.

        Returns:
            str or None: Path to the downloaded and extracted ChromeDriver executable, or None on failure.
        """
        log_prefix = "[CfT-Acquisition] "
        logger.info(f"{log_prefix}Initiating ChromeDriver acquisition from Chrome for Testing (Mode: {selection_mode}).")
        CFT_JSON_URL = "https://googlechromelabs.github.io/chrome-for-testing/known-good-versions-with-downloads.json"
        
        try:
            response = requests.get(CFT_JSON_URL, timeout=20)
            response.raise_for_status()
            data = response.json()
            logger.debug(f"{log_prefix}Successfully fetched CfT JSON data from {CFT_JSON_URL}.")
        except requests.RequestException as e:
            logger.error(f"{log_prefix}Failed to fetch CfT JSON: {e}")
            return None
        except json.JSONDecodeError as e:
            logger.error(f"{log_prefix}Failed to parse CfT JSON: {e}")
            return None

        versions_data = data.get("versions", [])
        if not versions_data:
            logger.error(f"{log_prefix}No 'versions' array found in CfT JSON.")
            return None

        system = platform.system().lower()
        arch = platform.machine().lower()
        if system == "windows": os_platform_key = "win64"
        elif system == "darwin": os_platform_key = "mac-arm64" if "arm" in arch or arch == "aarch64" else "mac-x64"
        elif system == "linux": os_platform_key = "linux64"
        else: logger.error(f"{log_prefix}Unsupported OS for CfT downloads: {system}"); return None
        logger.debug(f"{log_prefix}Target OS platform key for ChromeDriver: {os_platform_key}")

        available_drivers_full_info = [] # Contains dicts with version_entry_from_json, url, etc.
        for version_entry in versions_data:
            full_version_str = version_entry.get("version") # Full version string (e.g., 120.0.6099.71)
            if not full_version_str: continue

            downloads_info = version_entry.get("downloads", {})
            chromedriver_downloads = downloads_info.get("chromedriver", [])

            for driver_download_spec in chromedriver_downloads:
                if driver_download_spec.get("platform") == os_platform_key:
                    available_drivers_full_info.append({
                        "version": full_version_str,
                        "url": driver_download_spec.get("url"),
                        "revision": version_entry.get("revision") # Potentially useful for logging/display
                    })
                    break # Only need one URL per full version for our platform

        if not available_drivers_full_info:
            logger.error(f"{log_prefix}No ChromeDriver URLs found for '{os_platform_key}'.")
            return None
        
        # Sort by version (latest first) to ensure consistent 'latest' choice and presentation
        available_drivers_full_info.sort(key=lambda x: [int(part) for part in x['version'].split('.')], reverse=True)

        selected_driver_download_url = None
        target_version_display = None # To display which version was ultimately chosen

        if selection_mode == "latest_compatible":
            # *** This is the key updated section ***
            current_installed_chrome_version = self._get_installed_chrome_version_on_os()
            if not current_installed_chrome_version:
                logger.warning(f"{log_prefix}Could not detect installed Chrome browser version for 'latest_compatible' logic.")
            
            if current_installed_chrome_version:
                logger.info(f"{log_prefix}Installed Chrome: v{current_installed_chrome_version}. Searching compatible ChromeDriver...")
                installed_chrome_major_minor_build = '.'.join(current_installed_chrome_version.split('.')[:3])
                
                # Prioritize a driver whose MAJOR.MINOR.BUILD matches.
                found_compatible = False
                for driver_info in available_drivers_full_info:
                    driver_milestone = '.'.join(driver_info['version'].split('.')[:3])
                    if driver_milestone == installed_chrome_major_minor_build:
                        selected_driver_download_url = driver_info['url']
                        target_version_display = driver_info['version']
                        logger.info(f"{log_prefix}Auto-selected CfT ChromeDriver v{target_version_display} for matching Chrome v{installed_chrome_major_minor_build}.")
                        found_compatible = True
                        break
                
                # If no precise build match, take the latest whose MAJOR version matches
                if not found_compatible:
                    installed_chrome_major = current_installed_chrome_version.split('.')[0]
                    for driver_info in available_drivers_full_info:
                        if driver_info['version'].split('.')[0] == installed_chrome_major:
                            selected_driver_download_url = driver_info['url']
                            target_version_display = driver_info['version']
                            logger.info(f"{log_prefix}Auto-selected CfT ChromeDriver v{target_version_display} (latest major match) for Chrome v{installed_chrome_major}.")
                            found_compatible = True
                            break

                if not found_compatible:
                    logger.warning(f"{log_prefix}No perfectly compatible ChromeDriver found for Chrome v{current_installed_chrome_version}. Falling back to absolute latest from JSON list (may be incompatible).")
                    selected_driver_download_url = available_drivers_full_info[0]['url']
                    target_version_display = available_drivers_full_info[0]['version']
            else:
                logger.warning(f"{log_prefix}Could not detect installed Chrome version, defaulting to latest ChromeDriver found in JSON.")
                selected_driver_download_url = available_drivers_full_info[0]['url']
                target_version_display = available_drivers_full_info[0]['version']


        elif selection_mode == "manual_select":
            if not self.gui or not hasattr(self.gui, 'root') or not self.gui.root.winfo_exists():
                logger.error(f"{log_prefix}'manual_select' mode requires GUI, but GUI is not available. Cannot prompt user.")
                # If GUI is not available for manual selection, automatically fall back to latest for headless/CLI.
                selected_driver_download_url = available_drivers_full_info[0]['url']
                target_version_display = available_drivers_full_info[0]['version']
                logger.warning(f"{log_prefix}GUI not available for manual selection. Auto-selecting latest CfT ChromeDriver v{target_version_display}.")
            else:
                # GUI specific selection process (pseudo-code)
                driver_version_strings = [f"v{d['version']} (Revision: {d['revision']})" for d in available_drivers_full_info]
                
                # This calls a method in the GUI class that YOU will need to implement
                # to show a dialog/listbox for selection.
                # Example: `self.gui.show_driver_selection_dialog(driver_version_strings)`
                selected_index = self.gui.prompt_user_for_cfd_driver_selection(driver_version_strings) # Replace with your actual GUI method name
                
                if selected_index is not None and 0 <= selected_index < len(available_drivers_full_info):
                    selected_driver_download_url = available_drivers_full_info[selected_index]['url']
                    target_version_display = available_drivers_full_info[selected_index]['version']
                    logger.info(f"{log_prefix}User manually selected CfT ChromeDriver v{target_version_display}.")
                else:
                    logger.info(f"{log_prefix}Manual selection cancelled by user or invalid choice. Returning None.")
                    return None

        if not selected_driver_download_url:
            logger.error(f"{log_prefix}No valid ChromeDriver download URL could be determined via JSON endpoint.")
            return None
        
        # Determine the directory where this specific ChromeDriver version will be stored
        # within our managed_drivers folder (e.g., /logs/managed_drivers/chromedriver_120.0.6099.71)
        managed_driver_sub_dir = f"chromedriver_{target_version_display.replace('.', '_')}"
        
        # Call the generic download and extract helper
        driver_path = self._download_and_extract_zip_asset(
            url=selected_driver_download_url,
            target_base_dir=LOG_DIR / "managed_drivers",
            specific_asset_dir_name=managed_driver_sub_dir,
            asset_name_in_zip_primary="chromedriver",
            log_prefix_override=f"{log_prefix}Download v{target_version_display}"
        )
        return driver_path
    # --- WebDriver Setup (FIXED capabilities) ---

    def _setup_driver_common(self, is_worker=False, unique_profile_name=None):
        """
        Sets up Chrome WebDriver options and service with a strict, predictable
        driver acquisition hierarchy:
        1. Manual Path (if valid)
        2. Cached Driver (matching installed Chrome)
        3. Download from CfT Endpoint (matching installed Chrome)

        Args:
            is_worker (bool): True if setting up for a worker thread (forces headless).
            unique_profile_name (str): A unique name for the user data directory.

        Returns:
            tuple: (ChromeOptions, ChromeService, driver_path_used_string) or (None, None, None) on failure.
        """
        log_prefix = "Worker: " if is_worker else ""
        headless_mode = self.settings.get("headless", True) if not is_worker else True
        
        options = ChromeOptions()
        # --- Setting up common Chrome options (condensed for brevity) ---
        options.add_argument("--disable-blink-features=AutomationControlled")
        options.add_experimental_option("excludeSwitches", ["enable-automation", "enable-logging"])
        options.add_experimental_option('useAutomationExtension', False)
        options.add_argument('--no-sandbox')
        options.add_argument('--disable-dev-shm-usage')
        options.add_argument('--disable-gpu')
        options.add_argument('--log-level=3')
        options.add_argument("--disable-extensions")
        options.add_argument("--disable-popup-blocking")
        options.add_argument("--start-maximized")
        options.add_argument("--window-size=1920,1080")
        if headless_mode:
            options.add_argument("--headless=new")
        else:
            options.add_argument(f"--window-position={random.randint(50, 200)},{random.randint(50, 200)}")
            if not self.settings.get("use_persistent_browser_profiles", False):
                options.add_argument("--incognito")
        if self.settings.get("use_persistent_browser_profiles", False) and unique_profile_name:
            profile_path = LOG_DIR / "browser_profiles" / unique_profile_name
            profile_path.mkdir(parents=True, exist_ok=True)
            options.add_argument(f"--user-data-dir={profile_path.resolve()}")
        # --- End of common options setup ---

        logging_prefs = {'performance': 'ALL', 'browser': 'ALL', 'driver': 'ALL'}
        options.set_capability('goog:loggingPrefs', logging_prefs)

        chrome_binary = self.settings.get("chrome_binary_path", "").strip()
        if chrome_binary and Path(chrome_binary).is_file():
            options.binary_location = chrome_binary
            logger.debug(f"{log_prefix}Using custom Chrome binary: {chrome_binary}")
        elif chrome_binary:
            logger.warning(f"{log_prefix}Custom Chrome binary path is invalid: '{chrome_binary}'.")

        # --- REVOLUTIONIZED DRIVER ACQUISITION LOGIC ---
        service = None
        driver_path_used = "N/A"
        driver_acquisition_strategy = "None"
        service_args = ['--log-level=OFF']

        # --- Priority 1: User-Defined Manual Path (KING) ---
        manual_driver_path_str = self.settings.get("chrome_driver_path", "").strip()
        if manual_driver_path_str:
            manual_driver_path = Path(manual_driver_path_str)
            if manual_driver_path.is_file():
                logger.info(f"{log_prefix}Strategy 1: Using user-provided manual ChromeDriver path: {manual_driver_path}")
                try:
                    service = ChromeService(executable_path=str(manual_driver_path), service_args=service_args)
                    driver_path_used = str(manual_driver_path)
                    driver_acquisition_strategy = "Manual Path"
                    logger.info(f"{log_prefix}Successfully created service with manual driver.")
                except Exception as e:
                    logger.error(f"{log_prefix}Failed to create service with manual driver path '{manual_driver_path}': {e}. NO FALLBACK WILL BE ATTEMPTED.")
                    return None, None, None
            else:
                logger.error(f"{log_prefix}Manual ChromeDriver path was specified ('{manual_driver_path_str}') but is NOT a valid file. Please correct the path. NO FALLBACK WILL BE ATTEMPTED.")
                return None, None, None

        # --- Priority 2: Automated Acquisition (Cache -> Download) ---
        if not service:
            logger.info(f"{log_prefix}Manual path not provided. Attempting automated driver acquisition...")
            
            detected_version = self._get_installed_chrome_version_on_os()
            
            if detected_version:
                logger.info(f"[{log_prefix}] Detected installed Chrome Version: {detected_version}")
                sanitized_version_dir = f"chromedriver_{detected_version.replace('.', '_')}"
                exe_name = "chromedriver.exe" if platform.system().lower() == "windows" else "chromedriver"
                cached_driver_path = LOG_DIR / "managed_drivers" / sanitized_version_dir / exe_name

                if cached_driver_path.is_file():
                    logger.info(f"[{log_prefix}] Strategy 2a: Found compatible cached driver for Chrome {detected_version} at: {cached_driver_path}")
                    try:
                        service = ChromeService(executable_path=str(cached_driver_path), service_args=service_args)
                        driver_path_used = str(cached_driver_path)
                        driver_acquisition_strategy = "Cached Driver"
                    except Exception as e:
                        logger.warning(f"[{log_prefix}] Found cached driver, but failed to create service with it: {e}. Proceeding to download.")
                        service = None
            else:
                logger.warning(f"[{log_prefix}] Could not auto-detect installed Chrome version. Will attempt to download the LATEST available driver from CfT, which may mismatch.")

            if not service:
                logger.info(f"[{log_prefix}] Strategy 2c: No compatible cached driver. Attempting download via Chrome for Testing (CfT) JSON endpoint.")
                try:
                    downloaded_path = self._get_driver_path_via_json_endpoint(selection_mode="latest_compatible")

                    if downloaded_path and Path(downloaded_path).is_file():
                        service = ChromeService(executable_path=downloaded_path, service_args=service_args)
                        driver_path_used = downloaded_path
                        driver_acquisition_strategy = "Downloaded from CfT"
                    else:
                        logger.error(f"[{log_prefix}] Download via CfT did not yield a valid driver file path (Path: {downloaded_path}).")
                except Exception as cft_error:
                    # FIX IS HERE: Changed user_context_for_log to log_prefix
                    logger.error(f"[{log_prefix}] Error during CfT download process: {cft_error}", exc_info=True)

        # --- Final Verification and Return ---
        if not service:
            logger.critical(f"{log_prefix}CRITICAL FAILURE: ALL ChromeDriver acquisition strategies failed. Unable to create WebDriver Service.")
            if getattr(self, 'gui', None):
                messagebox.showerror("Fatal Driver Error", "Could not find or download a valid ChromeDriver. Please provide a correct manual path in Settings, or check your internet connection and Chrome installation.")
            return None, None, None

        logger.info(f"{log_prefix}WebDriver Service configured successfully via '{driver_acquisition_strategy}'. Path: '{driver_path_used}'.")
        return options, service, driver_path_used

    def _setup_driver(self):
        """
        Sets up the main Selenium WebDriver instance with enhanced stealth,
        dynamic proxy selection, and proper error handling for session stability.
        Ensures all settings are read directly from self.settings for correct scope.
        """
        if self.driver:
            logger.warning(
                "Closing existing main WebDriver before creating new one.")
            self.close_driver()

        logger.debug("Setting up main WebDriver...")

        selected_proxy = self.get_random_proxy_address()
        if selected_proxy is None:
            logger.error(
                "Main WebDriver setup failed: No usable connection (proxy or direct) available.")
            return None

        profile_name = f"main_ig_profile_{int(time.time())}_{random.randint(1000, 9999)}" \
            if self.settings.get("use_persistent_browser_profiles", False) else None

        options, service, driver_path_used = self._setup_driver_common(
            is_worker=False,
            unique_profile_name=profile_name
        )
        if options is None:
            logger.critical(
                "Main WebDriver setup failed: Common driver setup returned None options.")
            return None

        # --- CRITICAL FIX: ENSURE UA FROM __INIT__ IS USED AND NO RANDOM RE-ASSIGNMENT ---
        options.add_argument(f"user-agent={self.current_user_agent}")
        logger.debug(
            f"User Agent for this session: {self.current_user_agent}")
        # --- END CRITICAL FIX ---

        proxy_display = selected_proxy if selected_proxy else "Direct Connection"
        if selected_proxy:
            options.add_argument(f"--proxy-server=http://{selected_proxy}")
        else:
            logger.debug(
                f"Direct connection being used for main WebDriver, no proxy argument added.")

        logger.info(
            f"Setting up main Chrome WebDriver (Headless: {self.settings.get('headless', True)}, Connection: {proxy_display})...")
        logger.debug(f"  Browser path used: {driver_path_used}")

        driver_instance = None
        timeout_start = time.monotonic()
        try:
            logger.debug(
                "Initializing main WebDriver instance for this session...")
            driver_instance = webdriver.Chrome(
                service=service, options=options)
            instantiation_duration = time.monotonic() - timeout_start
            logger.debug(
                f"Main WebDriver instance created in {instantiation_duration:.2f}s.")

            # This block below applies selenium_stealth and should be skipped based on GUI settings.
            # Your GUI setting 'enable_stealth: False' should already disable this.
            # No changes needed here, just contextual reminder if you enable/disable via GUI.
            if self.settings.get("enable_stealth", True):
                stealth_start = time.monotonic()
                logger.debug(
                    "Applying Selenium Stealth to main driver for anti-detection measures.")
                try:
                    stealth(driver_instance,
                            languages=["en-US", "en"],
                            vendor="Google Inc.",
                            platform="Win32",
                            webgl_vendor="Intel Inc.",
                            renderer="Intel Iris OpenGL Engine",
                            fix_hairline=True)
                    logger.debug(
                        f"Stealth applied successfully in {time.monotonic() - stealth_start:.2f}s.")
                except Exception as stealth_err:
                    logger.warning(
                        f"Error applying Selenium Stealth: {stealth_err}. Proceeding without full stealth.")
            else:
                logger.debug("Selenium Stealth is disabled as per settings.")

            self.driver = driver_instance
            self.current_account = None
            self.current_proxy_address = selected_proxy

            setup_duration = time.monotonic() - timeout_start
            logger.info(
                f"Main WebDriver setup successful. Total time: {setup_duration:.2f}s. Driver ready.")
            return self.driver

        except SessionNotCreatedException as e:
            logger.critical(
                f"WebDriver Session Creation FAILED: {e}. ChromeDriver version likely mismatches Chrome browser version. Please check ChromeDriver updates or installed Chrome.", exc_info=True)
            self.current_proxy_address = None
            # Note: Do NOT reset self.current_user_agent here as it's set in __init__
            self.close_driver()
            return None

        except WebDriverException as e:
            err_str = str(e).lower()
            if any(msg in err_str for msg in ["proxy", "connection refused", "net::err_", "timeout", "dns_probe", "unreachable", "err_empty_response"]):
                logger.error(
                    f"WebDriver connection/proxy FAILED during setup for '{proxy_display}'. Error: {type(e).__name__} - {e}.")
                if selected_proxy and selected_proxy != "":
                    with self.proxies_lock:
                        for p in self.proxies:
                            if p['address'] == selected_proxy:
                                p['status'] = 'failed'
                                p['last_checked'] = time.time()
                                logger.info(
                                    f"Proxy '{selected_proxy}' marked as 'failed' due to WebDriver connection issue.")
                                break
            else:
                logger.error(
                    f"General WebDriver setup error: {e}", exc_info=True)

            self.current_proxy_address = None
            # Note: Do NOT reset self.current_user_agent here as it's set in __init__
            self.close_driver()
            return None

        except Exception as e:
            logger.critical(
                f"Unexpected critical error during main WebDriver setup: {e}.", exc_info=True)
            self.current_proxy_address = None
            # Note: Do NOT reset self.current_user_agent here as it's set in __init__
            self.close_driver()
            return None

    def _setup_driver_for_worker(self):
        """Sets up an ISOLATED WebDriver instance for a worker thread."""
        logger.debug("Worker: Setting up isolated WebDriver...")
        # Get proxy - workers need connections too
        worker_proxy = self.get_random_proxy_address()
        if worker_proxy is None and not self.settings.get("use_direct_connection_fallback"):
            logger.error(
                "Worker WebDriver setup failed: No usable proxy and fallback disabled.")
            return None

        # --- CRITICAL FIX: ENSURE UA FROM __INIT__ IS USED AND NO RANDOM RE-ASSIGNMENT ---
        # Worker should use the global chosen desktop UA
        worker_ua = self.current_user_agent
        # --- END CRITICAL FIX ---

        proxy_display = worker_proxy if worker_proxy else "Direct Connection"

        options, service, driver_path_used = self._setup_driver_common(
            is_worker=True)
        if options is None:
            return None  # Common setup failed

        # Add worker-specific options
        options.add_argument(f"user-agent={worker_ua}")
        proxy_arg = f"--proxy-server=http://{worker_proxy}" if worker_proxy else None
        if proxy_arg:
            options.add_argument(proxy_arg)

        logger.debug(
            f"Worker setup (Headless: True, Connection: {proxy_display}) using UA: {worker_ua}")

        driver_instance = None
        timeout_start = time.monotonic()
        try:
            logger.debug(
                f"Worker initializing WebDriver using driver: {driver_path_used}")
            driver_instance = webdriver.Chrome(
                service=service, options=options)
            logger.debug(
                f"Worker WebDriver instance created in {time.monotonic() - timeout_start:.2f}s")

            # This block below applies selenium_stealth and should be skipped based on GUI settings.
            if self.settings.get("enable_stealth", True):
                try:
                    stealth(driver_instance,
                            languages=["en-US", "en"],
                            vendor="Google Inc.",
                            platform="Win32",
                            webgl_vendor="Intel Inc.",
                            renderer="Intel Iris OpenGL Engine",
                            fix_hairline=True)
                except Exception as stealth_err:
                    logger.warning(
                        f"Worker stealth apply error: {stealth_err}")

            return driver_instance  # Return the isolated instance

        except Exception as e:
            logger.error(f"Worker WebDriver setup failed: {type(e).__name__} - {e}",
                         exc_info=logger.level == logging.DEBUG)
            if driver_instance:
                 try:
                     driver_instance.quit()
                 except:
                     pass
            return None

    # --- Account Handling ---
    @staticmethod
    def generate_password(length=18): # Increased default length for "powerful"
        # Minimum complexity requirements
        if length < 16: # Enforce a minimum length for true power
            logger.warning(f"Password length adjusted from {length} to 16 for enhanced security.")
            length = 16

        # Define character sets for full diversity
        lowercase_chars = string.ascii_lowercase
        uppercase_chars = string.ascii_uppercase
        digit_chars = string.digits
        symbol_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?" # Common and widely accepted symbols

        all_chars = lowercase_chars + uppercase_chars + digit_chars + symbol_chars

        while True:
            password = []
            # Guarantee at least one character from each set for strong passwords
            password.append(random.choice(lowercase_chars))
            password.append(random.choice(uppercase_chars))
            password.append(random.choice(digit_chars))
            password.append(random.choice(symbol_chars))

            # Fill the rest of the password length with random characters from all sets
            for _ in range(length - 4): # -4 because 4 characters are already guaranteed
                password.append(random.choice(all_chars))

            # Shuffle the password list to randomize the position of required characters
            random.shuffle(password)
            final_password = "".join(password)

            # Re-verify the generated password adheres to conditions, though guaranteed by construction.
            # This is a belt-and-braces check for paranoia-grade security.
            if (any(c.islower() for c in final_password)
                    and any(c.isupper() for c in final_password)
                    and any(c.isdigit() for c in final_password)
                    and any(c in symbol_chars for c in final_password)):
                logger.debug(f"Generated powerful password of length {length}.")
                return final_password

    def generate_username(self, max_attempts=30): # Increased max_attempts slightly
        logger.debug("Generating username...")
        
        # Ensure self.fake is initialized in EnhancedInstagramManager's __init__
        if not hasattr(self, 'fake'): # Fallback/safety if not initialized externally.
           
            self.fake = Faker()
            logger.warning("Faker was not initialized in __init__, initializing dynamically in generate_username.")

        # Robust Faker-based word/name generation (ensuring non-empty/alphabetic)
        def get_safe_faker_word(min_len=3):
            for _ in range(5):
                word = self.fake.word().lower()
                if len(word) >= min_len and word.isalpha(): return word
            return random.choice(["digital", "smart", "tech", "vista", "synth"])

        def get_safe_faker_name_part(name_type="first_name", min_len=3):
            for _ in range(5):
                part = getattr(self.fake, name_type)().lower()
                if len(part) >= min_len and part.isalpha(): return part
            return random.choice(["user", "creator", "artist", "travlr"])

        # Diverse generation patterns to make usernames seem less "bot-like"
        patterns = [
            lambda: f"{get_safe_faker_name_part()}{random.randint(100, 9999)}",          # firstname1234
            lambda: f"{get_safe_faker_word()}{random.choice(['_', ''])}{get_safe_faker_word(min_len=2)}{random.randint(10, 99)}", # word_wor88
            lambda: f"{get_safe_faker_name_part()}_{random.choice(['official', 'live', 'gaming', 'dev', 'art'])}{random.randint(1,999)}", # firstname_official123
            lambda: f"{get_safe_faker_name_part(name_type='last_name')}{get_safe_faker_name_part()}{random.randint(1,99)}", # lastnamefirstname99
            lambda: f"{self.fake.user_name().replace('.', '_').replace('-', '')}{random.choice(['_v', 'hq', 'x', 'z'])}", # fakerusername_x
            lambda: f"{get_safe_faker_word(min_len=4)}{str(random.randint(1,9))}", # wordxyz8
            lambda: f"{get_safe_faker_name_part()}{random.choice(['pic', 'gram', 'shots'])}{random.randint(1, 50)}",
            lambda: f"{get_safe_faker_word()}{self.fake.word()[:random.randint(1,3)]}{random.randint(1,99)}", # ex. worldtrv65
        ]

        # Use our rich custom lists for more thematic usernames, blending with Faker.
        prefixes_local = ["the_real_", "official_", "just_", "its_", "mega_", "ultra_", "super_", "best_"]
        nouns_local = ["pixel", "stream", "voyage", "code", "insight", "spirit", "vortex", "essence"]
        suffixes_local = ["_pro", "_master", "_hq", "_live", "_gaming", "_dev", "_lab", "_online", "_tech", "_zone"]
        separators = ["", ".", "_"] # Note: Instagram is stricter with multiple periods or underscores.
        
        # Extended complex patterns that leverage both Faker and custom lists
        complex_patterns = [
            lambda: f"{random.choice(prefixes_local)}{get_safe_faker_word()}{random.randint(100, 999)}",
            lambda: f"{random.choice(nouns_local)}{random.choice(suffixes_local)}",
            lambda: f"{get_safe_faker_name_part()}{random.choice(separators)}{get_safe_faker_word()}",
            lambda: f"{random.choice(string.ascii_lowercase)}{get_safe_faker_word(min_len=4)}{random.randint(100, 9999)}", # Starts with a letter for robustness
            lambda: f"{random.choice(nouns_local)}{random.randint(100,999)}{random.choice(suffixes_local)}", # e.g. code345tech
        ]
        
        all_generation_methods = patterns + complex_patterns

        # Internal helper to clean and perform final structural validation
        def sanitize_and_validate(raw_username_str):
            if not raw_username_str or not isinstance(raw_username_str, str): 
                return None

            candidate = re.sub(r'[^a-zA-Z0-9._]', '', raw_username_str.lower())
            candidate = re.sub(r'[._]{2,}', '.', candidate) # Consolidate multiple . or _
            candidate = candidate.strip('._') # Remove leading/trailing . or _

            # Ensure it always starts with a letter if current name starts with digit/symbol
            if candidate and (candidate[0].isdigit() or candidate[0] in '._'):
                candidate = random.choice(string.ascii_lowercase) + candidate
            
            # Re-check after prefixing, might create an empty string if `candidate` was like ".1" -> ""
            if not candidate: return None 

            # Final check against Instagram's primary rules (length, not just digits, proper boundaries)
            if 3 <= len(candidate) <= 30 and not candidate.isdigit() and \
               not candidate.startswith((' ', '.', '_')) and not candidate.endswith((' ', '.', '_')):
                return candidate
            return None # Failed final validation criteria

        for attempt in range(max_attempts):
            try:
                # Randomly pick a generation method and sanitize its output
                generated_raw = random.choice(all_generation_methods)()
                username_candidate = sanitize_and_validate(generated_raw)
                
                if username_candidate:
                    logger.debug(f"Generated valid username: '{username_candidate}' (Raw: '{generated_raw}', Attempt {attempt+1})")
                    return username_candidate
                else:
                    logger.debug(f"Generation attempt {attempt+1} resulted in invalid format from raw '{generated_raw}'. Retrying.")
            except Exception as e: # Catch any errors within a generation lambda or initial sanitize
                logger.warning(f"Username generation attempt {attempt+1} encountered an error: {e}", exc_info=logger.level == logging.DEBUG)

        # Fallback mechanism if all structured generation attempts fail
        logger.warning(f"All {max_attempts} main username generation attempts failed. Trying robust fallback generators.")
        
        # More robust fallback options
        fallback_strategies = [
            lambda: f"user_{get_safe_faker_name_part()}{str(random.randint(1000, 9999))}",
            lambda: f"{get_safe_faker_word(min_len=5)}_{str(int(time.time()) % 10000)}",
            lambda: f"{self.fake.user_name()}{random.randint(1,9)}{random.choice(string.ascii_lowercase)}", # More dynamic based on Faker's output
        ]
        
        for fb_attempt in range(5): # Max 5 fallback attempts
            try:
                fallback_raw = random.choice(fallback_strategies)()
                fallback_clean = sanitize_and_validate(fallback_raw)
                if fallback_clean:
                    logger.warning(f"Using fallback username: '{fallback_clean}' (Fallback Attempt {fb_attempt+1})")
                    return fallback_clean
            except Exception as fb_exc:
                logger.warning(f"Fallback username generation attempt {fb_attempt+1} failed: {fb_exc}", exc_info=logger.level == logging.DEBUG)

        # Absolute last resort, very unlikely to be hit if all above methods are sound
        final_critical_fallback = "temp_user_" + str(uuid.uuid4().hex[:8]) # Guarantee a valid string using UUID
        final_critical_fallback = sanitize_and_validate(final_critical_fallback) or "random_fallback" # Should never be None, but safe.
        logger.critical(f"All username generation strategies failed! Using final desperate fallback: {final_critical_fallback}")
        return final_critical_fallback
    
    def _try_click_ig_suggestion(self, driver_instance, username_field_el, username_cache_this_session):
        """
        Attempts to find and click an Instagram username suggestion.
        If a suggestion is clicked and successfully applies, it returns the text of that suggestion.
        Otherwise, returns None.

        Args:
            driver_instance: The WebDriver instance.
            username_field_el: The username input WebElement (used for context to find suggestions nearby).
            username_cache_this_session: A set of usernames already tried, to avoid clicking redundant suggestions.

        Returns:
            str or None: The text of the successfully clicked suggestion, or None.
        """
        user_context_for_log = self.current_account.get('username', 'SUGG_CLICK')[:15] if self.current_account else "SUGG_CLICK"
        picked_sugg_text = None
        suggestion_found_timeout = 2.5 # Time to wait for suggestions to appear after some input.

        # The HTML provided shows suggestions are DIVs with role=button and common classes
        # e.g., <div class="_acan _acap _acaq _acas _aj1- _ap30" role="button" tabindex="0">suggestedname</div>
        # and a "Refresh suggestion" button which has similar classes. We must distinguish.
        suggestion_xpath_strict = ".//div[@role='button' and contains(@class, '_acan') and string-length(normalize-space(text())) > 2 and string-length(normalize-space(text())) < 31 and not(contains(translate(normalize-space(text()),'REFSHUG','refshug'), 'refresh suggestion')) and not(.//*[name()='svg'])] | .//button[@role='button' and contains(@class, '_acan') and string-length(normalize-space(text())) > 2 and string-length(normalize-space(text())) < 31 and not(contains(translate(normalize-space(text()),'REFSHUG','refshug'), 'refresh suggestion')) and not(.//*[name()='svg'])]"

        try:
            # 1. Give time for suggestions UI to render after input/focus
            self._random_delay(0.5, 1.0, driver_instance)

            # 2. Attempt to find suggestion elements. Search relative to field's parent, then globally if needed.
            possible_sugg_elements = []
            try:
                # Assuming common Instagram parent classes that might contain the suggestion elements.
                # Adjust if these classes change or suggestions are in other parent containers.
                username_field_parent_candidate_xpath = "./ancestor::div[contains(@class, '_ab23')] | ./ancestor::div[contains(@class,'x1i10hfl')] | ./parent::div"
                username_field_immediate_parent = username_field_el.find_element(By.XPATH, username_field_parent_candidate_xpath)
                
                all_suggs_elements_in_context = WebDriverWait(username_field_immediate_parent, 1).until(
                    EC.presence_of_all_elements_located((By.XPATH, suggestion_xpath_strict.replace("//", ".//")))
                )
                possible_sugg_elements.extend(all_suggs_elements_in_context)
            except (NoSuchElementException, TimeoutException):
                logger.debug(f"[{user_context_for_log}] No suggestions in immediate username parent, trying wider search.")
                try: # Broader search for suggestions on the page if contextual failed
                    all_suggs_elements_global = WebDriverWait(driver_instance, 1.5).until(
                        EC.presence_of_all_elements_located((By.XPATH, suggestion_xpath_strict))
                    )
                    possible_sugg_elements.extend(all_suggs_elements_global)
                except (NoSuchElementException, TimeoutException):
                    logger.debug(f"[{user_context_for_log}] No global suggestions found within timeout either.")
            except StaleElementReferenceException:
                logger.warning(f"[{user_context_for_log}] Username field parent went stale while finding suggestions.")
                return None # Cannot find suggestions if context is bad

            if not possible_sugg_elements:
                logger.debug(f"[{user_context_for_log}] No candidate suggestion elements found using XPaths.")
                return None # No suggestions found, so return None

            # 3. Filter for truly valid, un-cached, and clickable suggestions
            valid_actionable_suggestions = []
            for el_sugg in possible_sugg_elements:
                try:
                    sugg_text = (el_sugg.text.strip() or el_sugg.get_attribute('aria-label') or "").lower()
                    if sugg_text and self.username_pattern.match(sugg_text) and \
                       3 <= len(sugg_text) <= 30 and \
                       sugg_text not in username_cache_this_session and \
                       el_sugg.is_displayed() and el_sugg.is_enabled():
                        valid_actionable_suggestions.append((el_sugg, sugg_text))
                    # else: logger.debug(f"[{user_context_for_log}] Filtered out suggestion: '{sugg_text}' (is displayed:{el_sugg.is_displayed()})")
                except StaleElementReferenceException:
                    logger.debug(f"[{user_context_for_log}] Suggestion element went stale during validation.")
                    continue
                except Exception as e_filter:
                    logger.debug(f"[{user_context_for_log}] Error filtering suggestion: {e_filter}")
            
            if not valid_actionable_suggestions:
                logger.debug(f"[{user_context_for_log}] No valid and actionable IG suggestions after filtering.")
                return None

            # 4. Randomly select and click one
            chosen_el, chosen_text = random.choice(valid_actionable_suggestions)
            logger.info(f"[{user_context_for_log}] Selected IG suggestion: '{chosen_text}'. Attempting click.")
            
            if self._js_click(chosen_el, driver_instance):
                picked_sugg_text = chosen_text
                logger.info(f"[{user_context_for_log}] Successfully clicked IG suggestion: '{picked_sugg_text}'.")
                self._random_delay(0.5, 1.0, driver_instance) # Small delay for UI update
                # Crucial: after clicking, Instagram's JS will likely fill the input field.
                # No further manual typing of this suggestion text is typically needed.
                return picked_sugg_text
            else:
                logger.warning(f"[{user_context_for_log}] Failed to click suggestion '{chosen_text}'.")
                return None # Failed to click

        except (TimeoutException) as te:
            logger.debug(f"[{user_context_for_log}] Timeout finding/interacting with suggestions within {suggestion_found_timeout}s. {te}")
        except Exception as e_main:
            logger.warning(f"[{user_context_for_log}] Overall error in _try_click_ig_suggestion: {e_main}", exc_info=False)
            
        return None # Default return on failure or no suggestions found

        # Ensure first character is always a letter if current generation doesn't guarantee it strongly
        def ensure_starts_with_letter(name_str):
            if name_str and name_str[0].isdigit() or name_str[0] in '._':
                return random.choice(string.ascii_lowercase) + name_str
            return name_str
            
        for attempt in range(max_attempts):
            try:
                # Randomly pick a generation method
                generated_raw_username = random.choice(all_generation_methods)()
                
                # Apply base cleaning and formatting (from old logic)
                username_candidate = re.sub(r'[^a-zA-Z0-9._]', '', generated_raw_username.lower())
                username_candidate = re.sub(r'[._]{2,}', '.', username_candidate).strip('._')
                username_candidate = ensure_starts_with_letter(username_candidate)

                # Ensure it meets basic IG criteria (length, not all digits, no leading/trailing invalid chars)
                if 3 <= len(username_candidate) <= 30 and not username_candidate.isdigit() and \
                   not username_candidate.startswith((' ', '.', '_')) and not username_candidate.endswith((' ', '.', '_')):
                    logger.debug(f"Generated human-like username: '{username_candidate}' (Attempt {attempt+1})")
                    return username_candidate
            except Exception as e:
                logger.warning(f"Username generation attempt {attempt+1} error: {e}", exc_info=logger.level == logging.DEBUG)

        fallback = f"bot_{int(time.time()) % 10000}_{random.randint(100, 999)}"[
            :30].strip('._')
        logger.warning(f"Username generation failed after all attempts. Fallback: {fallback}")
        return fallback
    
    def _quick_check_username_availability_http(self, username_to_check, proxy_for_check=None):
        """
        Performs a quick HTTP HEAD request to check if an Instagram profile URL for
        the given username likely exists (200) or results in a 404 (not found).
        Adds x-ig-app-id header for better resemblance to app requests.

        Args:
            username_to_check (str): The username.
            proxy_for_check (str, optional): Proxy string "ip:port" or None for direct.

        Returns:
            bool or None:
                True if 404 (likely available).
                False if 200 (likely taken, assuming it's a profile page).
                None for inconclusive results (other statuses, errors, timeout).
        """
        if not username_to_check:
            return None # Invalid input

        normalized_username = urllib.parse.quote(username_to_check.strip().lower())
        check_url = f"https://www.instagram.com/{normalized_username}/"
        log_prefix = f"UserHTTPCheck-{username_to_check[:10]}"

        http_headers = {
            'User-Agent': random.choice(DESKTOP_USER_AGENTS),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none', 
            'DNT': '1',
            'Pragma': 'no-cache',
            'Cache-Control': 'no-cache',
            'x-ig-app-id': '936619743392459', # Based on your research
        }
        
        http_proxies = None
        if proxy_for_check and isinstance(proxy_for_check, str):
            http_proxies = {
                "http": f"http://{proxy_for_check}",
                "https": f"http://{proxy_for_check}" 
            }
        
        try:
            logger.debug(f"[{log_prefix}]: Sending HEAD to {check_url} via {'proxy ' + proxy_for_check if proxy_for_check else 'direct'}.")
            
            with requests.Session() as s:
                s.headers.update(http_headers)
                if http_proxies:
                    s.proxies.update(http_proxies)

                response = s.head(check_url, timeout=self.settings.get("proxy_timeout", 7), allow_redirects=True)
            
            logger.debug(f"[{log_prefix}]: Response Status: {response.status_code} from {response.url} (original: {check_url})")

            final_url_path = urllib.parse.urlparse(response.url).path.strip('/').lower()
            requested_path_segment = normalized_username.lower()

            if response.status_code == 404:
                logger.info(f"[{log_prefix}]: Username '{username_to_check}' received 404. Likely AVAILABLE.")
                return True
            elif response.status_code == 200:
                if final_url_path == requested_path_segment or (final_url_path == f"accounts/login" and "checkpoint_platform" in response.text.lower()): # Check if it redirect to login but for the user/profile if it means account exists
                    logger.info(f"[{log_prefix}]: Username '{username_to_check}' received 200/Redirected (possible checkpoint). Likely TAKEN.")
                    return False
                else: # Got 200 but not profile or relevant error page, might be a general login/explore. Inconclusive.
                    logger.warning(f"[{log_prefix}]: Username '{username_to_check}' received 200 but URL path mismatch ({final_url_path} vs {requested_path_segment}). Inconclusive.")
                    return None
            elif response.status_code == 429: 
                logger.warning(f"[{log_prefix}]: HTTP pre-check for '{username_to_check}' rate-limited (429). Disabling pre-checks temporarily.")
                self.settings["enable_username_url_precheck"] = False 
                return None
            else:
                logger.warning(f"[{log_prefix}]: Username '{username_to_check}' - Inconclusive HTTP status {response.status_code}.")
                return None 

        except requests.exceptions.Timeout:
            logger.warning(f"[{log_prefix}]: Timeout during HTTP pre-check for '{username_to_check}'. Inconclusive.")
            return None
        except requests.exceptions.RequestException as e:
            logger.warning(f"[{log_prefix}]: RequestException during HTTP pre-check for '{username_to_check}': {str(e)[:100]}. Inconclusive.")
            return None
        except Exception as e:
            logger.error(f"[{log_prefix}]: Unexpected error in HTTP pre-check for '{username_to_check}': {e}", exc_info=True)
            return None

    def create_temporary_account(self, email=None, username=None, password=None):
        action_id = ''.join(random.choices(
            string.ascii_lowercase + string.digits, k=6))
        logger.info(f"AccCreate-{action_id}: Starting...")
        account_info_dict = None
        local_driver = None
        proxy_used = "Unknown"
        final_status = "failed_init"

        email_details_from_creator = None
        creation_username = None  # Define here for use in exception logging

        try:
            local_driver = self._setup_driver()
            if not local_driver:
                raise WebDriverException(
                    "WebDriver setup failed for account creation.")
            proxy_used = "Direct" if not self.current_proxy_address else self.current_proxy_address

            # create_temporary_email now returns a dictionary {'address': ..., 'provider': ..., 'details': ...} or None
            email_details_from_creator = self.email_creator.create_temporary_email()

            if not email_details_from_creator or not email_details_from_creator.get('address'):
                logger.error(
                    f"AccCreate-{action_id}: Failed to generate any temporary email.")
                raise ValueError("Failed to generate email.")

            creation_email = email_details_from_creator['address']
            logger.info(
                f"AccCreate-{action_id}: Using email: {creation_email} (Provider: {email_details_from_creator.get('provider')})")

            creation_username = username or self.generate_username()
            if not creation_username or not (3 <= len(creation_username) <= 30):
                raise ValueError(
                    f"Invalid username generated or provided: '{creation_username}'.")

            creation_password = password or self.generate_password()
            logger.info(
                f"AccCreate-{action_id}: Attempting signup for user: '{creation_username}'...")

            # --- CORRECTED CALL ---
            signup_successful = self.signup_with_selenium(
                email_details_dict=email_details_from_creator,
                username=creation_username,
                password=creation_password,
                driver_instance=local_driver
            )

            current_url_after_all = "Unknown"
            try:
                current_url_after_all = local_driver.current_url
                logger.debug(
                    f"AccCreate-{action_id}: URL after full signup flow: {current_url_after_all}")
            except WebDriverException as e:
                logger.warning(
                    f"AccCreate-{action_id}: Could not get final URL after signup attempt: {e}")

            if signup_successful is True:
                final_status = "active"
                logger.info(
                    f"AccCreate-{action_id}: '{creation_username}' successfully signed up and confirmed (Status: {final_status}).")
                if self.settings.get("enable_account_aging", True):
                    temp_acc_dict_for_aging = {
                        "username": creation_username, "password": creation_password, "email": creation_email}
                    self.age_account(temp_acc_dict_for_aging, local_driver)
            elif signup_successful == "verification_needed" or signup_successful == "email_confirmation_pending":
                final_status = "verification_needed"
                logger.warning(
                    f"AccCreate-{action_id}: '{creation_username}' created but requires verification (Status: {final_status}).")
            elif signup_successful == "username_unavailable":
                final_status = "failed_username"
                logger.error(
                    f"AccCreate-{action_id}: Could not secure a username for '{creation_username}'.")
            else:  # signup_successful is False
                final_status = "failed_signup_stage"
                logger.error(
                    f"AccCreate-{action_id}: Signup process failed at some stage. Check preceding logs for details.")

            if final_status not in ["failed_init", "failed_signup_stage", "failed_username"]:
                ua_string = "Unknown"
                try:
                    ua_string = local_driver.execute_script(
                        "return navigator.userAgent;")
                except Exception:
                    pass

                account_info_dict = {
                    "username": creation_username, "email": creation_email, "password": creation_password,
                    "created_at": time.time(), "status": final_status, "reports_made": 0, "last_report_time": 0,
                    "proxy_used": proxy_used, "user_agent": ua_string
                }

                with self.account_lock:
                    if not any(acc['username'] == account_info_dict['username'] for acc in self.accounts):
                        self.accounts.append(account_info_dict)
                        logger.info(
                            f"AccCreate-{action_id}: Account '{creation_username}' added to list with status '{final_status}'.")
                    else:
                        logger.warning(
                            f"AccCreate-{action_id}: Account '{account_info_dict['username']}' already exists, not re-adding.")
                self._save_account_to_csv(account_info_dict)
            else:
                account_info_dict = None

        except (WebDriverException, ValueError, Exception) as e:
            logger.error(f"AccCreate-{action_id}: Main process failed: {e}",
                         exc_info=logger.level == logging.DEBUG)
            self._save_screenshot(
                f"creation_exc_main_{creation_username or 'random'}", local_driver)
            if final_status == "failed_init":
                final_status = f"failed_{type(e).__name__}"
            account_info_dict = None
        finally:
            keep_open_for_debug = hasattr(local_driver, "_DEBUG_KEEP_OPEN") and getattr(
                local_driver, "_DEBUG_KEEP_OPEN", False)
            if local_driver and not keep_open_for_debug:
                logger.debug(
                    f"AccCreate-{action_id}: Closing creation driver.")
                try:
                    local_driver.quit()
                except Exception as qe:
                    logger.warning(f"Err closing driver: {qe}")
            elif local_driver and keep_open_for_debug:
                logger.warning(
                    f"AccCreate-{action_id}: DRIVER KEPT OPEN FOR DEBUGGING. Close it manually. User: {creation_username if 'creation_username' in locals() else 'N/A'}")
                try:
                    delattr(local_driver, "_DEBUG_KEEP_OPEN")
                except:
                    pass

            delay_min = self.settings.get("account_creation_delay_min", 4.0)
            delay_max = self.settings.get("account_creation_delay_max", 10.0)
            if delay_min > delay_max:
                delay_min = delay_max / 2
            time.sleep(random.uniform(delay_min, delay_max))

            logger.debug(
                f"AccCreate-{action_id}: Finished. Final Status: {final_status}. Account data: {'Exists' if account_info_dict else 'None'}")
            return account_info_dict

    def signup_with_selenium(self, email_details_dict, username, password, driver_instance):
        """
        Attempts sign up, with advanced stabilization, health checks, robust username validation
        (incl. IG suggestions, HTTP pre-check, simplified on-page feedback), element-based 
        birthday detection, email confirmation handling, and configurable debug pauses.
        """
        if not driver_instance:
            logger.error("Signup Failed: No WebDriver instance provided.")
            return False

        # FIX: The email string is now correctly derived from the dictionary.
        email = email_details_dict['address']

        wait_timeout = self.settings.get("webdriver_wait_timeout", 15) + 20
        wait = WebDriverWait(driver_instance, wait_timeout)
        signup_start_time = time.monotonic()
        original_username_attempt = username
        user_context_for_log = username[:15] 
        logger.debug(f"Starting Selenium signup for '{user_context_for_log}' (Full: {username})...")
        
        driver_should_be_kept_open_on_fail = False 

        try:
            self._inject_stealth_js_early(driver_instance) 
            self._clear_browser_data_cdp(driver_instance) 

            signup_target_url = self.platform_urls['signup'] 
            signup_phone_url_segment = "/accounts/signup/phone/"
            logger.info(f"[{user_context_for_log}] Navigating to: {signup_target_url}")
            driver_instance.get(signup_target_url)
            self._random_delay(3.5, 5.5, driver_instance)
            final_landed_url = driver_instance.current_url
            logger.debug(f"[{user_context_for_log}] URL after initial GET: {final_landed_url}")

            if signup_target_url in final_landed_url or "/emailsignup/" in final_landed_url:
                logger.info(f"[{user_context_for_log}] Landed on Email Signup page.")
            elif signup_phone_url_segment in final_landed_url:
                logger.warning(f"[{user_context_for_log}] Redirected to Phone Signup. Switching to Email.")
                email_tab_selectors = [(By.XPATH, "//button[contains(normalize-space(.), 'EMAIL')]"), (By.XPATH, "//div[@role='tab' and contains(normalize-space(.), 'Email')]")]
                email_tab_button = self._find_element_robust(driver_instance, email_tab_selectors, wait, "Email Tab")
                if email_tab_button and self._js_click(email_tab_button, driver_instance):
                    logger.info(f"[{user_context_for_log}] Clicked 'EMAIL' tab. Waiting.")
                    self._random_delay(3.0, 5.0, driver_instance) 
                    if not self._find_element_robust(driver_instance, [(By.NAME, "emailOrPhone")], WebDriverWait(driver_instance,7), "Email Field on Tab Switch", suppress_failure_log=True):
                        logger.critical(f"[{user_context_for_log}] SIGNUP FAILED: Switched to Email tab but email field not found."); driver_should_be_kept_open_on_fail = self._debug_pause(f"Email tab switch content fail for {user_context_for_log}", driver_instance, True); self._save_screenshot(f"su_email_tab_content_fail_{user_context_for_log}", driver_instance); return False
                    logger.info(f"[{user_context_for_log}] Successfully switched to/confirmed email signup flow.")
                else:
                    logger.critical(f"[{user_context_for_log}] SIGNUP FAILED: Cannot click 'EMAIL' tab."); driver_should_be_kept_open_on_fail = self._debug_pause(f"Email tab click fail for {user_context_for_log}", driver_instance, True); self._save_screenshot(f"su_phone_no_email_{user_context_for_log}", driver_instance); return False
            else:
                logger.critical(f"[{user_context_for_log}] SIGNUP FAILED: Unexpected navigation: {final_landed_url}"); driver_should_be_kept_open_on_fail = self._debug_pause(f"Unexpected nav for {user_context_for_log} to {final_landed_url}", driver_instance, True); self._save_screenshot(f"su_unexpected_nav_{user_context_for_log}", driver_instance); return False

            logger.info(f"[{user_context_for_log}] Multi-stage page stabilization...")
            main_mount_xpaths = ["//div[starts-with(@id, 'mount_')]", "//div[@id='react-root']", "//body/div[contains(@class, 'x9f619') and count(./*) > 1]"]
            if not any(self._find_element_robust(driver_instance, [(By.XPATH, xp)], wait, "StructuralAnchor", suppress_failure_log=True) for xp in main_mount_xpaths):
                logger.critical(f"[{user_context_for_log}] Structural mount point not found."); driver_should_be_kept_open_on_fail = self._debug_pause("Structural mount fail", driver_instance, True); self._save_screenshot(f"su_no_mount_{user_context_for_log}", driver_instance); return "page_rendering_failed"
            
            if not self._check_devtools_page_health(driver_instance, username=user_context_for_log): 
                logger.error(f"[{user_context_for_log}] SIGNUP FAILED: DevTools health FAILED."); driver_should_be_kept_open_on_fail = self._debug_pause("DevTools health check failed", driver_instance, True); return False

            try: 
                consent_xpath = "//button[contains(translate(normalize-space(.), 'ACDEILOPTU', 'acdeiloptu'), 'accept') or contains(translate(normalize-space(.), 'ACDEILOPTU', 'acdeiloptu'), 'allow')]"
                consent_button = WebDriverWait(driver_instance, 5).until(EC.element_to_be_clickable((By.XPATH, consent_xpath)))
                if self._js_click(consent_button, driver_instance): logger.info(f"[{user_context_for_log}] Dismissed cookie consent.")
            except: logger.debug(f"[{user_context_for_log}] No cookie consent / timed out.")
            
            email_field_el = self._find_element_robust(driver_instance, [(By.NAME, "emailOrPhone")], wait, "Email Field")
            if not email_field_el or not self._human_type(email_field_el, email, driver_instance): 
                logger.critical(f"[{user_context_for_log}] Email type fail"); return False
            
            full_name = f"{self.fake.first_name()} {self.fake.last_name()}"
            name_field_el = self._find_element_robust(driver_instance, [(By.NAME, "fullName")], wait, "Full Name Field")
            if not name_field_el or not self._human_type(name_field_el, full_name, driver_instance): return False

            # Username validation loop
            max_username_attempts_total = 7
            username_available_for_signup = False
            username_cache_this_session = {username}

            for attempt_num in range(max_username_attempts_total):
                username_to_evaluate = self.generate_username() if attempt_num > 0 else username
                if username_to_evaluate in username_cache_this_session: continue

                username_cache_this_session.add(username_to_evaluate)
                username_field_el = self._find_element_robust(driver_instance, [(By.NAME, "username")], wait, "Username Field")
                if not username_field_el: return False

                if self.settings.get("enable_username_url_precheck", True):
                    proxy_http = self.current_proxy_address if not self.settings.get("force_direct_connection") else None
                    pre_check_result = self._quick_check_username_availability_http(username_to_evaluate, proxy_http)
                    if pre_check_result is False: continue

                if not self._human_type(username_field_el, username_to_evaluate, driver_instance): continue
                self._random_delay(2.5, 4.0, driver_instance)

                username_taken_text_xpath = "//*[contains(text(), 'is not available') or contains(text(), 'is taken')]"
                if self._find_element_robust(driver_instance, [(By.XPATH, username_taken_text_xpath)], WebDriverWait(driver_instance, 0.5), "TakenText", True):
                    continue

                username = username_to_evaluate
                username_available_for_signup = True
                break
            
            if not username_available_for_signup:
                logger.error(f"[{user_context_for_log}] Could not find an available username after {max_username_attempts_total} attempts.")
                return "username_unavailable"
            
            if not self._human_type(self._find_element_robust(driver_instance, [(By.NAME, "password")], wait, "Password Field"), password, driver_instance): return False
            
            submit_xpath = "//button[@type='submit'][normalize-space()='Sign up']"
            submit_button = self._find_element_robust(driver_instance, [(By.XPATH, submit_xpath)], WebDriverWait(driver_instance,15), "Submit Button")
            if not submit_button or not self._js_click(submit_button, driver_instance): return False
            
            logger.info(f"[{user_context_for_log}] Form submitted. Waiting for outcome...")
            self._random_delay(8, 15, driver_instance)
            current_url_after_submit = driver_instance.current_url

            if "/birthday/" in current_url_after_submit or self._find_element_robust(driver_instance, [(By.XPATH, "//select[@title='Month:']")], WebDriverWait(driver_instance, 10), "BirthdayEl", True):
                return self._handle_birthday_prompt(driver_instance=driver_instance, email_details_dict=email_details_dict)
            
            if self._find_element_robust(driver_instance, [(By.XPATH, "//input[@name='confirmationCode']")], WebDriverWait(driver_instance, 5), "EmailCodeEl", True):
                return self._handle_email_confirmation_code(email_details_dict, driver_instance)
            
            known_challenge_indicators = ["/challenge/", "/confirm/", "/sms/"]
            if any(m in current_url_after_submit for m in known_challenge_indicators):
                return "verification_needed"

            known_block_indicators = ["suspended", "disabled", "/error/", "checkpoint/"]
            if any(m in current_url_after_submit for m in known_block_indicators):
                return False

            if "instagram.com" in current_url_after_submit and not any(fail_path in current_url_after_submit for fail_path in ["emailsignup", "login"]):
                self._handle_common_popups(["Not Now", "Cancel"], timeout=7, driver_instance=driver_instance)
                return True

            logger.error(f"[{user_context_for_log}] UNEXPECTED final URL: {current_url_after_submit}. Assuming failure.")
            self._check_signup_page_errors(driver_instance, username, "unexpected final url")
            return False

        except Exception as e_master: 
            exc_type = type(e_master).__name__; err_msg = str(e_master)[:200]
            logger.critical(f"SIGNUP FAILED ('{user_context_for_log}'): {exc_type}: {err_msg}", exc_info=True)
            self._save_screenshot(f"su_master_exc_{user_context_for_log}", driver_instance)
            return False
        finally:
            duration = time.monotonic() - signup_start_time
            logger.debug(f"Signup process for '{user_context_for_log}' finished in {duration:.2f}s.")
                
    def _try_click_ig_suggestion(self, driver_instance, username_field_el, username_cache_this_session):
        """
        Attempts to find and click an Instagram username suggestion.
        If a suggestion is clicked and successfully applies, it returns the text of that suggestion.
        Otherwise, returns None.

        Args:
            driver_instance: The WebDriver instance.
            username_field_el: The username input WebElement (used for context to find suggestions nearby).
            username_cache_this_session: A set of usernames already tried, to avoid clicking redundant suggestions.

        Returns:
            str or None: The text of the successfully clicked suggestion, or None.
        """
        user_context_for_log = self.current_account.get('username', 'SUGG_CLICK')[:15] if self.current_account else "SUGG_CLICK"
        picked_sugg_text = None
        suggestion_found_timeout = 2.5 # Time to wait for suggestions to appear after some input.

        # Refined XPath for suggestion buttons, targeting clickable divs/buttons with username-like text
        suggestion_button_xpath = (
            ".//div[@role='button' and string-length(normalize-space(.)) > 2 and string-length(normalize-space(.)) < 31 and not(contains(normalize-space(.), 'Facebook')) and not(contains(normalize-space(.), 'Log in')) and not(.//*[name()='svg']) and not(contains(translate(normalize-space(),'RSRFENH','rsrfenh'), 'refresh'))] | "
            ".//button[@role='button' and string-length(normalize-space(.)) > 2 and string-length(normalize-space(.)) < 31 and not(contains(normalize-space(.), 'Facebook')) and not(contains(normalize-space(.), 'Log in')) and not(.//*[name()='svg']) and not(contains(translate(normalize-space(),'RSRFENH','rsrfenh'), 'refresh'))]"
        )

        try:
            # 1. Give the UI a moment for suggestions to appear.
            self._random_delay(0.5, 1.0, driver_instance)

            # 2. Find suggestion elements, first in context then globally.
            possible_sugg_elements = []
            try:
                parent_of_username_field = username_field_el.find_element(By.XPATH, "./ancestor::div[contains(@class, '_ab23') or contains(@class,'x1i10hfl')] | ./parent::div")
                possible_sugg_elements.extend(
                    WebDriverWait(parent_of_username_field, 1).until(
                        EC.presence_of_all_elements_located((By.XPATH, suggestion_button_xpath.replace("//", ".//")))
                    )
                )
            except (NoSuchElementException, TimeoutException):
                logger.debug(f"[{user_context_for_log}] No suggestions in parent context, trying global search.")
                try:
                    possible_sugg_elements.extend(
                        WebDriverWait(driver_instance, 1.5).until(
                            EC.presence_of_all_elements_located((By.XPATH, suggestion_button_xpath.replace(".//","//")))
                        )
                    )
                except (NoSuchElementException, TimeoutException):
                    logger.debug(f"[{user_context_for_log}] No global suggestions found either.")
            except StaleElementReferenceException:
                logger.warning(f"[{user_context_for_log}] Username field's context became stale.")
                return None

            if not possible_sugg_elements:
                logger.debug(f"[{user_context_for_log}] No candidate suggestion elements found on page.")
                return None

            # 3. Filter for valid, clickable suggestions.
            valid_actionable_suggestions = []
            for el in possible_sugg_elements:
                try:
                    sugg_text = (el.text.strip() or el.get_attribute('aria-label') or "").lower()
                    if sugg_text and self.username_pattern.match(sugg_text) and 3 <= len(sugg_text) <= 30 and sugg_text not in username_cache_this_session and el.is_displayed() and el.is_enabled():
                        valid_actionable_suggestions.append((el, sugg_text))
                except StaleElementReferenceException: continue
                except Exception as e_filter: logger.debug(f"[{user_context_for_log}] Minor error filtering suggestion: {e_filter}")
            
            if not valid_actionable_suggestions:
                logger.debug(f"[{user_context_for_log}] No valid IG suggestions available after filtering.")
                return None

            # 4. Choose and click a suggestion.
            chosen_el, chosen_text = random.choice(valid_actionable_suggestions)
            logger.info(f"[{user_context_for_log}] Selecting IG suggestion: '{chosen_text}'.")
            
            if self._js_click(chosen_el, driver_instance):
                picked_sugg_text = chosen_text
                logger.info(f"[{user_context_for_log}] Successfully clicked IG suggestion: '{picked_sugg_text}'.")
                self._random_delay(0.5, 1.0, driver_instance) # Delay for UI to auto-fill input
                return picked_sugg_text
            else:
                logger.warning(f"[{user_context_for_log}] Failed to JS-click suggestion '{chosen_text}'.")
                return None

        except (TimeoutException) as te:
            logger.debug(f"[{user_context_for_log}] Timeout waiting for suggestions within {suggestion_found_timeout}s. {te}")
        except Exception as e_main:
            logger.warning(f"[{user_context_for_log}] Error in _try_click_ig_suggestion: {e_main}", exc_info=logger.level <= logging.DEBUG)
            
        return None 
                                  
    def _debug_pause(self, context_message="Debug pause", driver_instance=None, critical_failure=False):
        """
        Pauses script execution for debugging if configured.
        If pause_duration is < 0, waits for Enter in console.
        If critical_failure is True and pause_duration < 0, driver won't be auto-closed by caller.
        """
        pause_duration = self.settings.get("debug_pause_duration_on_fail", 0) 

        if pause_duration == 0 and not critical_failure: # No pause unless indefinite for critical
            return False # Indicates no pause happened, auto-close can proceed

        # Force indefinite pause if it's a critical failure and user wants any pause
        if critical_failure and pause_duration == 0: # If setting is 0 but it's critical
            logger.warning(f"Critical failure, forcing indefinite debug pause despite setting of 0 for user inspection: {context_message}")
            pause_duration = -1 # Override to indefinite
        elif critical_failure and pause_duration > 0:
             logger.warning(f"Critical failure, extending debug pause to indefinite for user inspection: {context_message}")
             pause_duration = -1 # Override to indefinite

        duration_str = 'Indefinite (press Enter in console to resume)' if pause_duration < 0 else f'{pause_duration} seconds'
        log_message = f" SCRIPT PAUSED ({duration_str}) :: {context_message} "
        border = "=" * (len(log_message) // 2)
        
        logger.info(f"\n{border}\n{log_message}\n{border}")
        
        if driver_instance:
            try: logger.info(f"Current URL for debug: {driver_instance.current_url}")
            except Exception as e: logger.warning(f"Could not get current URL during debug pause: {e}")
        
        if pause_duration > 0:
            time.sleep(pause_duration)
            logger.info("Debug pause finished. Resuming script.")
            return False # Pause happened, auto-close can proceed if not indefinite
        elif pause_duration < 0: # Indefinite pause
            try:
                input(">>> SCRIPT PAUSED. PRESS ENTER IN THIS CONSOLE TO RESUME EXECUTION OR MANUALLY CLOSE BROWSER...")
                logger.info("Resuming script after manual Enter.")
                return True # Indefinite pause happened, CALLER SHOULD NOT AUTO-CLOSE DRIVER if this returns true
            except EOFError: # Running in non-interactive environment
                 logger.warning("Indefinite pause requested but no interactive console. Pausing for 300s instead.")
                 time.sleep(300) # Fallback to 5 min pause
                 return True # Still signal that it was an 'indefinite-like' pause
        
        return False # Default if somehow pause_duration was 0 but it went through
    
    def _check_signup_page_errors(self, driver_instance, username_attempt, context_message=""):
        """Logs any visible error messages on the current page."""
        if not driver_instance: return []
        
        page_errors_found = []
        prefix = f"PageErr ({username_attempt}) [{context_message}]: " if context_message else f"PageErr ({username_attempt}): "
        
        try:
            # More generic error locators that might appear on signup forms
            error_xpaths = [
                "//div[contains(@class, 'errorContainer') or contains(@class, '_aauq') or @role='alert']//span", # Common error divs with spans
                "//p[contains(@class, 'error') or contains(@class, '_ab27')]", # Paragraphs with error classes
                "//div[@data-testid='form-error']", # Common test ID for form errors
            ]
            
            all_error_elements = []
            for xp in error_xpaths:
                try: 
                    # Use a very short wait as errors usually appear quickly if they are going to
                    elements = WebDriverWait(driver_instance, 1).until(EC.presence_of_all_elements_located((By.XPATH, xp)))
                    all_error_elements.extend(elements)
                except TimeoutException:
                    continue # This specific XPath didn't find anything quickly
            
            if not all_error_elements:
                logger.debug(f"{prefix}No specific common error elements detected.")
                return []

            unique_errors = set()
            for el in all_error_elements:
                try:
                    err_text = el.text.strip()
                    if err_text and err_text not in unique_errors:
                        logger.error(f"{prefix}'{err_text}'")
                        page_errors_found.append(err_text)
                        unique_errors.add(err_text)
                except Exception: # Stale element or other issue getting text
                    continue 
            
            if not page_errors_found:
                logger.debug(f"{prefix}Elements matched general error XPaths but had no visible/unique text.")
        
        except WebDriverException as e:
            logger.warning(f"{prefix}WebDriverException while checking page errors: {e}")
        except Exception as e:
            logger.warning(f"{prefix}Unexpected error checking page errors: {e}", exc_info=logger.level == logging.DEBUG)
        return page_errors_found
    
    def _find_element_robust(self, driver, selectors, wait, element_name="Element", suppress_failure_log=False): # Add new arg
        """
        Tries multiple selectors to find an element, primarily waiting for visibility.
        Args:
            suppress_failure_log (bool): If True, don't log error or save screenshot on final failure.
        """
        last_exception = None
        condition = EC.visibility_of_element_located 
        wait_type = "visibility"
        
        for i, (by, value) in enumerate(selectors):
            try:
                element = wait.until(condition((by, value)))
                # Only log success if not suppressed for "expected failures"
                if not suppress_failure_log or (suppress_failure_log and element_name == "Username Success Indicator"): # Be specific or more general
                    logger.debug(f"Found {element_name} via {wait_type} using selector: {by}='{value}'")
                return element
            except (TimeoutException, NoSuchElementException, ElementNotInteractableException, StaleElementReferenceException) as e:
                last_exception = e
                # Only log individual attempt failure if not suppressed
                if not suppress_failure_log:
                    logger.debug(
                        f"Attempt {i+1}/{len(selectors)}: Failed to find {element_name} "
                        f"waiting for {wait_type} with selector {by}='{value}'. Error: {type(e).__name__}"
                    )
            except WebDriverException as e:
                if not suppress_failure_log:
                    logger.error(f"WebDriverException while trying to find {element_name} with {by}='{value}': {e}")
                last_exception = e; break # Break on critical WebDriver error

        # Final failure logging / screenshot
        if not suppress_failure_log:
            logger.error(
                f"{element_name} NOT found via ANY of the {len(selectors)} provided selectors. "
                f"Last error encountered: {type(last_exception).__name__ if last_exception else 'None'}"
            )
            safe_filename_part = element_name.replace('/', '_').replace(' ', '_').lower()
            self._save_screenshot(f"find_fail_{safe_filename_part}", driver)
        return None

    def _human_type(self, element, text, driver_instance, char_delay_min=0.05, char_delay_max=0.15, max_typing_attempts=3):
        """
        Simulates robust human typing into a WebElement.
        Focuses on guaranteed field emptying before typing.
        Prioritizes character-by-character send_keys for reactivity, with JS event nudging.
        Handles StaleElementReferenceException by returning False to signal re-acquisition.
        Ensures field is reliably cleared before new text is sent.

        Args:
            element: The WebElement to type into.
            text (str): The text to type.
            driver_instance: The Selenium WebDriver instance.
            char_delay_min (float): Minimum delay (seconds) between characters.
            char_delay_max (float): Maximum delay (seconds) between characters.
            max_typing_attempts (int): How many times to retry the whole typing/verification process for this field.

        Returns:
            bool: True if typing and verification were successful, False otherwise (including for SRE).
        """
        if not element or not driver_instance:
            logger.error(f"[_human_type]: Invalid element or driver instance provided (element: {element}, driver: {driver_instance}).")
            return False

        element_name_for_logging = element.get_attribute('name') or element.get_attribute('aria-label') or element.tag_name or "Unknown_Field"
        logger.debug(f"[_human_type]: Targeting '{element_name_for_logging}' (Target: '{text[:30]}...'). Attempting to activate and type.")

        js_clear_events_script = """
            arguments[0].value = ''; 
            arguments[0].dispatchEvent(new Event('input', { bubbles: true }));
            arguments[0].dispatchEvent(new Event('change', { bubbles: true }));
        """
        js_final_sync_script = """
            arguments[0].dispatchEvent(new Event('input', { bubbles: true, cancelable: true }));
            arguments[0].dispatchEvent(new Event('change', { bubbles: true, cancelable: true }));
            arguments[0].dispatchEvent(new Event('blur', { bubbles: true, cancelable: true }));
            arguments[0].focus(); 
        """

        for attempt in range(max_typing_attempts):
            logger.debug(f"[_human_type]: Typing attempt {attempt + 1}/{max_typing_attempts} for '{element_name_for_logging}'.")
            
            try:
                # 1. --- Aggressive Activation ---
                try:
                    driver_instance.execute_script("arguments[0].scrollIntoViewIfNeeded(true);", element)
                    self._random_delay(0.1, 0.2, driver_instance) 

                    if self._js_click(element, driver_instance):
                        logger.debug(f"[{element_name_for_logging}] Activated via JS Click.")
                    else:
                        element.click() if element.is_enabled() and element.is_displayed() else driver_instance.execute_script("arguments[0].focus();", element)
                        logger.debug(f"[{element_name_for_logging}] Activated via native/JS focus.")
                except ElementClickInterceptedException:
                    logger.warning(f"[{element_name_for_logging}] Click intercepted during activation. Forcing JS focus."); driver_instance.execute_script("arguments[0].focus();", element)
                except (StaleElementReferenceException, ElementNotInteractableException) as e:
                    logger.warning(f"[{element_name_for_logging}] Activation error ({type(e).__name__}). Forcing JS focus: {str(e)[:50]}."); driver_instance.execute_script("arguments[0].focus();", element)
                except WebDriverException as e:
                    if "no such element" in str(e).lower() or "element is not attached" in str(e).lower():
                        raise StaleElementReferenceException(f"Element '{element_name_for_logging}' likely gone during activation.")
                    logger.error(f"[{element_name_for_logging}] WebDriverException during activation: {e}"); self._random_delay(0.5, 1.0, driver_instance); continue 
                
                self._random_delay(0.2, 0.4, driver_instance)

                # 2. --- GUARANTEED CLEARING ---
                # Ensure the field is truly empty before typing.
                cleared_successfully = False
                for clear_retry in range(5): # Allow more attempts to clear fully
                    try:
                        element.clear() # Try native clear first
                        driver_instance.execute_script(js_clear_events_script, element) # Send events after clear
                        self._random_delay(0.2, 0.4, driver_instance) # Brief pause for UI sync

                        current_val_after_clear = element.get_attribute('value')
                        if not current_val_after_clear: # If field is actually empty now
                            logger.debug(f"[{element_name_for_logging}] Field confirmed empty. Clear attempt {clear_retry+1}/{5}.")
                            cleared_successfully = True; break
                        
                        logger.warning(f"[{element_name_for_logging}] Field NOT EMPTY (val: '{current_val_after_clear[:15]}'). Retrying clear. Attempt {clear_retry+1}.")
                        # If still not empty, force JS clear again
                        driver_instance.execute_script("arguments[0].value = '';", element)
                        driver_instance.execute_script(js_clear_events_script, element)
                        self._random_delay(0.3, 0.6, driver_instance)
                    except (StaleElementReferenceException, ElementNotInteractableException):
                        raise # Propagate for re-acquisition by caller
                    except Exception as e_clear_attempt:
                        logger.warning(f"[{element_name_for_logging}] Exception during clear attempt {clear_retry+1}: {e_clear_attempt}. Trying again.")
                        self._random_delay(0.5, 1.0, driver_instance)
                
                if not cleared_successfully: # If field couldn't be emptied after all attempts
                    logger.error(f"[{element_name_for_logging}] FAILED to empty field after multiple attempts. Current: '{element.get_attribute('value')[:30]}'. Aborting typing attempt.")
                    return False # Signal failure to clear/type.

                # 3. --- Primary Typing: Character-by-Character send_keys ---
                logger.debug(f"[_human_type]: Typing '{text[:30]}...' into '{element_name_for_logging}' char by char.")
                for char_index, char_to_type in enumerate(text):
                    element.send_keys(char_to_type)
                    self._random_delay(char_delay_min, char_delay_max) 

                logger.debug(f"[_human_type]: Character-by-character typing completed for '{element_name_for_logging}'.")

                # 4. --- Post-Typing Event "Nudge" (JS) & Immediate Verification ---
                driver_instance.execute_script(js_final_sync_script, element)
                logger.debug(f"[_human_type]: Dispatched final sync events.")
                self._random_delay(0.5, 1.0, driver_instance) 

                # 5. --- Final Value Verification ---
                actual_value_after_typing = element.get_attribute('value')
                if actual_value_after_typing == text:
                    logger.info(f"[_human_type]: Successfully typed and VERIFIED '{text[:30]}...' in '{element_name_for_logging}'.")
                    return True 
                else:
                    logger.warning(f"[_human_type]: Final value mismatch for '{element_name_for_logging}'. Expected: '{text[:30]}...', Got: '{str(actual_value_after_typing)[:30]}...'. Retrying full attempt.")
                    # Fall through to the next attempt in the `max_typing_attempts` loop.

            except StaleElementReferenceException as sre:
                logger.warning(f"[_human_type]: StaleElementReferenceException for '{element_name_for_logging}' on attempt {attempt + 1}: {sre}. Signaling caller to re-acquire element.")
                return False 
            except WebDriverException as e_type:
                logger.error(f"[_human_type]: WebDriverException during typing attempt {attempt + 1} for '{element_name_for_logging}': {type(e_type).__name__} - {e_type}", exc_info=logger.level == logging.DEBUG)
                continue 
            except Exception as e_general:
                logger.error(f"[_human_type]: Unexpected error during typing attempt {attempt + 1}: {e_general}", exc_info=logger.level == logging.DEBUG)
                continue 

        # If all max_typing_attempts failed the standard process
        logger.critical(f"[_human_type]: FAILED to type and verify '{text[:30]}...' in '{element_name_for_logging}' after {max_typing_attempts} robust attempts. Returning False.")
        return False
            
    def _random_delay(self, min_sec=None, max_sec=None, driver_instance=None):
        min_d = min_sec if min_sec is not None else self.settings["random_delay_min"]
        max_d = max_sec if max_sec is not None else self.settings["random_delay_max"]
        delay = max(0.1, random.uniform(min_d, max_d))
        time.sleep(delay)

    def _js_click(self, element, driver_instance):
        """
        Attempts to click an element using JavaScript.

        This is often used as a fallback when regular Selenium click() fails,
        especially due to interception or visibility issues.

        Args:
            element: The WebElement to click.
            driver_instance: The Selenium WebDriver instance.

        Returns:
            True if the JavaScript click was executed (doesn't guarantee success
            of the action triggered by the click), False otherwise.
        """
        if not element or not driver_instance:
            logger.warning("JS click attempted with invalid element or driver instance.")
            return False

        try:
            # 1. Scroll the element into view using JavaScript.
            # scrollIntoViewIfNeeded is generally preferred as it scrolls less aggressively
            # than scrollIntoView(true) if the element is already partially visible.
            driver_instance.execute_script("arguments[0].scrollIntoViewIfNeeded(true);", element)

            # 2. Add a small delay after scrolling, before clicking.
            # This can sometimes help if the page is still rendering/adjusting after scroll.
            self._random_delay(0.1, 0.25, driver_instance) # Pass driver if delay needs it

            # 3. Execute the JavaScript click command.
            driver_instance.execute_script("arguments[0].click();", element)

            logger.debug(f"JavaScript click executed successfully on element: {element.tag_name if hasattr(element, 'tag_name') else 'UnknownTag'}")
            return True # Indicate the command was sent

        except (WebDriverException, StaleElementReferenceException) as e:
            # Handle common Selenium exceptions that might occur during JS execution
            # StaleElementReferenceException: The element is no longer attached to the DOM.
            # WebDriverException: Generic WebDriver errors (e.g., communication issues).
            error_message = str(e).split('\n')[0][:100] # Get first line of error, truncate
            logger.warning(
                f"JavaScript click failed due to {type(e).__name__}: {error_message}"
            )
            return False

        except Exception as e:
            # Catch any other unexpected exceptions
            logger.warning(
                f"JavaScript click failed unexpectedly: {e}",
                exc_info=logger.level == logging.DEBUG # Show traceback if debugging
            )
            return False

    def _save_screenshot(self, prefix="screenshot", driver_instance=None):
        """
        Saves a screenshot of the current browser window if enabled in settings.

        Args:
            prefix (str): A prefix for the screenshot filename.
            driver_instance: An optional specific WebDriver instance to use.
                             Defaults to self.driver.
        """
        driver = driver_instance or self.driver # Use provided driver or the main one
        # Check if screenshots are enabled and if a driver instance is available
        if not driver or not self.settings.get("save_screenshots"):
            if not self.settings.get("save_screenshots"):
                logger.debug("Screenshot saving is disabled in settings.")
            elif not driver:
                logger.debug("Screenshot requested but no valid driver instance available.")
            return # Do nothing if disabled or no driver

        try:
            # Ensure the screenshot directory exists
            SCREENSHOT_DIR.mkdir(exist_ok=True)

            # Create a safe filename with timestamp and random number
            safe_prefix = re.sub(r'[^\w\-]+', '_', prefix) # Sanitize prefix
            timestamp = time.strftime('%Y%m%d_%H%M%S')
            rand = random.randint(100, 999)
            filename = SCREENSHOT_DIR / f"{safe_prefix}_{timestamp}_{rand}.png"

            # Attempt to save the screenshot
            if driver.save_screenshot(str(filename)):
                logger.info(f"Screenshot saved: {filename.name}")
            else:
                # This case might be rare, depends on driver implementation
                logger.warning(f"Driver returned False for save_screenshot: {filename.name}")

        except WebDriverException as e:
            # Handle specific WebDriver errors, especially session closure
            err_msg = str(e).lower()
            # Check for common messages indicating the browser/session is gone
            if any(term in err_msg for term in ["session deleted", "no such window", "invalid session id", "target closed"]):
                logger.error(f"Cannot save screenshot '{prefix}': WebDriver session seems closed or unresponsive.")
                # Attempt to clean up the potentially dead driver instance if it's the main one
                if driver is self.driver:
                    self.close_driver()
            else:
                # Log other WebDriver exceptions
                logger.error(f"WebDriverException occurred while saving screenshot '{prefix}': {e}")

        except Exception as e:
            # Catch any other unexpected errors during screenshot saving
            logger.error(
                f"Unexpected error failed saving screenshot '{prefix}': {e}",
                exc_info=logger.level == logging.DEBUG # Show traceback if debug enabled
            )
            
    # === NEW ACCOUNT AGING / BOT BEHAVIOR METHODS ===
    
    def _random_age_delay(self, driver_instance=None):
        """Uses aging-specific random delay settings."""
        min_d = self.settings.get("min_age_action_delay_sec", 3.0)
        max_d = self.settings.get("max_age_action_delay_sec", 8.0)
        self._random_delay(min_d, max_d, driver_instance)

    def _set_profile_bio(self, driver_instance):
        """Sets a random bio for the newly created account."""
        log_prefix = "Age-Bio"
        try:
            logger.info(f"[{log_prefix}]: Attempting to set profile bio.")
            driver_instance.get("https://www.instagram.com/accounts/edit/")
            self._random_age_delay(driver_instance)

            bio_selectors = [
                (By.NAME, "biography"),
                (By.XPATH, "//textarea[@aria-label='Biography']")
            ]
            bio_textarea = self._find_element_robust(driver_instance, bio_selectors, WebDriverWait(driver_instance, 10), "Biography Textarea")
            
            if bio_textarea:
                bio_text = self.fake.sentence(nb_words=random.randint(10, 25))
                bio_textarea.clear() # Clear existing text
                self._random_age_delay(driver_instance) # Small delay after clear
                if self._human_type(bio_textarea, bio_text, driver_instance):
                    logger.info(f"[{log_prefix}]: Bio typed successfully: '{bio_text[:30]}...'")
                    
                    # Try to click Submit/Done button after changing bio
                    submit_btn_selectors = [
                        (By.XPATH, "//button[@type='submit'][normalize-space()='Submit']"),
                        (By.XPATH, "//button[normalize-space()='Done']") # Often "Done" on mobile web for profile editing
                    ]
                    submit_button = self._find_element_robust(driver_instance, submit_btn_selectors, WebDriverWait(driver_instance, 5), "Profile Save Button")
                    if submit_button:
                        if self._js_click(submit_button, driver_instance):
                            logger.info(f"[{log_prefix}]: Profile saved successfully.")
                            self._random_age_delay(driver_instance)
                            return True
                        else:
                            logger.warning(f"[{log_prefix}]: Failed to click submit button after bio set.")
                else:
                    logger.warning(f"[{log_prefix}]: Failed to type bio into textarea.")
            else:
                logger.warning(f"[{log_prefix}]: Bio textarea not found.")
        except Exception as e:
            logger.error(f"[{log_prefix}]: Error setting profile bio: {e}", exc_info=logger.level == logging.DEBUG)
        return False

    def _browse_explore_feed(self, driver_instance):
        """Navigates to Explore and scrolls down a few times to simulate browsing."""
        log_prefix = "Age-Explore"
        num_scrolls = self.settings.get("num_explore_scroll_loops", 3)
        if num_scrolls == 0:
            logger.debug(f"[{log_prefix}]: Explore browsing skipped (set to 0 scrolls).")
            return True

        logger.info(f"[{log_prefix}]: Browsing Explore feed ({num_scrolls} scrolls).")
        try:
            driver_instance.get("https://www.instagram.com/explore/")
            WebDriverWait(driver_instance, 10).until(
                EC.presence_of_element_located((By.XPATH, "//div[contains(@class, 'explore')]")) # General explore page indicator
            )
            self._random_age_delay(driver_instance)

            for i in range(num_scrolls):
                logger.debug(f"[{log_prefix}]: Scrolling Explore feed {i+1}/{num_scrolls}...")
                driver_instance.execute_script("window.scrollTo(0, document.body.scrollHeight);")
                self._random_age_delay(driver_instance)
            logger.info(f"[{log_prefix}]: Finished browsing Explore.")
            return True
        except Exception as e:
            logger.error(f"[{log_prefix}]: Error browsing explore feed: {e}", exc_info=logger.level == logging.DEBUG)
            return False

    def _follow_random_profiles(self, driver_instance):
        """Navigates to random hashtag pages and tries to follow a few profiles from posts."""
        log_prefix = "Age-Follow"
        follow_count_limit = self.settings.get("num_profiles_to_follow", 3)
        if follow_count_limit == 0:
            logger.debug(f"[{log_prefix}]: Following profiles skipped (set to 0 follows).")
            return True

        hashtags = ['memes', 'coding', 'travel', 'food', 'nature', 'art', 'science', 'fashion', 'music']
        followed_count = 0
        tried_urls = set() # To avoid revisiting same pages immediately

        logger.info(f"[{log_prefix}]: Attempting to follow {follow_count_limit} profiles.")
        for _ in range(follow_count_limit * 2): # Try more times than actual follow limit to find candidates
            if followed_count >= follow_count_limit: break

            hashtag = random.choice(hashtags)
            explore_tag_url = f"https://www.instagram.com/explore/tags/{hashtag}/"
            if explore_tag_url in tried_urls: continue
            tried_urls.add(explore_tag_url)

            try:
                logger.debug(f"[{log_prefix}]: Visiting hashtag: #{hashtag}")
                driver_instance.get(explore_tag_url)
                self._random_age_delay(driver_instance)

                post_link_selectors = [
                    (By.XPATH, "//div[@role='button']//a[contains(@href, '/p/') or contains(@href, '/reel/')]"), # Clickable wrapper over images
                    (By.XPATH, "//article//a[contains(@href, '/p/') or contains(@href, '/reel/')]"), # More general post link
                ]
                post_links = self._find_elements_robust(driver_instance, post_link_selectors, WebDriverWait(driver_instance, 5), "Hashtag Post Links")

                if not post_links:
                    logger.debug(f"[{log_prefix}]: No clickable post links found on #{hashtag} tag page. Trying next hashtag.")
                    self._random_age_delay(driver_instance)
                    continue

                selected_post_url = random.choice(post_links).get_attribute("href")
                if not selected_post_url or selected_post_url in tried_urls: # Ensure unique and valid URL
                     continue
                tried_urls.add(selected_post_url)
                
                logger.debug(f"[{log_prefix}]: Visiting post: {selected_post_url}")
                driver_instance.get(selected_post_url)
                self._random_age_delay(driver_instance)

                # Look for a follow button
                follow_button_selectors = [
                    (By.XPATH, "//button[normalize-space()='Follow' or normalize-space()='Follow back']"), # On post modal or profile header
                    (By.XPATH, "//button/div[normalize-space()='Follow']")
                ]
                follow_button = self._find_element_robust(driver_instance, follow_button_selectors, WebDriverWait(driver_instance, 7), "Follow Button")

                if follow_button and follow_button.is_displayed() and follow_button.is_enabled():
                    # Double-check that it's not a suggestion or already followed state for robustness
                    if "Following" not in follow_button.text and "Requested" not in follow_button.text:
                        if self._js_click(follow_button, driver_instance):
                            followed_count += 1
                            logger.info(f"[{log_prefix}]: Successfully followed a profile (Total: {followed_count}).")
                            self._random_age_delay(driver_instance)
                            
                            # Dismiss any "Turn on notifications" pop-ups quickly
                            self._handle_common_popups(["Not Now", "Cancel"], timeout=3, driver_instance=driver_instance)
                        else:
                            logger.warning(f"[{log_prefix}]: Failed to JS-click Follow button on post.")
                    else:
                        logger.debug(f"[{log_prefix}]: Follow button text indicates already following or pending for this profile.")
                else:
                    logger.debug(f"[{log_prefix}]: No actionable Follow button found on post page.")
            except Exception as e:
                logger.warning(f"[{log_prefix}]: Error attempting to follow profile on hashtag page {hashtag}: {e}", exc_info=logger.level == logging.DEBUG)
                self._save_screenshot(f"age_follow_fail_{self.current_account.get('username')}_{hashtag}", driver_instance)
            finally:
                self._random_age_delay(driver_instance) # Small delay after each attempt

        logger.info(f"[{log_prefix}]: Finished following. Followed {followed_count}/{follow_count_limit} profiles.")
        return followed_count > 0 # Return true if at least one profile was followed

    def _like_random_posts(self, driver_instance):
        """Navigates to Explore and likes a few random posts."""
        log_prefix = "Age-Like"
        like_count_limit = self.settings.get("num_posts_to_like", 5)
        if like_count_limit == 0:
            logger.debug(f"[{log_prefix}]: Liking posts skipped (set to 0 likes).")
            return True

        liked_count = 0
        tried_urls = set()

        logger.info(f"[{log_prefix}]: Attempting to like {like_count_limit} posts.")
        # Ensure we scroll the explore page sufficiently before picking posts
        try:
            driver_instance.get("https://www.instagram.com/explore/")
            self._random_age_delay(driver_instance)
            for _ in range(self.settings.get("num_explore_scroll_loops", 3)):
                driver_instance.execute_script("window.scrollTo(0, document.body.scrollHeight);")
                self._random_age_delay(driver_instance)
            logger.debug(f"[{log_prefix}]: Pre-scrolled Explore feed before liking.")
        except Exception as e:
            logger.warning(f"[{log_prefix}]: Could not pre-scroll explore for likes: {e}")

        for _ in range(like_count_limit * 2): # Try more times than limit to find available posts
            if liked_count >= like_count_limit: break

            post_link_selectors = [
                (By.XPATH, "//div[@role='button']//a[contains(@href, '/p/') or contains(@href, '/reel/')][1]"), # Focus on clickable areas with images
                (By.XPATH, "//article//a[contains(@href, '/p/') or contains(@href, '/reel/')]") # More general post link
            ]
            all_explore_post_elements = self._find_elements_robust(driver_instance, post_link_selectors, WebDriverWait(driver_instance, 5), "Explore Post Links")

            if not all_explore_post_elements:
                logger.debug(f"[{log_prefix}]: No new clickable post links found on Explore. Breaking.")
                break

            # Filter for visible elements and avoid already tried ones
            available_posts = [
                el for el in all_explore_post_elements if el.is_displayed() and el.get_attribute("href") and el.get_attribute("href") not in tried_urls
            ]

            if not available_posts:
                logger.debug(f"[{log_prefix}]: No new unique visible posts available to click for liking.")
                # Maybe scroll down further if no new visible ones? Already done by the loop.
                break

            selected_post_el = random.choice(available_posts)
            selected_post_url = selected_post_el.get_attribute("href")
            tried_urls.add(selected_post_url) # Add to tried so we don't pick it again

            try:
                logger.debug(f"[{log_prefix}]: Visiting post to like: {selected_post_url}")
                driver_instance.get(selected_post_url)
                self._random_age_delay(driver_instance)

                # Locate the like button (heart icon)
                # It can be a direct SVG within a span or an img with specific attributes.
                like_button_selectors = [
                    (By.XPATH, "//button/*[name()='svg' and @aria-label='Like'] | //span//*[name()='svg' and @aria-label='Like'] | //button[contains(.,'Like')]"), # General heart SVG/text within button
                    (By.XPATH, "//button[@data-testid='like_button']") # Potential data-test ID
                ]
                like_button = self._find_element_robust(driver_instance, like_button_selectors, WebDriverWait(driver_instance, 7), "Like Button")
                
                # Check if it's currently in an "unliked" state. Liked heart is solid, unliked is outline.
                # aria-label might be 'Like' or 'Unlike' (depending on current state)
                # This check can be tricky due to dynamic UI changes or accessibility labels
                if like_button:
                    aria_label = like_button.get_attribute('aria-label')
                    # If it's a solid heart (already liked), aria-label might be 'Unlike'
                    # Or it might have an attribute distinguishing filled/unfilled.
                    # Simple approach: If its current state suggests 'liked', skip. Otherwise click.
                    is_liked = False
                    if "Unlike" in (aria_label or ""):
                        is_liked = True
                    # Check for "unlike" button directly. This is safer than text content of like button, if it exist
                    elif self._find_element_robust(driver_instance, [(By.XPATH, "//button[contains(text(),'Unlike')]")], WebDriverWait(driver_instance, 1), "UnlikeBtn", suppress_failure_log=True):
                         is_liked = True
                         
                    if is_liked:
                        logger.debug(f"[{log_prefix}]: Post already liked, skipping.")
                        continue # Skip to next attempt to find post to like

                    if self._js_click(like_button, driver_instance):
                        liked_count += 1
                        logger.info(f"[{log_prefix}]: Successfully liked a post (Total: {liked_count}).")
                        self._random_age_delay(driver_instance)
                    else:
                        logger.warning(f"[{log_prefix}]: Failed to JS-click Like button.")
                else:
                    logger.debug(f"[{log_prefix}]: Like button not found or not actionable for this post.")

            except Exception as e:
                logger.warning(f"[{log_prefix}]: Error attempting to like post: {e}", exc_info=logger.level == logging.DEBUG)
                self._save_screenshot(f"age_like_fail_{self.current_account.get('username')}", driver_instance)
            finally:
                self._random_age_delay(driver_instance)

        logger.info(f"[{log_prefix}]: Finished liking. Liked {liked_count}/{like_count_limit} posts.")
        return liked_count > 0

    def _find_elements_robust(self, driver, selectors, wait, elements_name="Elements", suppress_failure_log=False):
        """
        Helper to find multiple elements, returning a list.
        """
        for i, (by, value) in enumerate(selectors):
            try:
                elements = wait.until(EC.presence_of_all_elements_located((by, value)))
                # Filter for visible, enabled, and non-empty elements before returning
                # This also checks for "text_content", some posts have blank visible elements.
                visible_elements = [el for el in elements if el.is_displayed() and el.is_enabled() and (el.text or el.get_attribute("src") or el.get_attribute("href"))]
                if visible_elements:
                    logger.debug(f"Found {len(visible_elements)} {elements_name} via {by}='{value}'.")
                    return visible_elements
            except (TimeoutException, NoSuchElementException, StaleElementReferenceException) as e:
                if not suppress_failure_log: logger.debug(f"Attempt {i+1}/{len(selectors)}: No {elements_name} found for {by}='{value}': {type(e).__name__}.")
            except WebDriverException as e:
                if not suppress_failure_log: logger.warning(f"WebDriverException while finding {elements_name} with {by}='{value}': {e}.")
                break
        if not suppress_failure_log: logger.debug(f"No {elements_name} found via any selector.")
        return []

    def age_account(self, account_info, driver_instance):
        """
        Performs various human-like actions on a newly created Instagram account
        to build trust and make it appear less suspicious.

        Args:
            account_info (dict): The dictionary for the newly created account.
            driver_instance: The WebDriver instance to use for aging.
        """
        if not self.settings.get("enable_account_aging", True):
            logger.info("Account aging is disabled as per settings. Skipping.")
            return

        user_context = account_info.get('username', 'N/A')
        logger.info(f"--- Starting account aging actions for '{user_context}' ---")
        aging_start_time = time.monotonic()
        
        # Action 1: Set Profile Bio
        self._set_profile_bio(driver_instance)

        # Action 2: Browse Explore Feed
        self._browse_explore_feed(driver_instance)

        # Action 3: Follow Random Profiles
        self._follow_random_profiles(driver_instance)

        # Action 4: Like Random Posts
        self._like_random_posts(driver_instance)
        
        # Optional: Add upload_fake_post here if you automate that part

        total_duration = time.monotonic() - aging_start_time
        logger.info(f"--- Finished account aging for '{user_context}' (Duration: {total_duration:.2f}s) ---")        

    def _handle_birthday_prompt(self, driver_instance=None, timeout=20, email_details_dict=None):
        # <<< THIS IS THE FIX. Note the change from email_for_confirm to email_details_dict
        """
        Handles the Instagram birthday prompt by selecting random valid values
        and then calls the email confirmation handler if it appears next.
        """
        if 'calendar' not in sys.modules:
            import calendar

        driver = driver_instance or self.driver
        if not driver:
            logger.error("BirthdayPrompt: No WebDriver instance.")
            return False

        if not email_details_dict:
            logger.error("BirthdayPrompt: Cannot proceed without email_details_dict for potential confirmation step.")
            return False

        user_context_for_log = self.current_account.get('username', 'N/A_BDAY')[:15] if self.current_account else "BDAY_PROMPT"
        logger.info(f"[{user_context_for_log}] Handling Instagram birthday prompt...")

        page_load_wait = WebDriverWait(driver, timeout)
        component_wait = WebDriverWait(driver, max(7, timeout // 2))

        try:
            # Locators
            month_xpath = "//select[@title='Month:']"
            day_xpath = "//select[@title='Day:']"
            year_xpath = "//select[@title='Year:']"
            next_button_xpath = "//button[normalize-space()='Next' and (@type='button' or @type='submit')] | //div[@role='button' and normalize-space()='Next']"

            # Wait for form
            page_load_wait.until(EC.presence_of_element_located((By.XPATH, month_xpath)))
            month_dp = self._find_element_robust(driver, [(By.XPATH, month_xpath)], component_wait, "Birthday Month Dropdown")
            day_dp = self._find_element_robust(driver, [(By.XPATH, day_xpath)], component_wait, "Birthday Day Dropdown")
            year_dp = self._find_element_robust(driver, [(By.XPATH, year_xpath)], component_wait, "Birthday Year Dropdown")

            if not (month_dp and day_dp and year_dp):
                logger.error(f"[{user_context_for_log}] Failed to find all birthday dropdowns.")
                self._save_screenshot(f"bday_dropdown_find_fail_{user_context_for_log}", driver)
                return False

            # Generate and select birthday
            year_val = random.randint(1990, 2003)
            month_val = random.randint(1, 12)
            day_val = random.randint(1, calendar.monthrange(year_val, month_val)[1])

            logger.info(f"[{user_context_for_log}] Selecting Birthday: {month_val}-{day_val}-{year_val}")
            Select(month_dp).select_by_value(str(month_val))
            self._random_delay(0.3, 0.6, driver)
            Select(day_dp).select_by_value(str(day_val))
            self._random_delay(0.3, 0.6, driver)
            Select(year_dp).select_by_value(str(year_val))
            self._random_delay(0.5, 1.0, driver)

            # Click "Next"
            next_btn_bday_el = component_wait.until(EC.element_to_be_clickable((By.XPATH, next_button_xpath)))
            if not self._js_click(next_btn_bday_el, driver):
                try:
                    next_btn_bday_el.click()
                except Exception as e:
                    logger.error(f"[{user_context_for_log}] Final click on Next button failed: {e}")
                    self._save_screenshot(f"bday_nextclick_fail_{user_context_for_log}", driver)
                    return False

            logger.info(f"[{user_context_for_log}] Clicked 'Next' on birthday page. Waiting for page transition...")
            self._random_delay(4.0, 7.0, driver_instance)

            # --- POST-SUBMIT CHECKS ---
            
            # PRIORITY 1: Check for Email Confirmation page
            email_code_heading_xpath = "//span[contains(text(),'Enter Confirmation Code')]"
            email_code_input_xpath = "//input[@name='confirmationCode']"
            try:
                WebDriverWait(driver, 5).until(EC.any_of(
                    EC.presence_of_element_located((By.XPATH, email_code_heading_xpath)),
                    EC.presence_of_element_located((By.XPATH, email_code_input_xpath))
                ))
                logger.info(f"[{user_context_for_log}] Email Confirmation page DETECTED after birthday. Handing off to email handler...")
                # The relay race hand-off: call the next function and return ITS result.
                return self._handle_email_confirmation_code(email_details_dict, driver, timeout)
            except TimeoutException:
                logger.debug(f"[{user_context_for_log}] Not an email page. Checking for main UI or other pages.")

            # PRIORITY 2: Check if successfully landed on the main feed
            try:
                WebDriverWait(driver, 7).until(EC.presence_of_element_located((
                    By.XPATH, "//nav | //div[@role='navigation'] | //a[@href='/direct/inbox/']")))
                logger.info(f"[{user_context_for_log}] Signup success: Landed directly on main feed after birthday.")
                self._handle_common_popups(["Not Now", "Cancel"], timeout=7, driver_instance=driver) # Dismiss popups
                return True
            except TimeoutException:
                # If it's not the email page and not the main feed, it's an unknown/failure state.
                logger.error(f"[{user_context_for_log}] FAILURE: Unknown page after birthday submit. Current URL: {driver.current_url}")
                self._save_screenshot(f"bday_unknown_page_{user_context_for_log}", driver)
                return False

        except Exception as e:
            logger.error(f"[{user_context_for_log}] An unhandled exception occurred in the birthday handler: {e}", exc_info=logger.level == logging.DEBUG)
            self._save_screenshot(f"bday_exception_{user_context_for_log}", driver)
            return False

    def _handle_email_confirmation_code(self, email_details_dict, driver_instance=None, timeout=180):
        """
        Handles the email confirmation code page by attempting to automatically read
        the code from the temporary email inbox.
        """
        driver = driver_instance or self.driver
        if not driver:
            logger.error("EmailConfirm: No WebDriver instance.")
            return False

        if not email_details_dict or not isinstance(email_details_dict, dict) or not email_details_dict.get('address'):
            logger.error(
                f"EmailConfirm: Invalid or missing email_details_dict for confirmation. Details: {email_details_dict}")
            return False

        email_address = email_details_dict['address']
        user_context_for_log = self.current_account.get(
            'username', 'N/A_EMAIL_CONFIRM')[:15] if self.current_account else "EMAIL_CONFIRM"
        logger.info(
            f"[{user_context_for_log}] Attempting to automatically fetch confirmation code for {email_address}...")

        code_input_xpath = "//input[@name='confirmationCode' or @aria-label='Confirmation Code']"
        next_button_xpath = "//button[normalize-space()='Next' and @type='button' or @type='submit'] | //div[@role='button' and normalize-space()='Next']"

        try:
            code_field = self._find_element_robust(driver, [(By.XPATH, code_input_xpath)], WebDriverWait(
                driver, 15), "Confirmation Code Input Field")
            if not code_field:
                logger.error(
                    f"[{user_context_for_log}] Confirmation Code input field NOT found on page. Cannot proceed.")
                self._save_screenshot(
                    f"email_code_input_missing_{user_context_for_log}", driver)
                return False

            confirmation_code = self.email_creator.read_confirmation_code(
                email_details_dict, wait_timeout_sec=timeout, poll_interval_sec=15)

            if not confirmation_code:
                logger.error(
                    f"[{user_context_for_log}] Failed to auto-retrieve confirmation code for {email_address} after {timeout}s.")
                driver_should_be_kept_open_on_fail = self._debug_pause(
                    f"Auto email code retrieval failed for {email_address}", driver, critical_failure=True)
                if driver_should_be_kept_open_on_fail and hasattr(driver, '_DEBUG_KEEP_OPEN'):
                    setattr(driver, "_DEBUG_KEEP_OPEN", True)
                self._save_screenshot(
                    f"email_code_auto_fail_{user_context_for_log}", driver)
                return False

            logger.info(
                f"[{user_context_for_log}] Automatically retrieved code: '{confirmation_code[:3]}***'. Typing...")
            if not self._human_type(code_field, confirmation_code, driver):
                logger.error(
                    f"[{user_context_for_log}] Failed to type confirmation code '{confirmation_code[:3]}***'.")
                driver_should_be_kept_open_on_fail = self._debug_pause(
                    f"Typing email code failed for {email_address}", driver, critical_failure=True)
                if driver_should_be_kept_open_on_fail and hasattr(driver, '_DEBUG_KEEP_OPEN'):
                    setattr(driver, "_DEBUG_KEEP_OPEN", True)
                self._save_screenshot(
                    f"email_code_type_fail_{user_context_for_log}", driver)
                return False

            self._random_delay(0.5, 1.0, driver)
            next_button_email_code = self._find_element_robust(driver, [(
                By.XPATH, next_button_xpath)], WebDriverWait(driver, 10), "Email Code Next Button")
            if not next_button_email_code:
                logger.error(
                    f"[{user_context_for_log}] 'Next' button on email code page not found.")
                return False

            logger.debug(
                f"[{user_context_for_log}] Clicking 'Next' after entering email code.")
            if not self._js_click(next_button_email_code, driver):
                logger.error(
                    f"[{user_context_for_log}] Failed to click 'Next' after email code.")
                return False

            logger.info(
                f"[{user_context_for_log}] Email code submitted. Waiting for final transition...")
            self._random_delay(5.0, 10.0, driver)

            current_url_after_code = driver.current_url
            logger.info(
                f"[{user_context_for_log}] URL after email code submission: {current_url_after_code}")

            failure_paths_after_code = [
                "/emailsignup/", "/login/", "/challenge/", "/confirm_email/", "contact_point_login", "/error/"]
            if "instagram.com" in current_url_after_code and not any(fp in current_url_after_code for fp in failure_paths_after_code):
                logger.info(
                    f"[{user_context_for_log}] Email confirmation successful. Landed on: {current_url_after_code}")
                self._handle_common_popups(
                    ["Not Now", "Cancel", "Save Info"], timeout=10, driver_instance=driver)
                try:
                    WebDriverWait(driver, 10).until(EC.presence_of_element_located(
                        (By.XPATH, "//nav | //div[@role='navigation'] | //a[@href='/direct/inbox/']")))
                    logger.info(
                        f"[{user_context_for_log}] Main UI confirmed. Account fully ready.")
                    return True
                except TimeoutException:
                    # FIX IS HERE: Corrected the variable name.
                    logger.warning(
                        f"[{user_context_for_log}] Landed on valid URL post-code, but main UI not detected. ({current_url_after_code})")
                    # Treat as success if passed email verification.
                    return True
            else:
                logger.error(
                    f"[{user_context_for_log}] Failed after email code submission. Landed on problematic URL: {current_url_after_code}")
                driver_should_be_kept_open_on_fail = self._debug_pause(
                    f"Fail after email code submit for {email_address}", driver, critical_failure=True)
                if driver_should_be_kept_open_on_fail and hasattr(driver, '_DEBUG_KEEP_OPEN'):
                    setattr(driver, "_DEBUG_KEEP_OPEN", True)
                self._save_screenshot(
                    f"email_code_final_fail_{user_context_for_log}", driver)
                self._check_signup_page_errors(
                    driver, user_context_for_log, context_message="after email code submit")
                return False

        except Exception as e:
            logger.error(f"[{user_context_for_log}] General error handling email confirmation: {e}",
                         exc_info=logger.level == logging.DEBUG)
            driver_should_be_kept_open_on_fail = self._debug_pause(
                f"Exception in email confirm for {email_address}", driver, critical_failure=True)
            if driver_should_be_kept_open_on_fail and hasattr(driver, '_DEBUG_KEEP_OPEN'):
                setattr(driver, "_DEBUG_KEEP_OPEN", True)
            self._save_screenshot(
                f"email_confirm_exc_{user_context_for_log}", driver)
            return False

        except Exception as e:
            logger.error(f"[{user_context_for_log}] General error handling email confirmation: {e}",
                         exc_info=logger.level == logging.DEBUG)
            driver_should_be_kept_open_on_fail = self._debug_pause(
                f"Exception in email confirm for {email_address}", driver, critical_failure=True)
            if driver_should_be_kept_open_on_fail and hasattr(driver, '_DEBUG_KEEP_OPEN'):
                setattr(driver, "_DEBUG_KEEP_OPEN", True)
            self._save_screenshot(
                f"email_confirm_exc_{user_context_for_log}", driver)
            return False
        
    def _handle_common_popups(self, button_text_keywords, timeout=5, driver_instance=None):
        """
        Attempts to find and click common pop-up buttons (like "Not Now", "Accept", "Save Info").

        Searches within typical dialog elements for buttons containing specified keywords.

        Args:
            button_text_keywords (str or list): A keyword string or list of keyword strings
                                                to look for in the button text (case-insensitive).
            timeout (int): Maximum time in seconds to wait for the popup button.
            driver_instance: Optional specific WebDriver instance. Defaults to self.driver.

        Returns:
            bool: True if a matching button was found and clicked successfully, False otherwise.
        """
        driver = driver_instance or self.driver
        if not driver:
            logger.error("Cannot handle popup: No WebDriver instance available.")
            return False

        # 1. Process Keywords
        keywords = []
        if isinstance(button_text_keywords, str):
            keywords = [button_text_keywords.lower().strip()] # Convert single string to list
        elif isinstance(button_text_keywords, list):
            # Filter out empty/None items and convert to lowercase
            keywords = [str(k).lower().strip() for k in button_text_keywords if k]
        else:
            logger.warning(f"Invalid keywords type provided for popup handling: {type(button_text_keywords)}. Expected str or list.")
            return False

        if not keywords:
            logger.warning("No valid keywords provided for popup handling.")
            return False

        logger.debug(f"Checking for common popup with button keywords: {keywords} (Timeout: {timeout}s)")

        # 2. Build Robust XPath
        try:
            # Create XPath condition for matching any keyword (case-insensitive)
            # translate() converts text to lowercase before comparison
            kw_cond = " or ".join([
                f"contains(translate(normalize-space(.), 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), '{kw}')"
                for kw in keywords
            ])

            # Construct the final XPath:
            # - Look inside standard dialog roles OR simple body divs (potential overlays)
            # - Find <button> elements OR elements with role="button"
            # - Ensure the button is not disabled (standard @disabled or @aria-disabled)
            # - Match the keyword condition
            xpath = (
                # Target potential popup container elements
                f"(//div[@role='dialog' or @role='alertdialog'] | //body/div[count(./*) < 5 and not(@id='react-root')])" # Added exclusion for main react root
                # Find standard <button> elements inside
                f"//button[({kw_cond}) and not(@disabled)]"
                # --- OR ---
                f" | "
                # Target potential popup container elements again
                f"(//div[@role='dialog' or @role='alertdialog'] | //body/div[count(./*) < 5 and not(@id='react-root')])"
                # Find elements acting as buttons via ARIA role
                f"//*[@role='button'][({kw_cond}) and not(@aria-disabled='true')]"
            )
            logger.debug(f"Popup Handler XPath: {xpath}") # Log the constructed XPath for debugging

            # 3. Wait for the button to be clickable
            popup_button = WebDriverWait(driver, timeout).until(
                EC.element_to_be_clickable((By.XPATH, xpath))
            )

            # 4. Get Button Text (for logging) and Click
            btn_text = "[Text Fetch Error]" # Default text if fetching fails
            try:
                # Prioritize aria-label if available, fallback to visible text
                btn_text = popup_button.get_attribute('aria-label') or popup_button.text or "[Empty Text/Label]"
                btn_text = btn_text.strip()
            except Exception:
                pass # Ignore errors fetching text, we still try to click

            logger.debug(f"Found potential popup button: '{btn_text}' matching keywords: {keywords}")

            # 5. Attempt JS Click
            if self._js_click(popup_button, driver):
                logger.info(f"Successfully clicked popup button: '{btn_text}' (Matched Keywords: {keywords})")
                self._random_delay(0.8, 1.8, driver) # Delay after clicking popup
                return True
            else:
                logger.warning(f"Found popup button '{btn_text}' but the JavaScript click failed.")
                return False

        # 6. Handle Expected Exceptions (Popup not found)
        except (TimeoutException, NoSuchElementException, StaleElementReferenceException):
            logger.debug(f"Popup button matching '{keywords}' was not found, became stale, or timed out within {timeout}s.")
            return False

        # 7. Handle WebDriver Exceptions
        except WebDriverException as e:
            # Log WebDriver errors at a higher level unless debugging
            level = logging.DEBUG if logger.level == logging.DEBUG else logging.WARNING
            logger.log(level, f"WebDriverException occurred while handling popup '{keywords}': {type(e).__name__}")
            # Don't show full traceback unless debugging
            return False

        # 8. Handle Other Unexpected Exceptions
        except Exception as e:
            logger.warning(
                f"An unexpected error occurred while handling popup '{keywords}': {e}",
                exc_info=logger.level == logging.DEBUG # Show traceback if debugging
            )
            return False

    def _save_account_to_csv(self, account_dict):
        if not account_dict or not account_dict.get('username'):
            logger.error("Attempted save invalid account data.")
            return
        file_path = Path(ACCOUNT_CSV_FILENAME)
        fieldnames = ["username", "email", "password", "status", "created_at", "reports_made", "last_report_time", "proxy_used", "user_agent"]
        username_to_save = account_dict['username']
        logger.debug(f"Saving/Updating '{username_to_save}' in CSV '{file_path.name}'...")
        with self._csv_lock:
            try:
                accounts_data = []
                file_exists = file_path.is_file()
                updated = False
                if file_exists:
                    try:
                        with open(file_path, "r", newline="", encoding='utf-8') as infile:
                            reader = csv.DictReader(infile)
                            if not reader.fieldnames or not all(f in reader.fieldnames for f in ["username", "password"]):
                                logger.error(f"CSV '{file_path.name}' invalid header. Will overwrite.")
                                file_exists = False
                            else:
                                accounts_data = [row for row in reader if any(row.values())]
                    except (FileNotFoundError, PermissionError):
                        logger.error(f"Cannot read existing CSV '{file_path.name}'.")
                        file_exists = False
                    except Exception as read_err:
                        logger.error(f"Error reading CSV '{file_path.name}': {read_err}. Will overwrite.", exc_info=True)
                        file_exists = False

                row_data = account_dict.copy()
                for key in ["created_at", "last_report_time"]:
                    ts = row_data.get(key)
                    row_data[key] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts)) if isinstance(ts, (int, float)) and ts > 0 else ""

                account_found_index = next((i for i, acc in enumerate(accounts_data) if acc.get('username') == username_to_save), -1)

                if account_found_index != -1:
                    # Update existing entry
                    for key, value in row_data.items():
                        if key in fieldnames: # Only update known fields
                            accounts_data[account_found_index][key] = value
                    updated = True
                    logger.debug(f"Updating entry for '{username_to_save}'.")
                else:
                    # Add new entry, ensuring all fields are present
                    new_row = {field: row_data.get(field, "") for field in fieldnames}
                    accounts_data.append(new_row)
                    logger.debug(f"Adding new entry for '{username_to_save}'.")

                try:
                    # Write the potentially modified data back to the CSV
                    with open(file_path, "w", newline="", encoding='utf-8') as outfile:
                        writer = csv.DictWriter(outfile, fieldnames=fieldnames, extrasaction='ignore', restval='')
                        writer.writeheader()
                        writer.writerows(accounts_data)
                    logger.info(f"Successfully {'updated' if updated else 'added'} '{username_to_save}' in '{file_path.name}'.")
                except (PermissionError, csv.Error, IOError) as write_e:
                    logger.critical(f"CSV SAVE FAILED for '{username_to_save}' to '{file_path}': {write_e}")

            except Exception as outer_e:
                logger.error(f"Outer CSV save error for '{username_to_save}': {outer_e}", exc_info=True)
            
    def load_accounts_from_csv(self, filename=ACCOUNT_CSV_FILENAME):
        """Loads account data from the specified CSV file."""
        file_path = Path(filename)
        logger.info(f"Loading accounts from: {file_path.name}")

        # Check if file exists first
        if not file_path.is_file():
            logger.warning(f"Account file '{filename}' not found. No accounts loaded.")
            # Ensure accounts list is empty if file doesn't exist
            with self.account_lock:
                self.accounts = []
            return # Exit the function

        # Initialize lists/sets for loading
        loaded_accounts = []
        loaded_usernames = set()
        required_fields = ["username", "password"] # Essential headers

        try:
            # Use lock for reading the file (although less critical than writing)
            with self._csv_lock, open(file_path, "r", newline="", encoding='utf-8') as file:
                reader = csv.DictReader(file)

                # Validate headers
                if not reader.fieldnames or not all(f in reader.fieldnames for f in required_fields):
                    logger.error(
                        f"CSV file '{filename}' is missing required headers ({required_fields}). Load aborted."
                    )
                    # Keep existing accounts if load fails due to headers? Or clear?
                    # Let's clear to match original intent on failure.
                    with self.account_lock:
                        self.accounts = []
                    return # Exit the function

                # Process each row in the CSV
                for i, row in enumerate(reader):
                    line_num = i + 2 # For user-friendly logging (1-based index + header)

                    # Skip completely empty rows
                    if not any(val.strip() for val in row.values()):
                        logger.debug(f"Skipping empty row {line_num}.")
                        continue

                    # --- Extract Core Fields ---
                    username = row.get("username", "").strip()
                    password = row.get("password", "").strip()

                    # Validate essential fields
                    if not username or not password:
                        logger.warning(f"Skipping row {line_num}: Missing required username or password.")
                        continue # Skip row if essential data is missing

                    # Check for duplicate usernames within this load operation
                    if username in loaded_usernames:
                        logger.warning(f"Skipping duplicate username '{username}' found at row {line_num}.")
                        continue # Skip this duplicate row

                    # --- Extract Optional Fields & Parse ---
                    email = row.get("email", "").strip()
                    # Default status to 'unknown' if missing or empty
                    status = (row.get("status", "").strip().lower() or "unknown")

                    # --- Define Timestamp Parsing Helper ---
                    # Defined inside the loop scope but only once per load call
                    # (Could be moved outside or made a static method for minor optimization)
                    def parse_ts(ts_str, field_name):
                        """Parses YYYY-MM-DD HH:MM:SS string to Unix timestamp."""
                        if not ts_str: # Handle empty timestamp strings
                            return 0.0
                        try:
                            # Attempt to parse the standard format
                            return time.mktime(time.strptime(ts_str, "%Y-%m-%d %H:%M:%S"))
                        except (ValueError, TypeError, OSError):
                            # Log warning if parsing fails
                            logger.warning(f"Row {line_num}: Invalid timestamp format for '{field_name}': '{ts_str}'. Using 0.")
                            return 0.0

                    # Parse timestamps using the helper
                    created_ts = parse_ts(row.get("created_at", "").strip(), "created_at")
                    last_report_ts = parse_ts(row.get("last_report_time", "").strip(), "last_report_time")

                    # Parse reports_made count
                    reports_made = 0
                    reports_str = row.get("reports_made", "0").strip() # Default to "0" if missing
                    if reports_str: # Attempt conversion only if string is not empty
                        try:
                            reports_made = max(0, int(reports_str)) # Ensure non-negative integer
                        except ValueError:
                            logger.warning(f"Row {line_num}: Invalid value for reports_made: '{reports_str}'. Using 0.")

                    # --- Construct Account Dictionary ---
                    account = {
                        "username": username,
                        "password": password,
                        "email": email,
                        "status": status,
                        "created_at": created_ts,
                        "reports_made": reports_made,
                        "last_report_time": last_report_ts,
                        "proxy_used": row.get("proxy_used", "").strip(), # Get optional fields
                        "user_agent": row.get("user_agent", "").strip()
                    }

                    # Add the processed account to our temporary list and track username
                    loaded_accounts.append(account)
                    loaded_usernames.add(username)
                    # End of loop for processing rows

            # --- Update Manager's Account List ---
            # If the try block completed without critical errors, update the main list
            with self.account_lock:
                self.accounts = loaded_accounts # Replace the old list with the newly loaded one
                logger.info(f"Successfully loaded {len(self.accounts)} unique accounts from '{filename}'.")

        # --- Exception Handling ---
        except (PermissionError, csv.Error, IOError) as e:
            # Handle specific file I/O or CSV format errors
            logger.critical(f"CSV LOAD FAILED for '{file_path}': {type(e).__name__} - {e}")
            # Clear accounts if load fails critically here
            with self.account_lock:
                self.accounts = []
        except Exception as e:
            # Handle any other unexpected errors during loading
            logger.error(
                f"Unexpected error while loading accounts from '{filename}': {e}",
                exc_info=True # Include traceback for unexpected errors
            )
            # Clear accounts if load fails critically here
            with self.account_lock:
                self.accounts = []
             
    # --- Login Method ---

    def login(self, account_to_login, driver_instance_override=None, update_main_driver=True):
        """Logs into an Instagram account. Can use override driver and optionally update self.driver."""
        if not account_to_login or not account_to_login.get('username'):
            logger.error("Login Failed: Invalid account data provided.")
            return False

        username = account_to_login['username']
        password = account_to_login['password']
        log_prefix_base = f"Login-{username[:10]}" # Use first 10 chars of username for brevity
        logger.info(f"[{log_prefix_base}]: Attempting login for '{username}'...")

        # Determine if using an isolated (override) driver or the main instance driver
        driver_to_use_initially = driver_instance_override
        is_isolated = driver_instance_override is not None
        if is_isolated:
            update_main_driver = False # Never update main driver if using an isolated one
            log_prefix_base += "-Iso" # Append suffix for isolated logs

        # --- Pre-Login Checks (only if using main driver) ---
        if not is_isolated:
            if self.driver and self.current_account and self.current_account.get('username') == username:
                # Check if already logged in with the target account on the main driver
                try:
                    # Quick check for a common element indicating logged-in state (e.g., nav bar)
                    WebDriverWait(self.driver, 3).until(EC.presence_of_element_located((By.XPATH, "//nav | //div[@role='navigation']")))
                    logger.info(f"[{log_prefix_base}]: Session for '{username}' is already active on main driver. Skipping login.")
                    return True # Already logged in
                except TimeoutException:
                    logger.warning(f"[{log_prefix_base}]: Main driver exists but session for '{username}' seems inactive. Proceeding with login attempt.")
                    self.close_driver() # Close potentially stale driver before trying again
                except Exception as check_err: # Catch other potential errors during check
                    logger.warning(f"[{log_prefix_base}]: Error checking active session ({check_err}). Proceeding with login attempt.")
                    self.close_driver()
            elif self.driver:
                # Close existing main driver if it's active but for a *different* user
                prev_user = self.current_account.get('username', '?') if self.current_account else 'None'
                logger.info(f"[{log_prefix_base}]: Closing existing main driver session (User: '{prev_user}') before logging in as '{username}'.")
                self.close_driver()

        # --- Login Attempt Loop ---
        login_success = False
        max_attempts = self.settings.get("max_login_attempts", 2)
        local_driver_for_login = None # Driver instance managed within this function if not isolated
        driver_to_use_this_attempt = driver_to_use_initially # Track override driver use per attempt

        for attempt in range(max_attempts):
            log_prefix = f"{log_prefix_base}-Att-{attempt+1}"
            logger.info(f"[{log_prefix}]: Starting login attempt {attempt+1}/{max_attempts}...")
            driver_instance = None # Clear driver instance for the start of the attempt

            # --- Setup Driver for this attempt ---
            if driver_to_use_this_attempt:
                # Use the provided override driver (might only be used for the first attempt if it fails)
                driver_instance = driver_to_use_this_attempt
                logger.debug(f"[{log_prefix}]: Using provided isolated driver instance.")
            else:
                # Need to manage local driver lifecycle (only if not using an override)
                if local_driver_for_login: # Should be None unless previous attempt failed setup? Close just in case.
                    logger.warning(f"[{log_prefix}]: Unexpected existing local driver found, attempting cleanup.")
                    try:
                        local_driver_for_login.quit()
                    except Exception: pass
                    local_driver_for_login = None
                    self.current_proxy_address = None # Clear proxy if we had to close driver

                # Set up a new main driver instance for this attempt
                logger.debug(f"[{log_prefix}]: Setting up new driver instance for login...")
                local_driver_for_login = self._setup_driver() # Uses main setup logic
                if not local_driver_for_login:
                    logger.warning(f"[{log_prefix}]: WebDriver setup failed for attempt {attempt+1}.")
                    # Retry only if there are more attempts left
                    if attempt < max_attempts - 1:
                        logger.info(f"[{log_prefix}]: Retrying driver setup after delay...")
                        self._random_delay(5, 10) # Wait longer if setup failed
                        continue # Go to next attempt
                    else:
                        logger.error(f"[{log_prefix}]: WebDriver setup failed on final attempt. Aborting login.")
                        break # Exit loop if setup fails on last attempt
                driver_instance = local_driver_for_login # Use the newly created local driver

            # Skip rest of attempt if driver setup failed and loop didn't continue/break
            if not driver_instance:
                logger.error(f"[{log_prefix}]: Critical error - driver instance is None despite setup logic. Skipping attempt.")
                continue

            # --- Perform Login Actions ---
            try:
                # Setup WebDriverWait for this attempt
                wait_timeout = self.settings.get("webdriver_wait_timeout", 15) + 10 # Extra time for login page
                wait = WebDriverWait(driver_instance, wait_timeout)
                login_url = self.platform_urls['login']

                # Navigate to login page
                logger.debug(f"[{log_prefix}]: Navigating to login page: {login_url}")
                driver_instance.get(login_url)
                self._random_delay(1.5, 3.5, driver_instance) # Allow page to load

                # Handle potential cookie banners
                self._handle_common_popups(["Accept", "Allow", "Allow essential and optional cookies"], timeout=5, driver_instance=driver_instance)

                # Fill login form
                logger.debug(f"[{log_prefix}]: Locating and filling login form fields...")
                user_selectors = [(By.NAME, "username"), (By.XPATH, "//input[@aria-label='Phone number, username, or email']")]
                pass_selectors = [(By.NAME, "password"), (By.XPATH, "//input[@aria-label='Password']")]

                user_field = self._find_element_robust(driver_instance, user_selectors, wait, "Login Username")
                if not user_field:
                    logger.warning(f"[{log_prefix}]: Failed to find username field. Skipping attempt.")
                    continue # Skip to next attempt if critical element missing

                pass_field = self._find_element_robust(driver_instance, pass_selectors, wait, "Login Password")
                if not pass_field:
                    logger.warning(f"[{log_prefix}]: Failed to find password field. Skipping attempt.")
                    continue # Skip to next attempt

                # Type credentials
                self._human_type(user_field, username, driver_instance)
                self._human_type(pass_field, password, driver_instance)
                self._random_delay(0.5, 1.5, driver_instance)

                # Click login button
                logger.debug(f"[{log_prefix}]: Locating and clicking login button...")
                login_xpath = "//button[@type='submit'][.//div[contains(text(),'Log in')] or contains(., 'Log in') or contains(.,'Log In')]"
                login_btn = self._find_element_robust(driver_instance, [(By.XPATH, login_xpath)], wait, "Login Button")
                if not login_btn:
                    logger.warning(f"[{log_prefix}]: Failed to find login button. Skipping attempt.")
                    continue # Skip to next attempt

                self._js_click(login_btn, driver_instance) # Use JS click for reliability
                logger.info(f"[{log_prefix}]: Login button clicked. Waiting for outcome...")

                # Wait for page transition or indicators of success/failure
                outcome_timeout = 30 # Seconds to wait for a recognizable outcome
                # Define possible outcome conditions (URLs, elements indicating success/failure/challenge)
                conditions = [
                    EC.url_contains("?__coig_login"), # Common success indicator?
                    EC.url_matches(r"https://www\.instagram\.com/(?:$|\?.*$)"), # Base domain (potential success)
                    EC.presence_of_element_located((By.XPATH, "//nav | //div[@role='navigation']")), # Main navigation (success)
                    EC.url_contains("/challenge/"), # Challenge required
                    EC.url_contains("/suspended/"), # Account suspended
                    EC.url_contains("/disabled/"), # Account disabled
                    EC.url_contains("/onetap/"), # "Save login info?" prompt page
                    EC.url_contains("/login/"), # Still on login page (potential failure)
                    EC.presence_of_element_located((By.ID, "slfErrorAlert")), # Specific error message element
                    EC.presence_of_element_located((By.XPATH, "//*[contains(text(), 'password was incorrect')]")), # Incorrect password text
                    EC.presence_of_element_located((By.XPATH, "//*[contains(text(), 'find your account')]")), # Username not found text
                    EC.presence_of_element_located((By.XPATH, "//*[contains(text(), 'Turn on Notifications')]")) # Post-login prompt page
                ]
                try:
                    # Wait until any of the defined conditions are met
                    WebDriverWait(driver_instance, outcome_timeout).until(EC.any_of(*conditions))
                    logger.debug(f"[{log_prefix}]: A login outcome condition was met.")
                    self._random_delay(1.5, 3.0, driver_instance) # Short delay after condition met
                except TimeoutException:
                    # If none of the conditions are met within the timeout
                    logger.error(f"[{log_prefix}]: Login outcome timed out after {outcome_timeout}s. Assuming failure for this attempt.")
                    self._save_screenshot(f"login_timeout_{username}", driver_instance)
                    continue # Skip to next attempt

                # --- Analyze Outcome ---
                current_url = "ErrorFetchingURL"
                page_source_lower = ""
                try:
                    current_url = driver_instance.current_url
                    # Get page source only if needed for error checks
                    if "/login/" in current_url or current_url == "ErrorFetchingURL":
                        page_source_lower = driver_instance.page_source.lower()
                except WebDriverException as url_err:
                    logger.warning(f"[{log_prefix}]: Could not get current URL or page source after login attempt: {url_err}")

                logger.debug(f"[{log_prefix}]: Analyzing login outcome. Current URL: {current_url}")

                # Check for specific failure conditions first
                if ("password was incorrect" in page_source_lower or
                        "find your account" in page_source_lower or
                        (driver_instance.find_elements(By.ID, "slfErrorAlert") and "/login/" in current_url)):
                    logger.error(f"[{log_prefix}]: Login Failed - Incorrect username or password indicated.")
                    account_to_login["status"] = "login_failed" # Update account status
                    break # Exit loop, no point retrying with wrong creds

                elif "/challenge/" in current_url:
                    logger.error(f"[{log_prefix}]: Login Failed - Verification challenge required.")
                    account_to_login["status"] = "challenge"
                    break # Exit loop, requires manual intervention

                elif any(b in current_url for b in ["/suspended/", "/disabled/", "account_disabled"]):
                    logger.error(f"[{log_prefix}]: Login Failed - Account is suspended or disabled.")
                    account_to_login["status"] = "banned"
                    break # Exit loop, account unusable

                # Check for intermediate pages that need dismissal
                elif "/onetap/" in current_url or "turn_on_notifications" in current_url:
                    logger.info(f"[{log_prefix}]: Intermediate page detected ({current_url}). Attempting to dismiss...")
                    dismissed = self._handle_common_popups(["Not Now", "Cancel"], timeout=5, driver_instance=driver_instance)
                    if dismissed:
                        self._random_delay(2, 4, driver_instance) # Wait after dismissal
                        # Re-check URL after dismissal
                        try:
                            current_url = driver_instance.current_url
                            logger.debug(f"[{log_prefix}]: URL after dismissing intermediate page: {current_url}")
                            # Now, re-evaluate based on the new URL (fall through to success check)
                        except WebDriverException as url_err_post_dismiss:
                            logger.warning(f"[{log_prefix}]: Could not get URL after dismissing intermediate page: {url_err_post_dismiss}. Assuming failure.")
                            continue # Assume failure if URL check fails after dismiss
                    else:
                        logger.warning(f"[{log_prefix}]: Failed to find/click dismiss button on intermediate page. Assuming failure for this attempt.")
                        self._save_screenshot(f"login_intermediate_stuck_{username}", driver_instance)
                        continue # Skip to next attempt

                # Check for success conditions (should be checked after handling intermediate pages)
                # Check if we are on instagram.com but NOT on a known failure/intermediate page
                is_likely_success_url = ("instagram.com" in current_url and not any(f in current_url for f in ["/login", "/challenge/", "/suspended/", "/disabled/", "/error/", "/onetap/"]))
                if is_likely_success_url:
                    try:
                        # Verify success by looking for a key UI element (e.g., main navigation)
                        WebDriverWait(driver_instance, 5).until(EC.presence_of_element_located((By.XPATH, "//nav | //div[@role='navigation']")))
                        logger.info(f"[{log_prefix}]: Login SUCCESS confirmed by presence of navigation element.")
                        login_success = True
                        account_to_login["status"] = "active" # Update account status

                        # If updating the main driver, assign it and the account
                        if update_main_driver:
                            logger.debug(f"[{log_prefix}]: Updating main driver instance.")
                            self.driver = driver_instance
                            self.current_account = account_to_login
                            local_driver_for_login = None # Prevent this driver from being closed in finally block

                        # Handle potential post-login popups ("Save Info?", "Notifications?")
                        self._handle_common_popups(["Not Now", "Cancel"], timeout=6, driver_instance=driver_instance)
                        self._handle_common_popups("Save Info", timeout=4, driver_instance=driver_instance) # Optional
                        break # Exit loop on success

                    except TimeoutException:
                        # URL looks okay, but main UI element not found - could be partial load or A/B test
                        logger.error(f"[{log_prefix}]: Login URL appears successful, but key UI element (nav) not found. Treating as partial/failed login.")
                        self._save_screenshot(f"login_partial_ui_missing_{username}", driver_instance)
                        continue # Try next attempt if available

                else:
                    # If none of the above conditions matched (and not timed out)
                    logger.error(f"[{log_prefix}]: Login resulted in unexpected state. URL: {current_url}. Assuming failure for this attempt.")
                    self._save_screenshot(f"login_unexpected_state_{username}", driver_instance)
                    continue # Try next attempt if available

            # --- Exception Handling for the current attempt ---
            except WebDriverException as e:
                logger.error(f"[{log_prefix}]: WebDriverException during login attempt: {e}", exc_info=logger.level == logging.DEBUG)
                self._save_screenshot(f"login_wd_exception_{username}", driver_instance)
                # Check if it's likely a network/proxy error - if so, break retries for this proxy
                if any(term in str(e).lower() for term in ["proxy", "refused", "net::err_", "timeout", "dns_probe", "unreachable"]):
                    logger.error(f"[{log_prefix}]: Exception suggests network or proxy issue. Aborting retries for this login sequence.")
                    account_to_login["status"] = "proxy_error" # Set specific status
                    break # Exit retry loop for this account
                # Otherwise, continue to next attempt if available
            except Exception as e:
                logger.error(f"[{log_prefix}]: Unexpected error during login attempt: {e}", exc_info=True)
                self._save_screenshot(f"login_exception_{username}", driver_instance)
                # Continue to next attempt if available

            # --- Finally block for the current attempt ---
            finally:
                # Cleanup logic specific to this attempt
                if is_isolated and not login_success and driver_to_use_this_attempt:
                    # If using an override driver and it failed this attempt
                    logger.warning(f"[{log_prefix}]: Isolated login attempt failed. Driver override will not be used for subsequent attempts (if any). Caller is responsible for managing this driver instance.")
                    driver_to_use_this_attempt = None # Stop using the override for next attempts

                elif local_driver_for_login and not login_success:
                    # If using a locally managed driver and it failed (and wasn't handed over on success)
                    logger.debug(f"[{log_prefix}]: Closing locally managed driver after unsuccessful attempt.")
                    try:
                        local_driver_for_login.quit()
                    except Exception as quit_err:
                        logger.warning(f"[{log_prefix}]: Error closing unsuccessful local driver: {quit_err}")
                    local_driver_for_login = None # Ensure it's reset
                    self.current_proxy_address = None # Clear proxy associated with the failed driver

            # --- End of Try/Except/Finally for one attempt ---

            # Add delay between attempts if not successful and more attempts remain
            if attempt < max_attempts - 1 and not login_success:
                delay_duration = random.uniform(2, 5)
                logger.info(f"[{log_prefix}]: Login attempt failed. Waiting {delay_duration:.2f}s before next attempt...")
                time.sleep(delay_duration) # Use time.sleep for inter-attempt delay

        # --- End of Login Attempt Loop ---

        # --- Post-Loop Finalization ---
        if not login_success:
            # Log failure if all attempts were exhausted or broken early
            final_status = account_to_login.get('status', 'unknown_failure') # Get status set during attempts
            logger.error(f"All {max_attempts} login attempts FAILED for '{username}'. Final determined status: {final_status}")
            # If this was supposed to update the main driver, ensure it's cleared on failure
            if update_main_driver:
                self.current_account = None
                # Ensure driver is closed if it wasn't already handled (e.g., final setup fail)
                if self.driver:
                    logger.debug("Clearing main driver instance due to overall login failure.")
                    # self.close_driver() # close_driver sets self.driver to None
                if local_driver_for_login: # Close lingering local driver if exists
                    try: local_driver_for_login.quit()
                    except: pass
                    local_driver_for_login = None

        else:
            logger.debug(f"Login sequence completed successfully for '{username}'.")

        # Save the final state of the account (status, etc.) to CSV regardless of success/failure
        self._save_account_to_csv(account_to_login)

        return login_success # Return the final success state

    # --- Report & Mass Report ---

    def report_account(self, target_username, reason="spam", driver_instance=None, reporting_account=None):
        """
        Attempts to report a target Instagram profile using the specified account and reason.

        Performs rate limiting checks (daily and interval) before proceeding.

        Args:
            target_username (str): The username of the account to report.
            reason (str): The reason category for the report (e.g., "spam", "hate", "scam").
            driver_instance: Optional specific WebDriver instance to use. Defaults to self.driver.
            reporting_account (dict): Optional specific account dictionary to use for reporting
                                    and tracking limits. Defaults to self.current_account.

        Returns:
            bool or str:
                - True: If the report submission process seemed successful.
                - False: If the report failed due to rate limits, WebDriver issues,
                        element finding issues, or other errors during the process.
                - "target_not_found": If the target profile page indicated the account doesn't exist.
        """
        # 1. --- Initialization and Validation ---
        driver = driver_instance or self.driver
        account = reporting_account or self.current_account

        # Validate inputs
        if not driver:
            logger.error("Report Failed: No WebDriver instance available.")
            return False
        if not account or 'username' not in account:
            logger.error("Report Failed: Invalid or missing reporting account data.")
            return False
        if not target_username or not isinstance(target_username, str) or not target_username.strip():
            logger.error("Report Failed: Invalid or empty target username provided.")
            return False

        # Prepare variables
        target_username = target_username.strip()
        current_acc_username = account.get('username', 'N/A')
        log_prefix = f"Report-{current_acc_username[:10]}-to-{target_username[:10]}" # Short log prefix
        logger.info(f"[{log_prefix}]: Initiating report for target '{target_username}' with reason '{reason}' by account '{current_acc_username}'.")

        # 2. --- Rate Limiting Checks ---
        now = time.time()
        reports_made_today = account.get("reports_made", 0)
        last_report_time = account.get("last_report_time", 0)
        max_reports = self.settings.get("max_reports_per_day", 15)
        min_interval = self.settings.get("report_interval_seconds", 1800)

        # Reset daily count if more than a day has passed
        # Add a small buffer (5%) to account for timing variations
        if (now - last_report_time) > (86400 * 1.05):
            if reports_made_today > 0: # Only log if count was > 0
                logger.info(f"[{log_prefix}]: Daily report count for '{current_acc_username}' reset (was {reports_made_today}).")
            reports_made_today = 0
            account["reports_made"] = 0 # Update the count in the dictionary

        # Check daily limit
        if reports_made_today >= max_reports:
            logger.warning(f"[{log_prefix}]: Report skipped - Daily limit ({max_reports}) reached for account '{current_acc_username}'.")
            # Flag for worker coordination if reporting_account was provided
            if reporting_account:
                account["_worker_rate_limited"] = True
            return False # Report skipped due to daily limit

        # Check interval limit (only if a previous report time exists)
        time_since_last = now - last_report_time
        if last_report_time != 0 and time_since_last < min_interval:
            wait_needed = min_interval - time_since_last
            logger.info(f"[{log_prefix}]: Report skipped - Cooldown active for account '{current_acc_username}'. {wait_needed:.0f}s remaining.")
            # Flag for worker coordination
            if reporting_account:
                account["_worker_rate_limited"] = True
            return False # Report skipped due to interval cooldown

        # Clear rate limit flag if checks passed (in case it was set previously)
        account.pop("_worker_rate_limited", None)

        # 3. --- Reporting Steps ---
        wait_timeout = self.settings.get("webdriver_wait_timeout", 15) + 5 # Slightly longer wait for profile/dialogs
        wait = WebDriverWait(driver, wait_timeout)
        short_wait = WebDriverWait(driver, 10) # Shorter wait for elements within already loaded dialogs
        profile_url = f"{self.platform_urls['base']}{urllib.parse.quote(target_username)}/"

        try:
            # Navigate to Target Profile
            logger.debug(f"[{log_prefix}]: Navigating to target profile: {profile_url}")
            driver.get(profile_url)
            self._random_delay(2.5, 5, driver) # Allow profile page to load

            # Check if Target Profile Exists
            try:
                # Look for common "page not found" text patterns
                not_found_xpath = "//*[contains(text(), \"Sorry, this page isn't available\") or contains(text(), \"Page Not Found\") or contains(text(), \"couldn't find this account\") or contains(h2,'Something Went Wrong')]"
                # Use a short wait, as this text appears quickly if the page is invalid
                WebDriverWait(driver, 4).until(EC.presence_of_element_located((By.XPATH, not_found_xpath)))
                # If the above line doesn't raise TimeoutException, the element was found
                logger.error(f"[{log_prefix}]: REPORT FAILED - Target profile '{target_username}' page indicates account not found or unavailable.")
                self._save_screenshot(f"report_target_nf_{target_username}", driver)
                return "target_not_found" # Specific return value for "not found"
            except TimeoutException:
                # Element not found, profile is likely accessible
                logger.debug(f"[{log_prefix}]: Target profile page appears accessible.")
            except WebDriverException as wd_err:
                # Handle potential driver errors during the check
                logger.error(f"[{log_prefix}]: WebDriverException while checking profile availability: {wd_err}")
                return False # Fail the report if this check errors out

            # Click Profile Options Menu (...)
            logger.debug(f"[{log_prefix}]: Attempting to click profile options menu (...)")
            # More robust XPath for the options button, covering different page layouts/versions
            opts_xpath = (
                "//header//button[descendant::*[local-name()='svg' and @aria-label='Options']] | " # SVG icon button in header
                "//header//button[.//span[@aria-label='Options']] | " # Span icon button in header
                "//div[h1]/following-sibling::button[.//span[@aria-label='Options']] | " # Button next to H1 (newer layout?)
                "//h2/following-sibling::button[.//span[@aria-label='Options']] | " # Button next to H2 (mobile layout?)
                "//button[@aria-label='User options' or @aria-label='Options']" # Direct aria-label match
            )
            options_btn = self._find_element_robust(driver, [(By.XPATH, opts_xpath)], wait, "Profile Options Button")
            if not options_btn:
                logger.error(f"[{log_prefix}]: REPORT FAILED - Could not find the profile options (...) button.")
                self._save_screenshot(f"report_opts_fail_{target_username}", driver)
                return False
            self._js_click(options_btn, driver)
            self._random_delay(0.8, 1.8, driver) # Wait for options menu to appear

            # Click 'Report' Option in Menu
            logger.debug(f"[{log_prefix}]: Attempting to click 'Report' option in the menu...")
            # XPath for the 'Report' button within a dialog or menu role
            report_xpath = "//div[@role='dialog' or @role='menu']//button[normalize-space()='Report' or normalize-space()='Report...']"
            report_opt_button = self._find_element_robust(driver, [(By.XPATH, report_xpath)], short_wait, "Report Option")
            if not report_opt_button:
                logger.error(f"[{log_prefix}]: REPORT FAILED - Could not find the 'Report' option in the menu.")
                self._save_screenshot(f"report_menu_fail_{target_username}", driver)
                return False
            self._js_click(report_opt_button, driver)
            self._random_delay(1.5, 3, driver) # Wait for report reason dialog to appear

            # Handle the Multi-Step Report Reason Flow
            logger.debug(f"[{log_prefix}]: Entering report reason selection flow for reason: '{reason}'")
            report_successful = self._handle_report_reason_flow(driver, reason, wait, short_wait, log_prefix)

            # Process Result of Reason Flow
            if report_successful:
                # Update account stats upon success
                with self.account_lock: # Ensure thread-safe update
                    current_reports = account.get("reports_made", 0)
                    account["reports_made"] = current_reports + 1
                    account["last_report_time"] = now # Record time of this successful report
                    logger.info(
                        f"[{log_prefix}]: Report submission process completed successfully. "
                        f"Report count for '{current_acc_username}' updated to: {account['reports_made']}."
                    )
                # Save account data if it's the main active account being used
                # (Worker threads handle saving their own accounts externally)
                if account is self.current_account:
                    self._save_account_to_csv(account)
                return True # Indicate overall success
            else:
                # Reason flow failed
                logger.error(f"[{log_prefix}]: Report reason selection flow failed or did not complete successfully.")
                # Screenshot might have been taken inside _handle_report_reason_flow
                return False # Indicate failure

        # 4. --- Exception Handling for the Entire Process ---
        except WebDriverException as e:
            logger.error(f"[{log_prefix}]: WebDriverException occurred during report process: {e}", exc_info=logger.level == logging.DEBUG)
            # Check if the session died
            if any(term in str(e).lower() for term in ["session deleted", "no such window", "invalid session", "target closed"]):
                logger.error(f"[{log_prefix}]: WebDriver session appears closed. Attempting cleanup.")
                # Close the main driver if it was the one that failed
                if driver is self.driver:
                    self.close_driver()
            # Return False for WebDriver errors
            return False
        except Exception as e:
            # Catch any other unexpected errors
            logger.error(f"[{log_prefix}]: An unexpected error occurred during the report process: {e}", exc_info=True)
            self._save_screenshot(f"report_unexpected_{target_username}", driver)
            return False
    
    def _handle_report_reason_flow(self, driver, reason_str, wait, short_wait, log_prefix):
        """
        Navigates the multi-step report reason dialog based on the provided reason string.
        (Docstring added for clarity based on context)

        Args:
            driver: The Selenium WebDriver instance.
            reason_str (str): The reason provided by the user (e.g., "spam", "hate speech").
            wait: WebDriverWait instance for longer waits (initial dialog load).
            short_wait: WebDriverWait instance for shorter waits (elements within dialogs).
            log_prefix (str): Prefix for logging messages.

        Returns:
            bool: True if the submission confirmation is detected, False otherwise.
        """
        reason_lower = reason_str.lower().strip()

        # Map user-friendly reasons to Instagram's likely keywords/phrases
        reason_map = {
            "spam": "spam",
            "scam": "scam or fraud",
            "hate": "hate speech",
            "bullying": "bullying or harassment",
            "nudity": "nudity or sexual",
            "violence": "violence or dangerous",
            "intellectual property": "intellectual property",
            "sale": "sale of illegal or regulated",
            "self-injury": "suicide or self-injury",
            "false information": "false information",
            "impersonation": "pretending to be",
            "underage": "under the age of 13",
            "something else": "something else" # Fallback
        }

        # Determine Primary Reason Keyword
        selected_reason_text = "Something Else"
        primary_reason_keyword = None

        if reason_lower == "spam":
            primary_reason_keyword = reason_map["spam"]
            selected_reason_text = "Spam"
        else:
            for key, keyword in reason_map.items():
                 if reason_lower == key.lower():
                     primary_reason_keyword = keyword
                     selected_reason_text = keyword.capitalize()
                     break
            if not primary_reason_keyword:
                for key, keyword in reason_map.items():
                     # Use len > 4 for partial match to avoid vague matches like 'sale' in 'false'
                     if key in reason_lower and len(key) > 4:
                         primary_reason_keyword = keyword
                         selected_reason_text = keyword.capitalize()
                         logger.debug(f"[{log_prefix}]: Partial match: '{reason_lower}' -> '{keyword}'.")
                         break

        if not primary_reason_keyword:
            primary_reason_keyword = reason_map["something else"]
            selected_reason_text = "Something Else"
            logger.warning(f"[{log_prefix}]: Reason '{reason_lower}' unmapped. Using '{primary_reason_keyword}'.")

        # Stage 1: Select the primary reason
        logger.debug(f"[{log_prefix}]: Report Flow Stage 1: Selecting reason containing '{primary_reason_keyword}'")
        stage1_xpath = (
            f"//div[@role='dialog' or @role='alertdialog']"
            f"//*[self::button or @role='button' or @role='radio' or @role='link' or ancestor::label[@role='radio']]"
            f"[contains(translate(normalize-space(.), 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), '{primary_reason_keyword}')]"
            f"[not(@disabled) and not(@aria-disabled='true')]"
        )
        stage1_choice = None

        try:
            stage1_choice = self._find_element_robust(
                driver, [(By.XPATH, stage1_xpath)], short_wait, f"Stage 1 ({selected_reason_text})")

            if not stage1_choice:
                 fallback_keyword = reason_map["something else"]
                 logger.warning(f"[{log_prefix}]: Stage 1 specific failed. Trying '{fallback_keyword}'.")
                 fallback_xpath = stage1_xpath.replace(primary_reason_keyword, fallback_keyword)
                 stage1_choice = self._find_element_robust(driver, [(By.XPATH, fallback_xpath)], short_wait, f"Stage 1 Fallback")

            if not stage1_choice:
                logger.error(f"[{log_prefix}]: FAILED Stage 1 - Cannot find reason/fallback.")
                self._save_screenshot("report_stage1_fail", driver)
                return False

            self._js_click(stage1_choice, driver)
            logger.info(f"[{log_prefix}]: Clicked Stage 1 element for '{selected_reason_text}' (or fallback).")
            self._random_delay(1.5, 3, driver) # Use instance method for delay

        except Exception as e1:
            logger.error(f"[{log_prefix}]: Error in Stage 1 click: {e1}")
            return False

        # Subsequent Stages
        max_stages = 5
        submission_confirmed = False
        stages_processed = 0

        for stage_num in range(2, max_stages + 2):
            logger.debug(f"[{log_prefix}]: Processing report stage {stage_num}...")
            action_taken = False
            stages_processed += 1
            confirmation_xpath = "//*[contains(text(), 'Thanks for reporting') or contains(text(), 'Report sent') or contains(text(), 'Report submitted') or contains(text(),'We received your report')]"

            # Check for confirmation text
            try:
                WebDriverWait(driver, 0.5).until(EC.presence_of_element_located((By.XPATH, confirmation_xpath)))
                logger.info(f"[{log_prefix}]: CONFIRMED by text stage {stage_num}.")
                submission_confirmed = True
                self._handle_common_popups(["Close", "Done"], timeout=2, driver_instance=driver)
                break
            except TimeoutException:
                pass # Continue checking other actions

            # Check for final submit button
            final_keywords = ["submit report", "submit", "done", "send report", "report account"]
            final_xpath = (
                f"//div[@role='dialog' or @role='alertdialog']//button"
                f"[not(@disabled) and not(@aria-disabled='true') and (" +
                " or ".join([f"contains(translate(normalize-space(.), 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), '{kw}')" for kw in final_keywords]) +
                ")]"
            )
            try:
                final_button = WebDriverWait(driver, 0.5).until(EC.element_to_be_clickable((By.XPATH, final_xpath)))
                btn_text = final_button.text.strip() or "[Submit]"
                logger.info(f"[{log_prefix}]: Found final button '{btn_text}' stage {stage_num}. Clicking...")
                self._js_click(final_button, driver)
                action_taken = True
                self._random_delay(2.0, 4.0, driver) # Use instance method

                # Check for confirmation text immediately after clicking submit
                try:
                    WebDriverWait(driver, 3).until(EC.presence_of_element_located((By.XPATH, confirmation_xpath)))
                    logger.info(f"[{log_prefix}]: CONFIRMED by text after clicking '{btn_text}'.")
                except TimeoutException:
                    logger.warning(f"[{log_prefix}]: Clicked final '{btn_text}', no confirmation text. Assuming success.")

                submission_confirmed = True
                self._handle_common_popups(["Close", "Done"], timeout=2, driver_instance=driver)
                break # Exit loop on final submission
            except TimeoutException:
                logger.debug(f"[{log_prefix}]: No final button stage {stage_num}.")
            except Exception as e_final:
                logger.warning(f"[{log_prefix}]: Error clicking final button: {e_final}")

            # Check for 'Next' button
            if not action_taken:
                next_xpath = "//div[@role='dialog' or @role='alertdialog']//button[normalize-space()='Next' and not(@disabled) and not(@aria-disabled='true')]"
                try:
                    next_button = WebDriverWait(driver, 0.5).until(EC.element_to_be_clickable((By.XPATH, next_xpath)))
                    logger.info(f"[{log_prefix}]: Found 'Next' button stage {stage_num}. Clicking...")
                    self._js_click(next_button, driver)
                    action_taken = True
                    self._random_delay(1.5, 3, driver) # Use instance method
                except TimeoutException:
                    logger.debug(f"[{log_prefix}]: No 'Next' button stage {stage_num}.")
                except Exception as e_next:
                    logger.warning(f"[{log_prefix}]: Error clicking 'Next': {e_next}")

            # Check for sub-options (radio buttons etc.)
            if not action_taken:
                sub_opt_xpath = (
                    f"//div[@role='dialog' or @role='alertdialog']"
                    # Find labels acting as radio buttons (common pattern) excluding hidden ones
                    f"//label[@role='radio'][not(ancestor::*[contains(@style,'display: none')])]"
                    # OR find actual radio input elements excluding hidden/disabled
                    f" | //div[@role='dialog']//input[@type='radio'][not(@disabled)][not(ancestor::*[contains(@style,'display: none')])]"
                    # OR find divs acting as radio buttons/menu items excluding hidden
                    f" | //div[@role='dialog']//div[@role='button' or @role='menuitemradio'][not(ancestor::*[contains(@style,'display: none')])]"
                )
                try:
                    sub_opts = WebDriverWait(driver, 1).until(EC.presence_of_all_elements_located((By.XPATH, sub_opt_xpath)))
                    clickable_opts = [el for el in sub_opts if el.is_displayed()]
                    if clickable_opts:
                        opt_to_click = clickable_opts[0] # Click the first one
                        opt_text = opt_to_click.text.strip() or opt_to_click.get_attribute('aria-label') or "[SubOpt]"
                        logger.info(f"[{log_prefix}]: Found sub-options stage {stage_num}. Clicking first: '{opt_text[:50]}...'")
                        self._js_click(opt_to_click, driver)
                        action_taken = True
                        self._random_delay(1.0, 2.5, driver) # Use instance method
                    else:
                        logger.debug(f"[{log_prefix}]: Sub-option elements present but not clickable stage {stage_num}.")
                except TimeoutException:
                     logger.debug(f"[{log_prefix}]: No sub-options stage {stage_num}.")
                except Exception as e_sub:
                     logger.warning(f"[{log_prefix}]: Error handling sub-options: {e_sub}")

            # Check if stuck (no action taken in this stage)
            if not action_taken:
                 logger.warning(f"[{log_prefix}]: No action in stage {stage_num}. Checking dialog status...")
                 dialog_marker_xpath = "//div[@role='dialog' or @role='alertdialog']//h1[contains(text(),'Report')]"
                 try:
                     # Wait for dialog marker to disappear
                     WebDriverWait(driver, 0.5).until_not(EC.presence_of_element_located((By.XPATH, dialog_marker_xpath)))
                     logger.info(f"[{log_prefix}]: Dialog marker gone stage {stage_num}. Assuming closure.")
                     submission_confirmed = True # Assume success if dialog closed
                     break
                 except TimeoutException:
                     logger.error(f"[{log_prefix}]: Dialog marker remained stage {stage_num}. Flow STUCK.")
                     self._save_screenshot(f"report_stuck_stage_{stage_num}", driver)
                     return False # Stuck
                 except (NoSuchElementException, StaleElementReferenceException):
                     # If checking for absence throws error, it also means it's gone
                     logger.info(f"[{log_prefix}]: Dialog marker gone (stale/no longer exists) stage {stage_num}. Assuming closure.")
                     submission_confirmed = True
                     break
                 except WebDriverException as wd_stale:
                     # Handle potential WebDriver errors during the staleness check
                     logger.warning(f"[{log_prefix}]: WebDriver error checking stale dialog marker: {wd_stale}. Assuming closure.")
                     submission_confirmed = True
                     break

            # Delay between stages if action was taken and not the last stage
            if action_taken and stage_num < max_stages + 1:
                self._random_delay(0.5, 1.0, driver) # Use instance method

        # --- Final Result ---
        if submission_confirmed:
            logger.info(f"[{log_prefix}]: Report reason flow completed successfully.")
            return True
        else:
            logger.error(f"[{log_prefix}]: Report flow FAILED after {stages_processed} stages.")
            self._save_screenshot("report_flow_fail_final", driver)
            return False
        
    def _mass_report_concurrent_logic(self, target, reason, accounts_to_use, max_workers, num_reports_per_account=1):
        """
        Manages concurrent execution of reports using a ThreadPoolExecutor.

        Args:
            target (str): The target username.
            reason (str): The report reason.
            accounts_to_use (list): List of account dictionaries to use for reporting.
            max_workers (int): Maximum number of concurrent worker threads.
            num_reports_per_account (int): How many times each account should attempt a report.

        Returns:
            dict: A dictionary summarizing the results.
        """
        # Initialize results dictionary
        results = {
            "success": 0, "failed_login": 0, "skipped_or_failed_report": 0,
            "target_not_found": 0, "worker_exception": 0, "rate_limited": 0,
            "total": len(accounts_to_use) * num_reports_per_account,
            "target": target, "reason": reason, "details": [] # List to store individual job results
        }

        # Ensure at least 1 worker, cap at number of accounts if fewer requested
        # Also ensure it doesn't exceed the number of tasks if tasks < max_workers
        actual_workers = max(1, min(max_workers, len(accounts_to_use) * num_reports_per_account, len(accounts_to_use)))
        logger.info(
            f"Mass Report Mgr: Starting {results['total']} report attempts for '{target}' "
            f"using up to {actual_workers} workers across {len(accounts_to_use)} selected accounts..."
        )

        # Create Tasks
        # Each task is a tuple: (account_dict, target_username, reason, report_attempt_number)
        tasks = []
        for acc in accounts_to_use:
             for i in range(num_reports_per_account):
                 tasks.append((acc, target, reason, i + 1)) # Add report number for logging

        random.shuffle(tasks) # Randomize order slightly to distribute load/timing

        # Execute Tasks Concurrently
        with concurrent.futures.ThreadPoolExecutor(max_workers=actual_workers, thread_name_prefix='MassReportWorker') as executor:
            # Map future object to the username for easy result tracking
            future_map = {
                executor.submit(self._mass_report_worker, task[0], task[1], task[2], task[3]): task[0]['username']
                for task in tasks
            }

            processed_count = 0
            # Process results as they complete
            for future in concurrent.futures.as_completed(future_map):
                processed_count += 1
                user = future_map[future] # Get username associated with this future
                log_prefix = f"MassMgr-{user[:10]}" # Log prefix for manager thread

                try:
                    job_result = future.result() # Get the result dict from the worker
                    results["details"].append(job_result) # Store detailed result
                    outcome = job_result.get("outcome", "unknown")

                    # Aggregate Results
                    if outcome == "success": results["success"] += 1
                    # Count each login failure attempt from workers
                    elif outcome.startswith("failed_login"): results["failed_login"] += 1
                    elif outcome == "skipped_or_failed_report": results["skipped_or_failed_report"] += 1
                    elif outcome == "target_not_found": results["target_not_found"] += 1
                    elif outcome == "rate_limited": results["rate_limited"] += 1
                    elif "exception" in outcome or "unknown" in outcome: results["worker_exception"] += 1
                    else:
                        # Catch any unexpected outcome strings from workers
                        logger.warning(f"[{log_prefix}]: Received unexpected worker outcome '{outcome}'. Counting as exception.")
                        results["worker_exception"] += 1

                    logger.debug(f"[{log_prefix}]: Worker job (Attempt {job_result.get('report_num', '?')}) for account '{user}' completed with outcome: {outcome}")

                except Exception as exc:
                    # Handle exceptions *retrieving* the result from the future
                    logger.error(f"[{log_prefix}]: CRITICAL error retrieving worker result for account '{user}': {exc}", exc_info=True)
                    results["worker_exception"] += 1
                    # Add placeholder detail for the failed future retrieval
                    results["details"].append({"username": user, "outcome": "future_exception", "error_details": str(exc)})

                finally:
                    # Update GUI Progress (if GUI is available and window exists)
                    if hasattr(self, 'gui') and self.gui and hasattr(self.gui,'root') and self.gui.root.winfo_exists():
                         try:
                             # Update status bar frequently
                             self.gui.root.after(0, lambda p=processed_count, t=results['total']: self.gui.update_status(f"Mass Report Progress: {p}/{t} jobs completed...", "info"))
                             # Update account list less frequently for performance
                             if processed_count % 10 == 0 or processed_count == results['total']:
                                 self.gui.root.after(10, self.gui.update_account_listbox)
                         except Exception as gui_err:
                             # Avoid crashing the manager thread due to GUI errors
                             logger.warning(f"GUI update error during mass report progress callback: {gui_err}")

        # Log Final Summary
        logger.info(
             f"Mass Report Concurrency FINISHED for '{target}'. "
             f"Results: OK: {results['success']}/{results['total']}, "
             f"LoginFail: {results['failed_login']}, RateLimit: {results['rate_limited']}, "
             f"Skip/Fail: {results['skipped_or_failed_report']}, NoTarget: {results['target_not_found']}, "
             f"Errors: {results['worker_exception']}."
         )

        # Final GUI Update
        if hasattr(self, 'gui') and self.gui and hasattr(self.gui,'root') and self.gui.root.winfo_exists():
             # Create a concise final status message
             final_msg = (
                 f"Mass Rpt Done '{target}'. OK:{results['success']}, LFail:{results['failed_login']}, "
                 f"RateL:{results['rate_limited']}, Skip:{results['skipped_or_failed_report']}, "
                 f"Err:{results['worker_exception']}"
             )
             try:
                  # Update status bar and ensure account list reflects final counts
                  self.gui.root.after(0, lambda msg=final_msg: self.gui.update_status(msg, "info"))
                  self.gui.root.after(50, self.gui.update_account_listbox) # Update listbox shortly after status
             except Exception as final_gui_err:
                 logger.warning(f"Final GUI update error after mass report: {final_gui_err}")

        return results

    def _mass_report_worker(self, account, target_username, reason, report_num):
        """ 
        The function executed by each worker thread for mass reporting.

        Sets up an isolated WebDriver, logs in, performs the report, updates account stats,
        and cleans up the driver.

        Args:
            account (dict): The account dictionary to use.
            target_username (str): The target to report.
            reason (str): The report reason.
            report_num (int): The attempt number for this account (for logging).

        Returns:
            dict: Result dictionary {'username', 'outcome', 'error_details', 'report_num'}.
        """
        username = account.get("username", "Unknown")
        log_prefix = f"Worker-{username[:10]}-R{report_num}" # Worker-specific log prefix
        worker_driver = None # Initialize driver variable for this worker
        login_success = False
        # Default outcome assumes something went wrong before specific outcomes are set
        final_outcome = "unknown_worker_failure" # Changed default from "unknown"
        err_details = None # Store specific error message if exception occurs

        try:
            logger.debug(f"[{log_prefix}]: Worker starting for target '{target_username}'...")

            # 1. Setup Isolated Driver for this worker
            worker_driver = self._setup_driver_for_worker() # Gets isolated options, service, proxy, UA
            if not worker_driver:
                final_outcome = "failed_login_driver_setup"
                # Raise exception to ensure cleanup and proper outcome reporting
                raise Exception("Worker driver setup failed.")

            # 2. Login using the isolated driver
            # Use a dedicated isolated login function to avoid conflicts with main driver state
            login_success = self._login_with_selenium_isolated(account, worker_driver, log_prefix)

            if not login_success:
                # Use the status set by the isolated login attempt (e.g., 'challenge', 'banned', 'login_failed')
                final_outcome = account.get("status", "failed_login_unknown") # Default if status wasn't set
                # Log the failure and let the function proceed to finally block for cleanup and return
                logger.error(f"[{log_prefix}]: Worker login failed. Status: {final_outcome}")
                # No exception raised here, worker should return the failure outcome
            else:
                # 3. Perform Report if Login Succeeded
                logger.debug(f"[{log_prefix}]: Login successful. Proceeding to report attempt {report_num}...")
                # Pass the isolated driver and the specific account dict to report_account
                report_result = self.report_account(
                    target_username,
                    reason,
                    driver_instance=worker_driver, # Use the worker's driver
                    reporting_account=account      # Pass the account for rate limiting checks
                )

                # 4. Determine Outcome based on report_account result
                if report_result is True:
                    final_outcome = "success"
                    logger.info(f"[{log_prefix}]: Report attempt successful.")
                elif report_result == "target_not_found":
                    final_outcome = "target_not_found"
                    logger.warning(f"[{log_prefix}]: Report failed - Target not found.")
                elif account.get("_worker_rate_limited"): # Check flag set by report_account
                    final_outcome = "rate_limited"
                    logger.warning(f"[{log_prefix}]: Report skipped - Rate limited.")
                    account.pop("_worker_rate_limited", None) # Clean up the temporary flag
                else: # Any other False return from report_account
                    final_outcome = "skipped_or_failed_report"
                    logger.error(f"[{log_prefix}]: Report action failed or was skipped (check report_account logs).")

        except Exception as e:
            # Catch exceptions during driver setup, login, or reporting within the worker
            logger.error(f"[{log_prefix}]: Worker encountered an exception: {type(e).__name__} - {e}", exc_info=logger.level == logging.DEBUG)
            err_details = f"{type(e).__name__}: {str(e)[:150]}" # Store brief error details
            # Preserve specific failure status if it occurred before the exception
            # Otherwise, set a generic worker exception outcome
            # Avoid overwriting specific login/setup failures with 'worker_exception'
            if final_outcome in ["unknown_worker_failure", "success", "skipped_or_failed_report", "target_not_found"]:
                 final_outcome = "worker_exception"

        finally:
            # 5. Cleanup: Close the worker's WebDriver instance
            if worker_driver:
                logger.debug(f"[{log_prefix}]: Closing worker WebDriver instance.")
                try:
                    worker_driver.quit()
                except Exception as qe:
                    logger.warning(f"[{log_prefix}]: Error closing worker driver: {qe}")

            # 6. Save Updated Account State (regardless of outcome)
            # This saves the potentially updated report count and last report time back to the CSV
            # Use the main instance's method which handles locking.
            # Ensure account is valid before saving
            if isinstance(account, dict) and account.get("username"):
                self._save_account_to_csv(account)
            else:
                 logger.error(f"[{log_prefix}]: Invalid account data detected in worker finally block, cannot save to CSV.")


            logger.debug(f"[{log_prefix}]: Worker finished. Final Outcome: {final_outcome}")

            # 7. Return result dictionary
            return {
                "username": username,
                "outcome": final_outcome,
                "error_details": err_details,
                "report_num": report_num # Include report attempt number in result
            }
            
    def _login_with_selenium_isolated(self, account_to_login, driver_instance, log_prefix):
        """
        Performs login steps using a provided, isolated WebDriver instance.
        Minimal version for workers, updates account status directly.

        Args:
            account_to_login (dict): Account dictionary.
            driver_instance: The isolated WebDriver instance to use.
            log_prefix (str): Logging prefix.

        Returns:
            bool: True on success, False on failure.
        """
        # --- Initial Checks and Variable Assignment ---
        if not driver_instance or not account_to_login:
            logger.error(f"[{log_prefix}]: Isolated login failed - Invalid driver or account data provided.")
            return False # Return early if inputs are bad

        # Assign username/password *after* the initial check passed
        username = account_to_login['username']
        password = account_to_login['password'] # Avoid logging password

        logger.debug(f"[{log_prefix}]: Performing isolated login for '{username}'...")

        # --- Main Login Logic (Now correctly indented) ---
        try:
            wait_timeout_setting = self.settings.get("webdriver_wait_timeout", 15)
            wait = WebDriverWait(driver_instance, wait_timeout_setting + 10) # Add buffer for login page

            # Navigate & Handle Cookies
            driver_instance.get(self.platform_urls['login'])
            # Pass driver instance to delay method
            self._random_delay(1.5, 3.5, driver_instance=driver_instance)
            self._handle_common_popups(["Accept", "Allow"], timeout=5, driver_instance=driver_instance)

            # Find Fields
            user_selectors = [(By.NAME, "username"), (By.XPATH, "//input[@aria-label='Phone number, username, or email']")]
            user_field = self._find_element_robust(driver_instance, user_selectors, wait, f"{log_prefix}-User")
            if not user_field:
                logger.error(f"[{log_prefix}]: Failed to find username field during isolated login.")
                return False # Fail early if critical element missing

            pass_selectors = [(By.NAME, "password"), (By.XPATH, "//input[@aria-label='Password']")]
            pass_field = self._find_element_robust(driver_instance, pass_selectors, wait, f"{log_prefix}-Pass")
            if not pass_field:
                logger.error(f"[{log_prefix}]: Failed to find password field during isolated login.")
                return False

            # Type Credentials & Delay
            self._human_type(user_field, username, driver_instance)
            self._human_type(pass_field, password, driver_instance)
            self._random_delay(0.5, 1.5, driver_instance=driver_instance)

            # Find & Click Login Button
            login_xpath = "//button[@type='submit'][.//div[contains(text(),'Log in')] or contains(., 'Log in')]"
            login_btn = self._find_element_robust(driver_instance, [(By.XPATH, login_xpath)], wait, f"{log_prefix}-Btn")
            if not login_btn:
                 logger.error(f"[{log_prefix}]: Failed to find login button during isolated login.")
                 return False

            self._js_click(login_btn, driver_instance)
            logger.debug(f"[{log_prefix}]: Isolated login button clicked. Waiting for outcome...")
            outcome_timeout = 30 # Seconds to wait

            # Define Outcome Conditions (same as main login)
            conditions = [
                EC.url_contains("?__coig_login"), EC.url_matches(r"https://www\.instagram\.com/(?:$|\?.*$)"),
                EC.presence_of_element_located((By.XPATH, "//nav | //div[@role='navigation']")), # Added role for robustness
                EC.url_contains("/challenge/"), EC.url_contains("/suspended/"), EC.url_contains("/disabled/"),
                EC.url_contains("/onetap/"), EC.url_contains("/login/"),
                EC.presence_of_element_located((By.ID, "slfErrorAlert")),
                EC.presence_of_element_located((By.XPATH, "//*[contains(text(), 'password was incorrect')]")),
                EC.presence_of_element_located((By.XPATH, "//*[contains(text(), 'find your account')]")),
                EC.presence_of_element_located((By.XPATH, "//*[contains(text(), 'Turn on Notifications')]"))
            ]

            # Wait for any condition
            try:
                WebDriverWait(driver_instance, outcome_timeout).until(EC.any_of(*conditions))
                self._random_delay(1.5, 3.0, driver_instance=driver_instance) # Delay after condition met
            except TimeoutException:
                logger.error(f"[{log_prefix}]: Isolated login outcome timed out after {outcome_timeout}s.")
                self._save_screenshot(f"iso_login_timeout_{username}", driver_instance)
                account_to_login["status"] = "login_timeout" # Update status
                return False

            # Analyze Outcome
            current_url = driver_instance.current_url # Get URL after wait
            page_source_lower = "" # Initialize empty
            try: # Get source only if potentially needed for error checks
                if "/login/" in current_url or "error" in current_url:
                    page_source_lower = driver_instance.page_source.lower()
            except WebDriverException as ps_err:
                logger.warning(f"[{log_prefix}]: Could not get page source for outcome analysis: {ps_err}")

            # Check failure conditions
            if ("password was incorrect" in page_source_lower or
                "find your account" in page_source_lower or
                ("/login/" in current_url and driver_instance.find_elements(By.ID, "slfErrorAlert"))): # Check for specific error div on login page
                logger.error(f"[{log_prefix}]: Isolated Login Failed - Incorrect Credentials indicated.")
                account_to_login["status"] = "login_failed"
                return False
            elif "/challenge/" in current_url:
                logger.error(f"[{log_prefix}]: Isolated Login Failed - Challenge Required.")
                account_to_login["status"] = "challenge"
                return False
            elif any(b in current_url for b in ["/suspended/", "/disabled/", "account_disabled"]):
                logger.error(f"[{log_prefix}]: Isolated Login Failed - Account Banned/Disabled.")
                account_to_login["status"] = "banned"
                return False
            elif "/onetap/" in current_url or "turn_on_notifications" in current_url:
                logger.info(f"[{log_prefix}]: Isolated login encountered intermediate page ({current_url}). Dismissing...")
                # Attempt to dismiss, but don't fail immediately if dismiss fails
                if not self._handle_common_popups(["Not Now", "Cancel"], timeout=5, driver_instance=driver_instance):
                     logger.warning(f"[{log_prefix}] Failed to find/click dismiss button on intermediate page during isolated login.")
                # Recheck URL after attempting dismissal
                try:
                    current_url = driver_instance.current_url
                    logger.debug(f"[{log_prefix}]: URL after attempting intermediate page dismissal: {current_url}")
                except WebDriverException as post_dismiss_err:
                     logger.warning(f"[{log_prefix}]: Could not get URL after intermediate page dismissal: {post_dismiss_err}. Assuming failure.")
                     account_to_login["status"] = "login_intermediate_fail"
                     return False # Fail if we can't even check the URL after dismiss

            # Check for success conditions (after handling intermediate pages)
            is_likely_success_url = ("instagram.com" in current_url and
                                     not any(f in current_url for f in ["/login", "/challenge/", "/suspended/", "/disabled/", "/onetap/", "/error/"]))

            if is_likely_success_url:
                try:
                    # Final confirmation: look for main navigation element
                    WebDriverWait(driver_instance, 5).until(EC.presence_of_element_located((By.XPATH, "//nav | //div[@role='navigation']")))
                    logger.info(f"[{log_prefix}]: Isolated login successful for '{username}'.")
                    account_to_login["status"] = "active" # Update status
                    # Handle post-login popups if they appear
                    self._handle_common_popups(["Not Now", "Cancel"], timeout=6, driver_instance=driver_instance)
                    self._handle_common_popups("Save Info", timeout=4, driver_instance=driver_instance) # Optional save info popup
                    return True
                except TimeoutException:
                    logger.error(f"[{log_prefix}]: Isolated login URL ({current_url}) looked okay, but key UI element (nav) missing. Assuming partial failure.")
                    account_to_login["status"] = "login_partial_fail" # Specific status for this case
                    return False
            else:
                # If it's not a recognized failure or success state after checks
                logger.error(f"[{log_prefix}]: Isolated login resulted in unexpected final state. URL: {current_url}")
                account_to_login["status"] = "login_unexpected"
                return False

        # --- Exception Handling ---
        except WebDriverException as e:
            logger.error(f"[{log_prefix}]: WebDriverException during isolated login: {e}", exc_info=logger.level==logging.DEBUG)
            self._save_screenshot(f"iso_login_wd_err_{username}", driver_instance)
            # Try to set a more specific status based on error type
            if any(term in str(e).lower() for term in ["proxy", "refused", "net::err_", "timeout", "dns_probe", "unreachable", "disconnected"]):
                account_to_login["status"] = "proxy_error"
            else:
                account_to_login["status"] = "login_webdriver_error"
            return False
        except Exception as e:
            logger.error(f"[{log_prefix}]: Unexpected error during isolated login: {e}", exc_info=True)
            self._save_screenshot(f"iso_login_exc_{username}", driver_instance)
            account_to_login["status"] = "login_exception"
            return False
        
    # --- Data Extraction ---

    def _analyze_network_logs(self, logs):
        """
        Processes performance logs (obtained via driver.get_log('performance'))
        to extract relevant Instagram GraphQL JSON responses.

        Args:
            logs (list): A list of log entries, where each entry is typically
                         a dictionary containing a 'message' field with JSON data.

        Returns:
            list: A list of dictionaries, where each dictionary represents a
                  successfully parsed GraphQL response containing a 'data' key.
                  Format: [{'url', 'status', 'requestId', 'data': {...}}]
        """
        graphql_responses = []
        graphql_url_part = "/api/graphql" # Identifier for GraphQL API requests
        relevant_methods = ["Network.responseReceived", "Network.dataReceived", "Network.loadingFinished"]
        # Store intermediate data per request ID during processing
        response_data_map = {} # Maps requestId -> [True] if dataReceived was seen
        finished_requests = {} # Maps requestId -> {url, headers, status, mimeType}

        try:
            for entry in logs:
                # Basic structure check for log entry
                if not isinstance(entry, dict) or "message" not in entry:
                    continue
                try:
                    # Parse the JSON message within the log entry
                    message_data = json.loads(entry["message"])
                    log = message_data.get("message", {}) # The actual log content
                except (json.JSONDecodeError, TypeError):
                    # Ignore entries with invalid JSON format
                    continue

                method = log.get("method") # e.g., "Network.responseReceived"
                params = log.get("params")
                # Skip if not a relevant network method or no parameters
                if not params or method not in relevant_methods:
                    continue

                request_id = params.get("requestId")
                if not request_id: continue # Skip if no request ID

                # --- Store response info when received ---
                if method == "Network.responseReceived":
                    response = params.get("response", {})
                    url = response.get("url", "")
                    # Only track requests potentially containing GraphQL data
                    if graphql_url_part in url:
                        # Store key response details needed when loading finishes
                        finished_requests[request_id] = {
                            "url": url,
                            "headers": response.get("headers", {}),
                            "status": response.get("status"),
                            "mimeType": response.get("mimeType")
                        }
                        # Initialize data received flag (as list containing bool for mutability by reference)
                        response_data_map[request_id] = [] # Empty list means no data received yet

                # --- Mark when data starts arriving for a tracked request ---
                elif method == "Network.dataReceived":
                    # Check if we are tracking this request ID and haven't marked data yet
                    if request_id in response_data_map and not response_data_map[request_id]:
                         # Mark that data has been received (append True to the list)
                         response_data_map[request_id].append(True)

                # --- Process when request loading is finished ---
                elif method == "Network.loadingFinished":
                    # Check if this is a tracked GraphQL request ID that has received data
                    if request_id in finished_requests and request_id in response_data_map:
                        request_info = finished_requests[request_id]
                        # Final check: ensure it's a GraphQL URL and data flag is set
                        if graphql_url_part in request_info.get("url", "") and response_data_map[request_id]:
                            body = None
                            decoded_body = None
                            try:
                                # Attempt to get the response body using Chrome DevTools Protocol command
                                body_info = self.driver.execute_cdp_cmd('Network.getResponseBody', {'requestId': request_id})
                                body = body_info.get('body')
                                base64_encoded = body_info.get('base64Encoded', False)

                                if body:
                                     logger.debug(f"NetLog: Received body for request {request_id} (Base64 Encoded: {base64_encoded})")
                                     # Decode if necessary (often base64 encoded)
                                     decoded_body = base64.b64decode(body).decode('utf-8', 'ignore') if base64_encoded else body

                                     # Attempt to parse the decoded body as JSON
                                     if decoded_body:
                                        try:
                                            json_data = json.loads(decoded_body)
                                            # Check for standard Instagram GraphQL success structure
                                            if isinstance(json_data, dict) and 'data' in json_data:
                                                graphql_responses.append({
                                                    "url": request_info.get("url"),
                                                    "status": request_info.get("status"),
                                                    "requestId": request_id,
                                                    "data": json_data # Store the parsed JSON data
                                                })
                                                logger.debug(f"NetLog: Successfully parsed GraphQL JSON response for {request_id}")
                                            # Check for explicit failure status in JSON body
                                            elif isinstance(json_data, dict) and json_data.get('status') == 'fail':
                                                logger.warning(f"NetLog: GraphQL request {request_id} failed (status='fail'): {json_data.get('message', '?')}")
                                            else:
                                                # Log if JSON doesn't match expected structures
                                                logger.debug(f"NetLog: Response {request_id} is JSON but not expected GraphQL format.")
                                        except json.JSONDecodeError:
                                            # Log if body wasn't valid JSON
                                            logger.debug(f"NetLog: Failed to decode JSON for request {request_id}. Body starts: {decoded_body[:100]}...")
                                        except Exception as parse_e:
                                            # Catch other errors during JSON processing
                                            logger.warning(f"NetLog: Error processing JSON for request {request_id}: {parse_e}")
                                else: # Body was empty from CDP command
                                     logger.debug(f"NetLog: execute_cdp_cmd getResponseBody returned empty body for {request_id}")
                            except WebDriverException as cdp_e:
                                # Ignore "No resource with given identifier found" - common if request finished very quickly
                                if "No resource with given identifier found" not in str(cdp_e):
                                    logger.debug(f"NetLog: CDP getResponseBody failed for {request_id}: {cdp_e}")
                            except Exception as body_e:
                                logger.warning(f"NetLog: Error getting/processing response body for {request_id}: {body_e}")

                        # Clean up processed request ID from tracking dictionaries regardless of success
                        finished_requests.pop(request_id, None)
                        response_data_map.pop(request_id, None)

        except Exception as e:
            # Catch errors in the main loop iterating through logs
            logger.error(f"Error processing performance logs loop: {e}", exc_info=True)

        logger.info(f"Network log analysis complete. Found {len(graphql_responses)} potential GraphQL responses.")
        return graphql_responses
    
    def extract_user_data(self, username):
        """
        Extracts profile information for a target user using a combination of
        HTML scraping and network log analysis (GraphQL responses).

        Requires being logged in.

        Args:
            username (str): The target Instagram username.

        Returns:
            dict: A dictionary containing extracted data and status information.
                  Keys include: username, extraction_status, data (nested dict).
        """
        # --- Pre-checks ---
        if not self.driver or not self.current_account:
            logger.error("Extract Failed: Login required.")
            return {"username": username, "extraction_status": "Login Required", "data": None}
        if not username or not isinstance(username, str) or not username.strip():
            logger.error("Extract Failed: Invalid target.")
            return {"username": None, "extraction_status": "Missing Username", "data": None}

        target_username = username.strip()
        logger.info(f"Extracting data for '{target_username}'")
        profile_url = f"{self.platform_urls['base']}{urllib.parse.quote(target_username)}/"
        wait = WebDriverWait(self.driver, self.settings.get("webdriver_wait_timeout", 15))
        start_time = time.monotonic()

        # --- Initialize Data Structure ---
        user_data = {
            "username": target_username,
            "extraction_timestamp": time.time(),
            "extraction_status": "pending", # Initial status
            "profile_url": profile_url,
            # Fields to be populated
            "user_id": None,
            "full_name": None,
            "profile_pic_url": None,
            "is_private": None, # True, False, or None if undetermined
            "is_verified": False,
            "follower_count": None,
            "following_count": None,
            "media_count": None, # Posts count
            "biography": None,
            "external_url": None,
            "category_name": None, # Business account category
            "recent_posts": [], # List of dicts for recent posts
            "network_responses": [] # Store raw GraphQL responses
        }

        try:
            # 1. --- Clear Performance Logs (Best Effort) ---
            try:
                # Clear any previous logs before navigation
                self.driver.get_log('performance')
                logger.debug("Cleared previous perf logs.")
            except Exception as log_clear_err: # Catch broader errors here
                logger.warning(f"Could not clear perf logs (may not be critical): {log_clear_err}")

            # 2. --- Navigate to Profile ---
            logger.debug(f"Navigating to profile: {profile_url}")
            self.driver.get(profile_url)
            self._random_delay(3, 5, self.driver) # Allow time for page and network requests

            # 3. --- Check for Profile Not Found / Rate Limit ---
            try:
                # Combined XPath for "Not Found", "Unavailable", or Rate Limit messages
                error_xpath = "//*[contains(text(), \"Sorry, this page isn't available\") or contains(text(), \"Page Not Found\") or contains(text(), \"couldn't find this account\") or contains(h2,'Something Went Wrong') or contains(text(),'Please wait a few minutes')]"
                # Short wait for error message
                err_el = WebDriverWait(self.driver, 3).until(EC.presence_of_element_located((By.XPATH, error_xpath)))
                # Determine specific error
                page_text = err_el.text.lower()
                status = "Rate Limited" if "wait a few minutes" in page_text else "Profile not found or unavailable"
                logger.warning(f"Extraction stopped for '{target_username}': {status}.")
                user_data["extraction_status"] = status
                return user_data # Return early as no data can be extracted
            except TimeoutException:
                # Error message not found, profile is likely accessible
                logger.debug(f"Profile page '{target_username}' appears accessible.")
            except WebDriverException as e:
                 # Handle errors during the check itself
                 logger.warning(f"WD error checking profile availability: {e}")

            # 4. --- Check for Private Account ---
            try:
                private_xpath = "//h2[contains(text(), 'This Account is Private') or contains(text(),'account is private')]"
                # Use very short wait - private banner appears quickly
                WebDriverWait(self.driver, 1).until(EC.visibility_of_element_located((By.XPATH, private_xpath)))
                user_data["is_private"] = True
                logger.info(f"Target account '{target_username}' is Private.")
            except TimeoutException:
                # Banner not found, assume public (or unable to determine)
                user_data["is_private"] = False
                logger.debug(f"Target account '{target_username}' assumed Public (no private banner found).")
            except WebDriverException as e:
                 logger.warning(f"WD error checking private status: {e}")
                 user_data["is_private"] = None # Mark as undetermined

            # --- Nested Helper functions for HTML scraping (Correctly Indented) ---
            def get_txt(driver, xpaths):
                for xp in xpaths:
                    try:
                        return driver.find_element(By.XPATH, xp).text.strip()
                    except Exception: # Catch broad exception for simplicity here
                        continue
                return None

            def get_attr(driver, xpaths, attr):
                 for xp in xpaths:
                     try:
                         return driver.find_element(By.XPATH, xp).get_attribute(attr)
                     except Exception:
                         continue
                 return None

            def exists(driver, xpath):
                 try:
                     # Check presence quickly
                     WebDriverWait(driver, 0.2).until(EC.presence_of_element_located((By.XPATH, xpath)))
                     return True
                 except Exception: # Catch Timeout or other exceptions
                     return False

            # 5. --- Basic HTML Scraping ---
            logger.debug("Scraping basic HTML info...")
            try:
                user_data["full_name"] = get_txt(self.driver, ["//header//h1", "//span[contains(@class,'FullName')]", "//section//h1"])
                user_data["is_verified"] = exists(self.driver, "//header//*[local-name()='svg'][@aria-label='Verified']")
                user_data["profile_pic_url"] = get_attr(self.driver, ["//header//img[contains(@alt, 'profile picture')]", "//div[contains(@class,'profile')]/img"], 'src')
                bio_xps = ["//header//h1/following-sibling::span[1]", "//header//div/span[normalize-space()]", "//div[@data-testid='UserBio']"]
                user_data["biography"] = get_txt(self.driver, bio_xps)
                url_xps = ["//header//a[@rel and contains(@href,'http')]", "//a[@data-testid='UserUrl']"]
                user_data["external_url"] = get_attr(self.driver, url_xps, 'href')
            except Exception as html_err:
                 logger.warning(f"Minor HTML scrape error: {html_err}", exc_info=logger.level == logging.DEBUG)

            # --- HTML Stats Scraping ---
            logger.debug("Scraping HTML stats...")
            stats_block = ""
            try:
                stats_xps = ["//header//ul", "//div[contains(@class,'Stats')]//span"]
                for xp in stats_xps:
                    try:
                        stats_block = WebDriverWait(self.driver, 1).until(EC.visibility_of_element_located((By.XPATH, xp))).text
                        if stats_block: break # Found non-empty stats block
                    except Exception: # Catch Timeout or other errors finding element
                        continue
            except Exception as stats_err: # Catch errors in the loop logic itself
                logger.warning(f"Cannot find stats container via HTML: {stats_err}")

            # --- Nested Helper to parse counts like "1,234", "1.5k", "2M" (Correctly Indented) ---
            def parse_ct(txt, kw_pat):
                 # Use raw string for regex pattern
                 match = re.search(rf"([\d.,]+\s*[km]?)\s*{kw_pat}", txt, re.IGNORECASE)
                 if not match: return None
                 num_s = match.group(1).lower().replace(',', '').replace(' ', '').strip()
                 mult = 1_000_000 if 'm' in num_s else (1_000 if 'k' in num_s else 1)
                 num_s = num_s.replace('m','').replace('k','')
                 try:
                     return int(float(num_s)*mult)
                 except ValueError:
                     return None

            if stats_block:
                user_data["media_count"] = parse_ct(stats_block, r"posts?")
                user_data["follower_count"] = parse_ct(stats_block, r"followers?")
                user_data["following_count"] = parse_ct(stats_block, r"following")
                logger.debug(f"HTML Stats: P={user_data['media_count']}, Flw={user_data['follower_count']}, Flg={user_data['following_count']}")
            else:
                logger.warning("Stats block text not found or empty via HTML.")

            # 6. --- Scrape Recent Posts from HTML (if public) ---
            if user_data["is_private"] is False:
                logger.debug("Scraping HTML posts...")
                max_html_posts = 6 # Limit HTML post scraping
                try:
                    post_link_xpath = "//main//a[contains(@href, '/p/') or contains(@href, '/reel/')]"
                    post_els = WebDriverWait(self.driver, 3).until(EC.presence_of_all_elements_located((By.XPATH, post_link_xpath)))
                    extracted = set() # Track codes to avoid duplicates
                    for el in post_els:
                        if len(user_data["recent_posts"]) >= max_html_posts:
                            break
                        try:
                            url = el.get_attribute('href')
                            match = re.search(r"/(?:p|reel)/([\w-]+)", url)
                            if match:
                                code = match.group(1)
                                if code not in extracted:
                                    thumb = get_attr(el, [".//img"], 'src') # Find img within the link 'a' tag
                                    user_data["recent_posts"].append({"code": code, "url": url, "thumbnail_url": thumb})
                                    extracted.add(code)
                        except Exception: # Ignore errors for single post element
                            continue
                    logger.debug(f"HTML Posts Scraped: {len(user_data['recent_posts'])}.") # Log count outside loop
                except TimeoutException:
                    logger.warning("Post grid/links timeout during HTML scraping.")
                except Exception as post_err:
                    logger.warning(f"HTML post scrape error: {post_err}")
            else:
                logger.debug("Skipping HTML post scraping (private profile).")

            # 7. --- Analyze Network Logs (GraphQL) ---
            logger.debug("Retrieving & analyzing performance logs...")
            try:
                logs = self.driver.get_log('performance')
                if logs:
                    logger.info(f"Retrieved {len(logs)} perf log entries.")
                    net_data = self._analyze_network_logs(logs) # Call the separate analysis method
                    user_data["network_responses"] = net_data # Store raw responses
                    # Find the first response containing the main user data structure
                    user_info_resp = next((r['data'] for r in net_data if r.get('data',{}).get('data',{}).get('user')), None)

                    if user_info_resp and 'user' in user_info_resp.get('data', {}):
                        api_data = user_info_resp['data']['user']
                        logger.info(f"Found API user info (ID: {api_data.get('id')}). Updating data...")
                        # Update user_data dict, prioritizing API data
                        user_data.update({
                            "user_id": api_data.get('id'),
                            "full_name": api_data.get('full_name') or user_data["full_name"],
                            "profile_pic_url": api_data.get('profile_pic_url_hd') or api_data.get('profile_pic_url') or user_data["profile_pic_url"],
                            "is_private": api_data.get('is_private'), # API value is more reliable
                            "is_verified": api_data.get('is_verified'),
                            "biography": api_data.get('biography'),
                            "external_url": api_data.get('external_url'),
                            "category_name": api_data.get('category_name')
                        })
                        # Update counts from API edges
                        m = api_data.get('edge_owner_to_timeline_media', {}).get('count')
                        f1 = api_data.get('edge_followed_by', {}).get('count')
                        f2 = api_data.get('edge_follow', {}).get('count')
                        if m is not None: user_data["media_count"] = m
                        if f1 is not None: user_data["follower_count"] = f1
                        if f2 is not None: user_data["following_count"] = f2

                        # Extract recent posts from API data
                        media_edges = api_data.get('edge_owner_to_timeline_media', {}).get('edges', [])
                        net_posts = []
                        if media_edges:
                            for edge in media_edges:
                                node = edge.get('node', {})
                                if node.get('shortcode'):
                                    # Attempt to get caption text safely
                                    caption_node = node.get('edge_media_to_caption', {}).get('edges', [{}])[0].get('node', {})
                                    caption_text = caption_node.get('text') if caption_node else None

                                    net_posts.append({
                                        "code": node['shortcode'],
                                        "url": f"https://www.instagram.com/p/{node['shortcode']}/",
                                        "thumbnail_url": node.get('thumbnail_src'),
                                        "is_video": node.get('is_video', False),
                                        "likes": node.get('edge_liked_by', {}).get('count'),
                                        "comments": node.get('edge_media_to_comment', {}).get('count'),
                                        "caption": caption_text, # Add caption
                                        "timestamp": node.get('taken_at_timestamp')
                                    })
                            if net_posts:
                                logger.debug(f"Merging {len(net_posts)} API posts (replacing HTML posts).")
                                user_data["recent_posts"] = net_posts # Prioritize API posts list
                    else:
                        logger.warning("User info structure ('data.user') not found in network responses.")
                else:
                    logger.warning("Performance log retrieval returned no entries or failed.")
            except WebDriverException as log_e:
                 # Handle errors getting logs
                 logger.error(f"Failed get/process logs: {log_e}.")
            except Exception as e: # Catch other errors during analysis
                 logger.error(f"Unexpected log analysis error: {e}", exc_info=True)

            # 8. --- Finalize Status ---
            if user_data["extraction_status"] == "pending": # Only update if not already set to an error
                status_det = "Public" if user_data["is_private"] is False else ("Private" if user_data["is_private"] is True else "Privacy Unknown")
                net_info = f"+ {len(user_data['network_responses'])} API Resp" if user_data["network_responses"] else "(No API Data)"
                # Determine HTML completeness based on a few key fields
                html_info = f"({('Partial' if any(v is None for k, v in user_data.items() if k in ['full_name', 'follower_count', 'media_count']) else 'Full')} HTML)"
                user_data["extraction_status"] = f"Completed [{status_det}] {html_info} {net_info}"

            # --- Log Completion ---
            duration = time.monotonic() - start_time
            logger.info(f"Data extraction finished for '{target_username}' ({user_data['extraction_status']}) in {duration:.2f}s")
            return user_data # Return the populated dictionary

        # --- Exception Handling for the Entire Process ---
        except WebDriverException as e:
            logger.error(f"Extract WDException for '{target_username}': {e}", exc_info=logger.level==logging.DEBUG)
            if "session deleted" in str(e).lower() or "disconnected" in str(e).lower():
                logger.error("WebDriver session lost during extraction. Closing driver.")
                self.close_driver() # Close the dead driver
            user_data["extraction_status"] = "WebDriver Error"
            return user_data
        except Exception as e:
            logger.error(f"Extract unexpected error for '{target_username}': {e}", exc_info=True)
            self._save_screenshot(f"extract_fail_{target_username}", self.driver) # Use self.driver for screenshot
            user_data["extraction_status"] = "Unexpected Error"
            return user_data
        
    def _check_devtools_page_health(self, driver_instance, username=None, min_successful_network_requests=10, max_console_errors=2, check_critical_resource_urls=None):
        """
        Performs a comprehensive health check of the loaded page by analyzing browser console logs
        and network performance logs retrieved via Chrome DevTools Protocol.
        Returns True if the page appears healthy (i.e., critical resources loaded, no major JS errors),
        False otherwise, signaling a fundamental rendering or anti-bot blocking issue.

        Args:
            driver_instance: The Selenium WebDriver instance.
            username (str, optional): The username context for specific logging and screenshot naming.
            min_successful_network_requests (int): Minimum number of non-error (2xx/3xx status)
                                                   network requests expected for a 'healthy' page load.
            max_console_errors (int): Maximum number of 'SEVERE' level console errors allowed.
                                      Too many often indicate critical JavaScript failures.
            check_critical_resource_urls (list): List of URL substrings. If any of these URLs
                                                 report HTTP 4xx/5xx errors, it's considered a critical failure.
                                                 If None, a default list for Instagram resources is used.
        """
        if not driver_instance:
            logger.warning("DevTools Health Check: No driver instance provided. Cannot perform checks.")
            return False

        log_context = f"DevTools HC for '{username or 'unknown'}':"
        logger.debug(f"{log_context} Initiated. Analyzing console and network activity...")

        try:
            # 1. Prepare Expected Critical Resource URL Patterns
            # These are common static resources or API calls whose failure usually means a broken page.
            if check_critical_resource_urls is None:
                check_critical_resource_urls = [
                    "//static.cdninstagram.com/rsrc.php/",  # Primary static resources CDN
                    "rsrc.php/",                             # Generic static resources
                    "/api/graphql",                         # Instagram's internal GraphQL API endpoints
                    "/accounts/web_create_ajax/",           # Signup/creation related API endpoints
                    "/accounts/emailsignup/",               # Initial page URL (if re-requests occurred)
                    "/data/manifest.json",                  # PWA manifest, part of overall app load
                ]

            # 2. Retrieve Performance Logs (Network Activity)
            performance_logs = []
            try:
                # `driver_instance.get_log('performance')` retrieves events since the last call or navigation.
                all_raw_performance_logs = driver_instance.get_log('performance')
                logger.debug(f"{log_context} Retrieved {len(all_raw_performance_logs)} raw performance log entries.")
            except Exception as e:
                logger.warning(f"{log_context} Failed to retrieve performance logs (ensure 'goog:loggingPrefs': 'performance' is 'ALL'): {e}")
                all_raw_performance_logs = [] 

            network_success_count = 0
            critical_network_errors_found = 0

            for entry in all_raw_performance_logs:
                try:
                    log_data = json.loads(entry['message']).get('message', {})
                    if log_data.get('method') == 'Network.responseReceived':
                        response_params = log_data.get('params', {}).get('response', {})
                        url = response_params.get('url', '')
                        status = response_params.get('status')
                        protocol = response_params.get('protocol') # E.g., "http/1.1", "h2"

                        # Filter out data URIs, WebSocket connections etc., focusing on HTTP(S) network traffic
                        if url.startswith(("http://", "https://")):
                            if 200 <= status < 400: # Standard successful HTTP responses
                                network_success_count += 1
                            elif status >= 400: # Client-side (4xx) or Server-side (5xx) HTTP errors
                                is_critical_url = any(part in url for part in check_critical_resource_urls)
                                if is_critical_url:
                                    critical_network_errors_found += 1
                                    logger.warning(f"{log_context} CRITICAL network resource failed (Status: {status}, URL: {url})!")
                                else:
                                    logger.debug(f"{log_context} Non-critical network error (Status: {status}, URL: {url}).")

                except (json.JSONDecodeError, KeyError, TypeError) as e:
                    logger.debug(f"{log_context} Could not parse performance log entry or missing key in network log: {e} - {entry.get('message', 'N/A')[:100]}...")
                except Exception as e:
                    logger.warning(f"{log_context} Unexpected error processing a performance log entry (Network domain): {e}", exc_info=logger.level == logging.DEBUG)

            # 3. Retrieve Browser (Console) Logs
            browser_logs = []
            try:
                browser_logs = driver_instance.get_log('browser')
                logger.debug(f"{log_context} Retrieved {len(browser_logs)} raw browser console log entries.")
            except Exception as e:
                logger.warning(f"{log_context} Failed to retrieve browser logs (ensure 'goog:loggingPrefs': 'browser' is 'ALL'): {e}")
                browser_logs = []

            console_error_count = 0
            for entry in browser_logs:
                if entry.get('level') == 'SEVERE': # Severe often indicates uncaught JavaScript errors or critical console.error calls
                    console_error_count += 1
                    logger.warning(f"{log_context} Console SEVERE error detected: {entry.get('message', 'N/A')[:150]}...")
                elif entry.get('level') == 'WARNING':
                    logger.debug(f"{log_context} Console WARNING: {entry.get('message', 'N/A')[:150]}...")

            # 4. Evaluate Page Health Based on Defined Criteria
            health_check_passed = True
            diagnostic_messages = [] # Collect messages for a detailed report

            if network_success_count < min_successful_network_requests:
                diagnostic_messages.append(f"Low network activity ({network_success_count} successful requests, expected at least {min_successful_network_requests}). Insufficient resources loaded for page to be fully functional.")
                health_check_passed = False
            
            if critical_network_errors_found > 0:
                diagnostic_messages.append(f"Detected {critical_network_errors_found} critical network resource failures (e.g., essential JS/CSS bundles). These indicate significant blocking or loading issues.")
                health_check_passed = False

            if console_error_count > max_console_errors:
                diagnostic_messages.append(f"Detected {console_error_count} severe console errors. JavaScript on the page might be fundamentally broken, preventing form interaction or submission.")
                health_check_passed = False
            
            if not health_check_passed:
                final_log_level = logging.ERROR
                final_log_msg = f"{log_context} Page Health Check FAILED: {'; '.join(diagnostic_messages)}. This suggests direct bot detection blocking crucial page components, even if they load visually. Aborting further interaction to save resources."
                logger.log(final_log_level, final_log_msg)
                # Save screenshots and HTML source for detailed post-mortem analysis of the failed state
                self._save_screenshot(f"devtools_health_fail_{username or 'unknown'}", driver_instance) 
                self._save_page_source_for_debug(f"devtools_health_fail_source_{username or 'unknown'}", driver_instance)
                return False
            else:
                logger.info(f"{log_context} Page Health Check PASSED. Browser state and network integrity appear robust for proceeding with form interaction.")
                return True

        except Exception as e:
            logger.critical(f"{log_context} UNEXPECTED CRITICAL ERROR during DevTools page health check process: {e}. This indicates a problem within the check itself. Assuming page is unhealthy to be safe, and aborting.", exc_info=True)
            self._save_screenshot(f"devtools_check_exception_{username or 'unknown'}", driver_instance)
            self._save_page_source_for_debug(f"devtools_check_exception_source_{username or 'unknown'}", driver_instance)
            return False

    def _save_page_source_for_debug(self, prefix="page_source_debug", driver_instance=None):
        """
        Saves the full HTML source of the current page to a file for debugging purposes.
        This is particularly useful when visual elements are missing or interaction fails,
        but the HTML source is still present, providing context.
        """
        driver = driver_instance or self.driver
        if not driver:
            logger.warning("Attempted to save page source but no valid driver instance available.")
            return

        try:
            LOG_DIR.mkdir(exist_ok=True) # Ensure the designated log directory exists
            # Create a unique, sanitized filename with prefix, timestamp, and random suffix
            safe_prefix = re.sub(r'[^\w\-]+', '_', prefix)
            timestamp = time.strftime('%Y%m%d_%H%M%S')
            rand = random.randint(100, 999)
            filename = LOG_DIR / f"{safe_prefix}_{timestamp}_{rand}.html"

            # Retrieve the full page HTML source
            page_source = driver.page_source
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(page_source)
            logger.info(f"Full page source saved for debug: {filename.name}")
        except WebDriverException as e:
            logger.error(f"WebDriverException saving page source for '{prefix}': {e}", exc_info=logger.level == logging.DEBUG)
        except Exception as e:
            logger.error(f"Unexpected error saving page source for '{prefix}': {e}", exc_info=logger.level == logging.DEBUG)    
    
    def _clear_browser_data_cdp(self, driver_instance):
        """
        Clears all browser data (cache, cookies, local storage, etc.) using CDP commands.
        This provides a pristine browser state for each attempt.
        """
        if not driver_instance:
            logger.warning("Attempted to clear browser data but no driver instance provided.")
            return

        logger.debug("Attempting to clear browser data via CDP commands...")
        try:
            # Clear browser cache
            driver_instance.execute_cdp_cmd('Network.clearBrowserCache', {})
            logger.debug("Browser cache cleared.")

            # Clear browser cookies (more aggressive than simple driver.delete_all_cookies())
            driver_instance.execute_cdp_cmd('Network.clearBrowserCookies', {})
            logger.debug("Browser cookies cleared.")
            
            # Clear Local Storage, Session Storage, IndexedDB, WebSQL, Cache Storage
            # This is done by simulating a 'clear history' essentially.
            # `Browser.clearData` requires specifying data types and origin.
            # A more direct approach to clear all known storage types is often through JS injection
            # or by resetting the user-data-dir entirely (which we are doing with non-persistent profiles).
            # For this context, explicitly clearing individual storage is more robust.
            # Example for Local Storage for the current origin:
            driver_instance.execute_script("window.localStorage.clear();")
            driver_instance.execute_script("window.sessionStorage.clear();")
            logger.debug("Local and Session Storage cleared.")
            
            # For IndexedDB, CacheStorage etc., clearing browser cache and cookies helps,
            # but deep clearing might require more complex CDP like 'Storage.clearDataForOrigin'.
            # Given that non-persistent profiles (`--incognito` or new `user-data-dir`) should isolate this,
            # the primary focus is what persists *within* a session, for which JS clear is effective.

            logger.info("Browser cache, cookies, local and session storage successfully cleared via CDP.")
        except WebDriverException as e:
            logger.warning(f"WebDriverException during browser data clearing: {e}")
        except Exception as e:
            logger.error(f"Unexpected error during browser data clearing: {e}", exc_info=logger.level == logging.DEBUG)
            
    def _inject_stealth_js_early(self, driver_instance):
        """
        Injects JavaScript directly into the browser to evade common bot detection
        fingerprints *before* the page's scripts have a chance to run.
        This is done using CDP's `Page.addScriptToEvaluateOnNewDocument`.

        This version incorporates **Redirection Hijack Logic** (intercepts client-side JS navigation)
        and **Advanced Environmental Spoofing** to present a believable browser fingerprint.
        """
        if not driver_instance:
            logger.warning(
                "Attempted JS injection but no driver instance provided.")
            return

        logger.debug(
            "Injecting early-stage JavaScript cloaking and Redirection Hijack for fingerprint evasion...")
        try:
            # --- The Master Stealth and Redirection Hijack Payload ---
            stealth_js_code = """
            // This script will run BEFORE ANY page scripts, thanks to Page.addScriptToEvaluateOnNewDocument.
            // It's designed to fix known Selenium/Chromium anti-detection vectors and control navigation.

            // === 1. Essential Navigator Properties ===
            // Ensure 'webdriver' is always undefined (basic, but critical)
            Object.defineProperty(navigator, 'webdriver', { get: () => undefined, configurable: true });

            // Override `languages` for consistency if not handled elsewhere
            Object.defineProperty(navigator, 'languages', {
                get: () => ['en-US', 'en'], // Common pattern for English-speaking users
                configurable: true
            });

            // Spoof `hardwareConcurrency` (too low can be suspicious)
            // Randomize within a believable range for modern multi-core CPUs
            Object.defineProperty(navigator, 'hardwareConcurrency', { get: () => Math.floor(Math.random() * (16 - 4) + 4), configurable: true }); // 4-15 cores

            // === 2. Device Memory - A Crucial Tell ===
            // Override deviceMemory from 0.5 to a more realistic value (e.g., 4GB or 8GB blocks)
            // A more sophisticated spoofing than simply 4 or 8.
            Object.defineProperty(navigator, 'deviceMemory', { get: () => Math.floor(Math.random() * (16 - 4) / 4 + 1) * 4, configurable: true }); // e.g. 4, 8, 12, 16 GB

            // === 3. `window.chrome` Object - Fix Missing Runtime/Webstore ===
            // If window.chrome object is already present (from previous stealth or native)
            if (window.chrome && typeof window.chrome === 'object') {
                if (typeof window.chrome.runtime === 'undefined') {
                    Object.defineProperty(window.chrome, 'runtime', { get: () => ({}), configurable: true });
                }
                if (typeof window.chrome.webstore === 'undefined') {
                    Object.defineProperty(window.chrome, 'webstore', { get: () => ({}), configurable: true });
                }
            } else {
                // If window.chrome is completely missing or non-object, recreate it
                window.chrome = {
                    runtime: {},
                    app: { isInstalled: false }, // Mimics a standard Chrome browser without extensions
                    webstore: {}
                };
                Object.defineProperty(window, 'chrome', {
                    value: window.chrome,
                    writable: false, // Make it non-writable for stability
                    configurable: false // Make it non-configurable once set
                });
            }

            // === 4. Navigator Plugins - More Realistic Emulation ===
            // Recreate a more plausible, consistent plugin list with proper MIME types.
            // These names are typical for internal Chrome plugins.
            Object.defineProperty(navigator, 'plugins', {
                get: () => ([
                    {
                        name: 'Chrome PDF Viewer',
                        description: 'Portable Document Format',
                        filename: 'internal-pdf-viewer',
                        length: 1, // Number of MimeTypes
                        0: { type: 'application/pdf', description: 'Portable Document Format' }
                    },
                    {
                        name: 'Chromium PDF Viewer',
                        description: 'Portable Document Format',
                        filename: 'internal-pdf-viewer',
                        length: 1,
                        0: { type: 'application/x-google-chrome-pdf', description: 'Portable Document Format' }
                    }
                ]),
                configurable: true // Allow re-defining if other stealth libs interfere (unlikely with this level of early injection)
            });
            
            // maxTouchPoints for desktop browsers should typically be 0
            Object.defineProperty(navigator, 'maxTouchPoints', { get: () => 0, configurable: true });

            // === 5. WebGL Spoofing - The Most Critical Fix ===
            // Intercept getParameter to return plausible (but generic) GPU information.
            // This hides WebDriver's synthetic GPU or null values.

            const getParameterProxy = new Proxy(WebGLRenderingContext.prototype.getParameter, {
                apply: function(target, thisArg, argumentsList) {
                    const parameter = argumentsList[0];
                    const originalResult = Reflect.apply(target, thisArg, argumentsList); // Get actual result

                    switch (parameter) {
                        // UNMASKED_VENDOR_WEBGL (Commonly requested parameter for GPU vendor)
                        case 37445: return 'Google Inc.'; // A realistic, generic vendor for Chrome

                        // UNMASKED_RENDERED_WEBGL (Commonly requested parameter for GPU renderer)
                        // A believable generic renderer string, avoiding "WebKit" or null.
                        // SwiftShader is Google's software renderer, plausible on various systems.
                        case 37446: return 'ANGLE (Google, Vulkan 1.3.0 (SwiftShader) )'; 
                        
                        // Ensure other vital parameters return non-zero/non-null if they're commonly checked and expect numbers.
                        case 3379: // GL_MAX_TEXTURE_SIZE
                            return originalResult > 0 ? originalResult : 16384; 
                        case 34047: // GL_MAX_TEXTURE_MAX_ANISOTROPY_EXT
                            return originalResult ? originalResult : Float32Array.of(1.0); 
                        case 34930: // GL_MAX_VERTEX_ATTRIBS
                            return originalResult > 0 ? originalResult : 16;
                        case 7936: // GL_VENDOR (raw)
                            return 'Google Inc.'; 
                        case 7937: // GL_RENDERER (raw)
                            return 'ANGLE (Google, Vulkan 1.3.0 (SwiftShader))'; 
                        case 7938: // GL_VERSION (raw)
                            return 'WebGL 1.0 (ANGLE)';

                        default:
                            return originalResult;
                    }
                }
            });

            // Override the native getParameter method for WebGLRenderingContext
            Object.defineProperty(WebGLRenderingContext.prototype, 'getParameter', {
                value: getParameterProxy,
                configurable: true,
                writable: true
            });

            // === 6. Canvas 2D Spoofing - Introduce Minor Pixel Noise and Ensure Context Stability ===
            // This aims to make the canvas fingerprint unique on each run,
            // while preserving the visual integrity of what's drawn.
            const originalCanvasGetContext = HTMLCanvasElement.prototype.getContext;
            Object.defineProperty(HTMLCanvasElement.prototype, 'getContext', {
                value: function(...args) {
                    // Call the original getContext method to get the actual context
                    const context = originalCanvasGetContext.apply(this, args);

                    if (args[0] === '2d' && context) { // Ensure it's a 2D context and not null
                        // Intercept commonly used 2D context methods for fingerprinting
                        if (typeof context.fillText === 'function') {
                            const originalFillText = context.fillText;
                            // Ensure 'this' binding for original function
                            context.fillText = function(text, x, y, maxWidth) {
                                // Add a tiny random offset to the text coordinates
                                originalFillText.call(this, text, x + Math.random() * 0.1, y + Math.random() * 0.1, maxWidth);
                            };
                        }
                        if (typeof context.getImageData === 'function') {
                            const originalGetImageData = context.getImageData;
                             // Ensure 'this' binding for original function
                            context.getImageData = function(sx, sy, sw, sh) {
                                const imageData = originalGetImageData.call(this, sx, sy, sw, sh);
                                // Add very minor pixel noise to the ImageData (e.g., 1 bit per pixel to a few channels)
                                for (let i = 0; i < imageData.data.length; i += 4) { // Iterate through pixels (RGBA)
                                    if (Math.random() > 0.95) { // Only affect a small percentage of pixels
                                        imageData.data[i] = imageData.data[i] ^ 1;   // Toggle red channel
                                        imageData.data[i+1] = imageData.data[i+1] ^ 1; // Toggle green channel
                                    }
                                }
                                return imageData;
                            };
                        }
                        // Set standard properties that might be checked on the context
                        if (typeof context.font !== 'undefined') context.font = "14px Arial"; // Ensure a common font
                        if (typeof context.textBaseline !== 'undefined') context.textBaseline = "alphabetic"; // Default baseline
                    }
                    return context;
                },
                configurable: true,
                writable: true
            });

            // === 7. Anti-Bot Specific Traces Cleanup / Control ===
            // Remove specific known ChromeDriver/Puppeteer variables if they exist in the global scope.
            if (window.$cdc_ && typeof window.$cdc_ === 'object' && window.$cdc_.driver) {
                Object.defineProperty(window, '$cdc_', { value: undefined, configurable: true });
                delete window.$cdc_; 
            }
            if (window.chrome_cdp_events) {
                Object.defineProperty(window, 'chrome_cdp_events', { value: undefined, configurable: true });
                delete window.chrome_cdp_events;
            }
            
            // Normalize Function.prototype.toString (undo common proxy)
            // Some anti-bot methods try to check if `toString` is native code.
            // If it's wrapped, it changes its string representation. Restore it.
            // This must be done carefully to not cause illegal invocations.
            Object.defineProperty(Function.prototype.toString, 'toString', {
                value: (function originalToString() {
                    return 'function ' + this.name + '() { [native code] }';
                }).bind(Function.prototype.toString),
                configurable: true,
                writable: true
            });


            // === 8. REDIRECTION HIJACK / ANTI-NAVIGATION LOGIC (Still critical) ===
            // Intercept and prevent actual URL changes triggered by client-side JS
            // While still logging the intended destination to the console.

            const originalPushState = history.pushState;
            const originalReplaceState = history.replaceState;
            const originalAssign = window.location.assign;
            const originalReplace = window.location.replace;
            // Removed direct window.location.href setter override due to browser protection issues.

            // Store attempted navigations for Python to collect via console logs
            const logHijackedNavigation = (type, targetUrl, details = {}) => {
                const logEntry = {
                    event: 'RedirectionHijack',
                    type: type,
                    targetUrl: targetUrl,
                    // Keep original URL for logging to track the non-change
                    currentUrlWhenHijacked: window.location.href, 
                    timestamp: Date.now(),
                    details: details
                };
                // Use a distinctive prefix for Python to easily parse these specific logs
                console.log(`__HIJACKED_NAV_LOG__: ${JSON.stringify(logEntry)}`);
            };

            // 1. Override history.pushState & history.replaceState (soft navigation)
            history.pushState = function(state, unused, url) {
                if (url && typeof url === 'string' && url !== window.location.href) {
                    logHijackedNavigation('history.pushState', url, { state: state });
                }
                // Suppress actual history changes for stability.
            };

            history.replaceState = function(state, unused, url) {
                if (url && typeof url === 'string' && url !== window.location.href) {
                    logHijackedNavigation('history.replaceState', url, { state: state });
                }
                // Suppress actual history changes.
            };

            // 2. Override window.location.assign (direct navigation)
            window.location.assign = function(url) {
                if (url && typeof url === 'string' && url !== window.location.href) {
                    logHijackedNavigation('location.assign', url);
                }
                // Prevent actual navigation: do NOT call originalAssign.
            };

            // 3. Override window.location.replace (direct navigation, no history)
            window.location.replace = function(url) {
                if (url && typeof url === 'string' && url !== window.location.href) {
                    logHijackedNavigation('location.replace', url);
                }
                // Prevent actual navigation: do NOT call originalReplace.
            };

            // 4. Clean up localStorage/sessionStorage calls, but only if access is possible.
            // This addresses the "Storage is disabled inside 'data:' URLs" warning.
            // It uses a try-catch for robustness on storage access.
            if (window.location.protocol !== 'data:') { // Already in place, but essential
                try {
                    // Only attempt to clear if storage is actually accessible and not null/undefined
                    if (window.localStorage && typeof window.localStorage.clear === 'function') {
                        window.localStorage.clear();
                    }
                    if (window.sessionStorage && typeof window.sessionStorage.clear === 'function') {
                        window.sessionStorage.clear();
                    }
                    // Optionally, add logic for IndexedDB and Cache Storage, more complex via JS.
                    // This is sufficient for primary HTTP/HTTPS pages.
                } catch (e) {
                    // Log to console if an error occurs during clear (e.g., security error on certain pages)
                    console.warn(`Stealth Payload V5: Error clearing storage. May be due to security sandbox on certain URLs: ${e.message}`);
                }
            }


            console.log("Stealth Payload V5: Full environmental reconstruction, navigation hijack, and storage clearing fix deployed.");
            """

            # Use CDP command to inject the script. This runs BEFORE document scripts.
            driver_instance.execute_cdp_cmd("Page.addScriptToEvaluateOnNewDocument", {
                "source": stealth_js_code,
                "id": "insta-stealth-and-hijack-v5-injection"
            })
            logger.info(
                "Early-stage JavaScript cloaking (CDP `addScriptToEvaluateOnNewDocument`) injected successfully.")
        except WebDriverException as e:
            logger.error(
                f"WebDriverException during early JS injection: {e}. Cannot apply full fingerprint evasion or redirect control.", exc_info=logger.level == logging.DEBUG)
        except Exception as e:
            logger.critical(
                f"Unexpected error during early JS injection: {e}. Major stealth layer compromised.", exc_info=True)
                    
    def close_driver(self):
        """Closes the main WebDriver instance if it exists."""
        if self.driver:
            user = self.current_account.get('username', 'None') if self.current_account else 'None'
            logger.debug(f"Closing main WebDriver (Proxy: {self.current_proxy_address}, User: {user})...")
            try:
                self.driver.quit()
            except Exception as e: logger.error(f"Error during driver quit: {e}")
            finally:
                self.driver = None
                self.current_account = None
                self.current_proxy_address = None
                

# === GUI Class ===

class EnhancedInstagramManagerGUI:
    # --- Color Palette ---
    BG_COLOR = "#2E2E2E"
    FG_COLOR = "#EAEAEA"
    ACCENT_COLOR = "#C13584"
    SECONDARY_COLOR = "#5851DB"
    WIDGET_BG = "#3C3C3C"
    WIDGET_FG = "#FFFFFF"
    ERROR_COLOR = "#FF6B6B"
    SUCCESS_COLOR = "#6BCB77"
    LOG_TEXT_BG = "#252525"
    LISTBOX_SELECT_BG = ACCENT_COLOR
    TREEVIEW_HEAD_BG = SECONDARY_COLOR
    PROGRESS_BAR_COLOR = SECONDARY_COLOR
    LOG_COLOR_DEBUG = "grey60"
    LOG_COLOR_INFO = FG_COLOR
    LOG_COLOR_WARNING = "orange"
    LOG_COLOR_ERROR = ERROR_COLOR
    LOG_COLOR_CRITICAL = "#FF2020"

    def __init__(self, root, manager_instance):
        """
        Initializes the Enhanced Instagram Manager GUI.

        Args:
            root (tk.Tk): The main Tkinter root window.
            manager_instance (EnhancedInstagramManager): An instance of the backend manager logic.
        """
        # --- Input Validation ---
        if not isinstance(root, tk.Tk):
            raise TypeError("GUI root must be a tk.Tk instance.")
        if not isinstance(manager_instance, EnhancedInstagramManager):
            raise TypeError("GUI requires an EnhancedInstagramManager instance.")

        # --- Core Attributes ---
        self.root = root
        self.manager = manager_instance
        self.manager.gui = self # Link manager back to GUI

        # --- Logging Setup for GUI ---
        self.log_queue = queue.Queue()
        log_level = logging.DEBUG if self.manager.settings.get("debug_mode") else logging.INFO
        # Setup global logging again, passing the queue reference for GUI updates
        setup_global_logging(level=log_level, queue_ref=self.log_queue)

        logger.info("Initializing GUI...")

        # --- Window and Style Configuration ---
        self._configure_root_window()
        self._configure_styles()

        # --- Main Layout Frame ---
        self.main_frame = ttk.Frame(self.root, padding="10")
        self.main_frame.pack(fill=tk.BOTH, expand=True)

        # --- Tab Control Setup ---
        self.tab_control = ttk.Notebook(self.main_frame, style="TNotebook")
        self.account_tab = ttk.Frame(self.tab_control, padding="10")
        self.proxy_tab = ttk.Frame(self.tab_control, padding="10")
        self.report_tab = ttk.Frame(self.tab_control, padding="10")
        self.data_tab = ttk.Frame(self.tab_control, padding="10")
        self.settings_log_tab = ttk.Frame(self.tab_control, padding="10")

        self.tab_control.add(self.account_tab, text=" Accounts ")
        self.tab_control.add(self.proxy_tab, text=" Proxies ")
        self.tab_control.add(self.report_tab, text=" Reporting ")
        self.tab_control.add(self.data_tab, text=" Data Extraction ")
        self.tab_control.add(self.settings_log_tab, text=" Settings & Log ")
        self.tab_control.pack(fill=tk.BOTH, expand=True, pady=5)

        # --- Status Bar ---
        self.status_var = tk.StringVar(value="Initializing...")
        self.status_bar = ttk.Label(self.root, textvariable=self.status_var, style="Status.TLabel", relief=tk.SUNKEN, anchor=tk.W, padding=(5, 2))
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X, pady=(5, 0)) # Pack below tabs

        # --- GUI State Variables ---
        self._action_buttons = [] # To manage button states collectively
        self._last_extracted_data = None # Store results of data extraction
        self._mass_report_active = threading.Event() # Track if mass report is running

        # --- Initialization Steps ---
        self._init_setting_vars() # Initialize Tkinter variables linked to settings
        self.setup_account_tab()
        self.setup_proxy_tab()
        self.setup_report_tab()
        self.setup_data_tab()
        self.setup_settings_log_tab()

        # --- Initial GUI Updates & Callbacks ---
        self.update_account_listbox() # Populate account list
        self.update_proxy_treeview() # Populate proxy list
        self.enable_actions(False) # Start with actions disabled
        self.root.after(500, self.check_proxy_readiness) # Check when proxies are ready
        self.root.after(100, self.update_log_display) # Start polling log queue
        self.root.protocol("WM_DELETE_WINDOW", self.on_close) # Handle closing the window
        self.setup_error_handling() # Set up global error handler for Tkinter

        logger.info(
            f"GUI Initialized. (Total Startup Time: {time.monotonic() - START_TIME:.2f}s)"
        )

    def _init_setting_vars(self):
        """ Initialize tk variables for settings before GUI elements are created. """
        self.settings_vars = {
            "debug_mode": tk.BooleanVar(value=self.manager.settings.get("debug_mode", False)),
             # === NEW DEBUGGING SETTING VAR ===
            "debug_pause_duration_on_fail": tk.IntVar(value=self.manager.settings.get("debug_pause_duration_on_fail", 0)),
             # ======================================
            "headless": tk.BooleanVar(value=self.manager.settings.get("headless", True)),
            "enable_stealth": tk.BooleanVar(value=self.manager.settings.get("enable_stealth", True)),
            "save_screenshots": tk.BooleanVar(value=self.manager.settings.get("save_screenshots", False)),
            "use_direct_connection_fallback": tk.BooleanVar(value=self.manager.settings.get("use_direct_connection_fallback", True)),
            "force_direct_connection": tk.BooleanVar(value=self.manager.settings.get("force_direct_connection", False)), 
            "geoip_db_path": tk.StringVar(value=self.manager.settings.get("geoip_db_path", "")),
            "chrome_driver_path": tk.StringVar(value=self.manager.settings.get("chrome_driver_path", "")),
            "chrome_binary_path": tk.StringVar(value=self.manager.settings.get("chrome_binary_path", "")),
            "random_delay_min": tk.DoubleVar(value=self.manager.settings.get("random_delay_min", 0.8)),
            "random_delay_max": tk.DoubleVar(value=self.manager.settings.get("random_delay_max", 2.5)),
            "account_creation_delay_min": tk.DoubleVar(value=self.manager.settings.get("account_creation_delay_min", 4.0)),
            "account_creation_delay_max": tk.DoubleVar(value=self.manager.settings.get("account_creation_delay_max", 10.0)),
            "report_interval_seconds": tk.IntVar(value=self.manager.settings.get("report_interval_seconds", 1800)),
            "webdriver_wait_timeout": tk.IntVar(value=self.manager.settings.get("webdriver_wait_timeout", 15)),
            "proxy_timeout": tk.IntVar(value=self.manager.settings.get("proxy_timeout", 5)),
            "use_persistent_browser_profiles": tk.BooleanVar(value=self.manager.settings.get("use_persistent_browser_profiles", False)),
            "enable_username_url_precheck": tk.BooleanVar(value=self.manager.settings.get("enable_username_url_precheck", True)),
            "max_prechecks_per_signup": tk.IntVar(value=self.manager.settings.get("max_prechecks_per_signup", 2)),
            # Default to cleanup
            "cleanup_persistent_profiles": tk.BooleanVar(value=self.manager.settings.get("cleanup_persistent_profiles", True)),
            "max_login_attempts": tk.IntVar(value=self.manager.settings.get("max_login_attempts", 2)),
            "max_reports_per_day": tk.IntVar(value=self.manager.settings.get("max_reports_per_day", 15)),
            "proxy_test_threads": tk.IntVar(value=self.manager.settings.get("proxy_test_threads", 100)),
            "max_mass_report_workers": tk.IntVar(value=self.manager.settings.get("max_mass_report_workers", 5)),
          # === NEW ACCOUNT AGING SETTING VARS ===
            "enable_account_aging": tk.BooleanVar(value=self.manager.settings.get("enable_account_aging", True)),
            "min_age_action_delay_sec": tk.DoubleVar(value=self.manager.settings.get("min_age_action_delay_sec", 3.0)),
            "max_age_action_delay_sec": tk.DoubleVar(value=self.manager.settings.get("max_age_action_delay_sec", 8.0)),
            "num_explore_scroll_loops": tk.IntVar(value=self.manager.settings.get("num_explore_scroll_loops", 3)),
            "num_profiles_to_follow": tk.IntVar(value=self.manager.settings.get("num_profiles_to_follow", 3)),
            "num_posts_to_like": tk.IntVar(value=self.manager.settings.get("num_posts_to_like", 5)),
            # ======================================
        }
        

    def _configure_root_window(self):
        self.root.title(f"Instagram Account Manager V2.5.1")
        default_width, default_height = 1200, 850
        min_width, min_height = 1000, 700
        try:
            screen_width = self.root.winfo_screenwidth()
            screen_height = self.root.winfo_screenheight()
            x_pos = max(0, (screen_width//2)-(default_width//2))
            y_pos = max(0, (screen_height//2)-(default_height//2))
            self.root.geometry(f"{default_width}x{default_height}+{x_pos}+{y_pos}")
        except: self.root.geometry(f"{default_width}x{default_height}")
        self.root.minsize(min_width, min_height)
        self.root.configure(bg=self.BG_COLOR)

    def _configure_styles(self):
        self.style = ttk.Style()
        try: self.style.theme_use('clam')
        except tk.TclError: logger.warning("Clam theme N/A.")
        self.style.configure(".", background=self.BG_COLOR, foreground=self.FG_COLOR, fieldbackground=self.WIDGET_BG, insertcolor=self.WIDGET_FG, font=("Segoe UI", 9))
        self.style.map(".", background=[('disabled', self.BG_COLOR)], foreground=[('disabled', 'grey50')])
        self.style.configure("TFrame", background=self.BG_COLOR)
        self.style.configure("TLabel", background=self.BG_COLOR, foreground=self.FG_COLOR); self.style.configure("Header.TLabel", foreground=self.ACCENT_COLOR, font=("Segoe UI", 14, "bold"))
        self.style.configure("Status.TLabel", foreground=self.SECONDARY_COLOR, font=("Segoe UI", 9), background="#333333")
        self.style.configure("Error.TLabel", foreground=self.ERROR_COLOR, font=("Segoe UI", 9, "bold"))
        self.style.configure("Success.TLabel", foreground=self.SUCCESS_COLOR, font=("Segoe UI", 9))
        self.style.configure("TButton", background=self.ACCENT_COLOR, foreground=self.WIDGET_FG, font=("Segoe UI", 10, "bold"), borderwidth=1, padding=(10, 6))
        self.style.map("TButton", background=[('active', self.SECONDARY_COLOR), ('disabled', '#555555')], foreground=[('disabled', '#AAAAAA')], relief=[('pressed', tk.SUNKEN), ('!pressed', tk.RAISED)])
        self.style.configure("TNotebook", background=self.BG_COLOR, borderwidth=0)
        self.style.configure("TNotebook.Tab", background=self.WIDGET_BG, foreground="grey85", font=("Segoe UI", 10), padding=[12, 6], borderwidth=0)
        self.style.map("TNotebook.Tab", background=[("selected", self.SECONDARY_COLOR)], foreground=[("selected", self.WIDGET_FG)], font=[("selected", ("Segoe UI", 10, "bold"))], expand=[("selected", [1, 1, 1, 0])])
        self.style.configure("TLabelframe", background=self.BG_COLOR, borderwidth=1, relief=tk.GROOVE, padding=10)
        self.style.configure("TLabelframe.Label", background=self.BG_COLOR, foreground=self.SECONDARY_COLOR, font=("Segoe UI", 10, "italic"))
        self.style.configure("TCheckbutton", background=self.BG_COLOR, foreground=self.FG_COLOR, indicatorcolor=self.WIDGET_BG, font=("Segoe UI", 9))
        self.style.map("TCheckbutton", indicatorcolor=[('selected', self.ACCENT_COLOR), ('active', self.SECONDARY_COLOR)], foreground=[('disabled', 'grey50')])
        self.style.configure("TEntry", foreground=self.WIDGET_FG, fieldbackground=self.WIDGET_BG, borderwidth=1, relief=tk.FLAT)
        self.style.map("TEntry", fieldbackground=[('disabled', '#505050')], foreground=[('disabled', 'grey70')])
        self.style.configure("TSpinbox", foreground=self.WIDGET_FG, fieldbackground=self.WIDGET_BG, borderwidth=1, arrowcolor=self.FG_COLOR, relief=tk.FLAT, arrowsize=10)
        self.style.map("TSpinbox", fieldbackground=[('disabled', '#505050')], foreground=[('disabled', 'grey70')])
        self.style.configure("TCombobox", foreground=self.WIDGET_FG, fieldbackground=self.WIDGET_BG, borderwidth=1, arrowcolor=self.FG_COLOR, relief=tk.FLAT, padding=(5,3))
        self.style.map('TCombobox', fieldbackground=[('readonly', self.WIDGET_BG), ('disabled', '#505050')], foreground=[('readonly', self.WIDGET_FG), ('disabled', 'grey70')])
        self.root.option_add('*TCombobox*Listbox.background', self.WIDGET_BG)
        self.root.option_add('*TCombobox*Listbox.foreground', self.WIDGET_FG); self.root.option_add('*TCombobox*Listbox.selectBackground', self.SECONDARY_COLOR)
        self.root.option_add('*TCombobox*Listbox.selectForeground', self.WIDGET_FG)
        self.root.option_add('*TCombobox*Listbox.font', ("Segoe UI", 9))
        self.style.configure("Treeview", background=self.WIDGET_BG, foreground=self.WIDGET_FG, fieldbackground=self.WIDGET_BG, borderwidth=1, relief=tk.FLAT, rowheight=22)
        self.style.configure("Treeview.Heading", background=self.TREEVIEW_HEAD_BG, foreground=self.WIDGET_FG, font=("Segoe UI", 9, "bold"), relief=tk.FLAT, padding=(5, 5))
        self.style.map("Treeview.Heading", background=[('active', self.ACCENT_COLOR)])
        self.style.map("Treeview", background=[('selected', self.LISTBOX_SELECT_BG)], foreground=[('selected', self.WIDGET_FG)])
        self.style.configure("Vertical.TScrollbar", background=self.WIDGET_BG, troughcolor=self.BG_COLOR, borderwidth=0, arrowcolor=self.FG_COLOR)
        self.style.configure("Horizontal.TScrollbar", background=self.WIDGET_BG, troughcolor=self.BG_COLOR, borderwidth=0, arrowcolor=self.FG_COLOR)
        self.style.map("TScrollbar", background=[('active', self.SECONDARY_COLOR)])
        self.style.configure("Horizontal.TProgressbar", troughcolor=self.WIDGET_BG,
                             background=self.PROGRESS_BAR_COLOR, borderwidth=1, thickness=15)

    def setup_account_tab(self):
        logger.debug("Setting up Account tab...")
        main_acc_frame = ttk.Frame(self.account_tab)
        main_acc_frame.pack(fill=tk.BOTH, expand=True)
        main_acc_frame.rowconfigure(0, weight=1)
        main_acc_frame.columnconfigure(0, weight=1)
        list_frame = ttk.LabelFrame(main_acc_frame, text=" Saved Accounts ", style="TLabelframe")
        list_frame.grid(row=0, column=0, padx=5, pady=5, sticky="nsew")
        list_scrollbar = ttk.Scrollbar(list_frame, orient="vertical", style="Vertical.TScrollbar")
        list_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.account_listbox = tk.Listbox(list_frame, bg=self.WIDGET_BG, fg=self.WIDGET_FG, selectbackground=self.LISTBOX_SELECT_BG, selectforeground=self.WIDGET_FG, font=("Segoe UI", 10), relief=tk.FLAT, highlightthickness=0, borderwidth=1, yscrollcommand=list_scrollbar.set); self.account_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True); list_scrollbar.config(command=self.account_listbox.yview); self.account_listbox.bind('<<ListboxSelect>>', self.on_account_select)
        manual_frame = ttk.LabelFrame(main_acc_frame, text=" Manual Login ", style="TLabelframe")
        manual_frame.grid(row=1, column=0, padx=5, pady=(10, 5), sticky="ew")
        manual_frame.columnconfigure(1, weight=1)
        ttk.Label(manual_frame, text="Username:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.manual_user_entry = ttk.Entry(manual_frame, width=30)
        self.manual_user_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        ttk.Label(manual_frame, text="Password:").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.manual_pass_entry = ttk.Entry(manual_frame, width=30, show="*")
        self.manual_pass_entry.grid(row=1, column=1, padx=5, pady=5, sticky="ew")
        self.manual_login_btn = ttk.Button(manual_frame, text="Login with These Credentials", 
                                           command=self.manual_login, style="TButton")
        self.manual_login_btn.grid(row=0, column=2, rowspan=2, padx=10, pady=5, sticky="ns")
        button_frame = ttk.Frame(main_acc_frame)
        button_frame.grid(row=2, column=0, padx=5, pady=(5, 0), sticky="ew")
        button_frame.columnconfigure(0, weight=1)
        button_frame.columnconfigure(1, weight=1)
        self.create_account_btn = ttk.Button(button_frame, text="Create New Account", 
                                             command=self.create_account, style="TButton")
        self.create_account_btn.grid(row=0, column=0, padx=5, pady=5, sticky="ew")
        self.login_btn = ttk.Button(button_frame, text="Login Selected Account", 
                                    command=self.login_selected_account, 
                                    style="TButton", state=tk.DISABLED)
        self.login_btn.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        self._action_buttons.extend(
            [self.create_account_btn, self.manual_login_btn])

    def setup_proxy_tab(self):
        logger.debug("Setting up Proxy tab...")
        tree_frame = ttk.Frame(self.proxy_tab); tree_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10)); tree_frame.grid_rowconfigure(0, weight=1); tree_frame.grid_columnconfigure(0, weight=1)
        self.proxy_tree = ttk.Treeview(tree_frame, columns=("address", "status", "latency", "country", "last_checked"), show="headings", style="Treeview"); headings = {"address": ("Proxy Address / Direct", 200, tk.W), "status": ("Status", 100, tk.CENTER), "latency": ("Latency (s)", 80, tk.CENTER), "country": ("Country", 100, tk.CENTER), "last_checked": ("Last Checked", 150, tk.CENTER)}
        for cid, (txt, wd, anc) in headings.items():
            self.proxy_tree.heading(cid, text=txt, anchor=anc); self.proxy_tree.column(cid, width=wd, anchor=anc, stretch=tk.YES);
        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.proxy_tree.yview, style="Vertical.TScrollbar"); hsb = ttk.Scrollbar(tree_frame, orient="horizontal", command=self.proxy_tree.xview, style="Horizontal.TScrollbar"); self.proxy_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set); self.proxy_tree.grid(row=0, column=0, sticky="nsew"); vsb.grid(row=0, column=1, sticky="ns"); hsb.grid(row=1, column=0, sticky="ew")
        bottom_frame = ttk.Frame(self.proxy_tab)
        bottom_frame.pack(fill=tk.X, pady=(5, 0)); bottom_frame.columnconfigure(0, weight=1)
        self.proxy_progress = ttk.Progressbar(bottom_frame, orient="horizontal", mode="determinate", style="Horizontal.TProgressbar") # Grid later
        self.refresh_proxies_btn = ttk.Button(bottom_frame, text="🔄 Refresh Proxy List", command=self.refresh_proxies, style="TButton")
        self.refresh_proxies_btn.grid(row=0, column=1, padx=10, pady=5, sticky="e")
        self._action_buttons.append(self.refresh_proxies_btn)

    def setup_report_tab(self):
        logger.debug("Setting up Report tab...")
        target_frame = ttk.LabelFrame(self.report_tab, text=" Target Account ", style="TLabelframe"); target_frame.pack(fill=tk.X, pady=(0, 10)); target_frame.columnconfigure(1, weight=1); ttk.Label(target_frame, text="Username:").grid(row=0, column=0, padx=5, pady=5, sticky="w"); self.target_entry = ttk.Entry(target_frame, style="TEntry", width=40); self.target_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        reason_frame = ttk.LabelFrame(self.report_tab, text=" Report Reason ", style="TLabelframe")
        reason_frame.pack(fill=tk.X, pady=(0, 10)); report_reasons = ["Spam", "Scam or Fraud", "Hate Speech", "Bullying or Harassment", "Nudity or Sexual Activity", "Violence or Dangerous", "Intellectual Property", "Sale of Illegal or Regulated Goods", "Suicide or Self-Injury", "False Information", "Impersonation", "Underage" ,"Something Else"]; self.report_reason_var = tk.StringVar(value=report_reasons[0]); self.report_reason_combo = ttk.Combobox(reason_frame, textvariable=self.report_reason_var, values=report_reasons, state="readonly", style="TCombobox"); self.report_reason_combo.pack(fill=tk.X, padx=5, pady=5)
        mass_opts_frame = ttk.LabelFrame(self.report_tab, text=" Mass Report Options ", style="TLabelframe")
        mass_opts_frame.pack(fill=tk.X, pady=(0, 10)); mass_opts_frame.columnconfigure(1, weight=1); mass_opts_frame.columnconfigure(3, weight=1)
        ttk.Label(mass_opts_frame, text="Use Accounts (Max):").grid(
            row=0, column=0, padx=5, pady=5, sticky="w")
        self.mass_report_accounts_var = tk.IntVar(value=max(1, len(self.manager.accounts)))
        self.mass_report_accounts_spin = ttk.Spinbox(mass_opts_frame, from_=1, to=10000, increment=1, textvariable=self.mass_report_accounts_var, width=8, style="TSpinbox"); self.mass_report_accounts_spin.grid(row=0, column=1, padx=5, pady=5, sticky="w")
        ttk.Label(mass_opts_frame, text="Concurrent Workers:").grid(
            row=0, column=2, padx=5, pady=5, sticky="w")
        self.mass_report_workers_spin = ttk.Spinbox(mass_opts_frame, from_=1, to=self.settings_vars["max_mass_report_workers"].get() * 2, increment=1, textvariable=self.settings_vars["max_mass_report_workers"], width=8, style="TSpinbox")
        self.mass_report_workers_spin.grid(row=0, column=3, padx=5, pady=5, sticky="w")
        button_frame = ttk.Frame(self.report_tab)
        button_frame.pack(fill=tk.X, pady=(15, 0)); button_frame.columnconfigure(0, weight=1); button_frame.columnconfigure(1, weight=1)
        self.single_report_btn = ttk.Button(button_frame, text="Report with Logged-in Account", command=self.single_report, style="TButton")
        self.single_report_btn.grid(row=0, column=0, padx=5, pady=5, sticky="ew")
        self.mass_report_btn = ttk.Button(button_frame, text="Mass Report (Using Options Above)", command=self.mass_report, style="TButton")
        self.mass_report_btn.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        self._action_buttons.extend(
            [self.single_report_btn, self.mass_report_btn])

    def setup_data_tab(self):
        logger.debug("Setting up Data Extraction tab...")
        target_frame = ttk.LabelFrame(self.data_tab, text=" Target Account ", style="TLabelframe"); target_frame.pack(fill=tk.X, pady=(0, 10)); target_frame.columnconfigure(1, weight=1); ttk.Label(target_frame, text="Username:").grid(row=0, column=0, padx=5, pady=5, sticky="w"); self.data_target_entry = ttk.Entry(target_frame, style="TEntry", width=40); self.data_target_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        button_frame = ttk.Frame(self.data_tab); button_frame.pack(fill=tk.X, pady=(5, 10)); button_frame.columnconfigure(1, weight=1)
        self.extract_data_btn = ttk.Button(button_frame, text="📊 Extract Profile Data", command=self.extract_data, style="TButton"); self.extract_data_btn.grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.save_data_btn = ttk.Button(button_frame, text="💾 Save Last Extracted Data", command=self.save_extracted_data, style="TButton", state=tk.DISABLED); self.save_data_btn.grid(row=0, column=2, padx=5, pady=5, sticky="e")
        results_frame = ttk.LabelFrame(self.data_tab, text=" Extracted Data ", style="TLabelframe")
        results_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 0))
        self.data_results_text = scrolledtext.ScrolledText(results_frame, bg=self.LOG_TEXT_BG, fg=self.FG_COLOR, insertbackground=self.FG_COLOR, wrap=tk.WORD, font=("Consolas", 10), relief=tk.FLAT, highlightthickness=0, borderwidth=1, state=tk.DISABLED)
        self.data_results_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self._action_buttons.append(self.extract_data_btn)

    def setup_settings_log_tab(self):
        logger.debug("Setting up Settings & Log tab...")
        
        # PanedWindow for separating settings from logs
        paned_window = ttk.PanedWindow(self.settings_log_tab, 
                                       orient=tk.VERTICAL)
        paned_window.pack(fill=tk.BOTH, 
                          expand=True)

        # Top pane for settings, with a scrollbar
        settings_scroll_frame = ttk.Frame(paned_window)
        settings_canvas = tk.Canvas(settings_scroll_frame, 
                                    bg=self.BG_COLOR, highlightthickness=0)
        settings_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        settings_scrollbar = ttk.Scrollbar(settings_scroll_frame, 
                                           orient="vertical", 
                                           command=settings_canvas.yview, style="Vertical.TScrollbar")
        settings_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        settings_canvas.configure(yscrollcommand=settings_scrollbar.set)
        
        settings_inner_frame = ttk.Frame(settings_canvas, padding=10)
        settings_canvas.create_window((0,0), window=settings_inner_frame, anchor="nw")
        settings_inner_frame.bind("<Configure>", lambda e: settings_canvas.configure(scrollregion=settings_canvas.bbox("all")))
        
        # Layout configuration for columns
        col_widths = [150, 80, 150, 80] 
        num_cols = len(col_widths) 
        current_row = 0 

        # --- Behavior Settings Section ---
        ttk.Label(settings_inner_frame, text="Behavior", style="TLabelframe.Label").grid(row=current_row, 
                                                                                         column=0, columnspan=num_cols, sticky="w", pady=(0,5))
        current_row += 1
        # -- use persisten profile setting --
        ttk.Checkbutton(settings_inner_frame, text="Use Persistent Profiles", 
                        variable=self.settings_vars["use_persistent_browser_profiles"], 
                        command=self.update_manager_bool_setting("use_persistent_browser_profiles"), 
                        style="TCheckbutton").grid(row=current_row, 
                                                   column=0, columnspan=2, sticky="w", padx=5, pady=2)
        # -- profile cleanup on exit setting -- 
        ttk.Checkbutton(settings_inner_frame, text="Cleanup Profiles on Exit", 
                        variable=self.settings_vars["cleanup_persistent_profiles"], 
                        command=self.update_manager_bool_setting("cleanup_persistent_profiles"), 
                        style="TCheckbutton").grid(row=current_row, 
                                                   column=2, columnspan=2, sticky="w", padx=5, pady=2)
        current_row += 1
        
        # --- New Username Pre-Check Settings ---
        ttk.Checkbutton(settings_inner_frame, text="Enable Fast Username Pre-Check", 
                        variable=self.settings_vars["enable_username_url_precheck"], 
                        command=self.update_manager_bool_setting("enable_username_url_precheck"), 
                        style="TCheckbutton").grid(row=current_row, 
                                                   column=0, columnspan=2, sticky="w", padx=5, pady=2)
        
        self._create_spinbox_setting(settings_inner_frame, current_row, 2,
                            "Max Pre-Checks / Signup:", self.settings_vars["max_prechecks_per_signup"], 0, 5,
                            setting_key_name_str="max_prechecks_per_signup")
        current_row += 1
        
        # --- Separator and Account Aging/Behavior Section ---
        ttk.Separator(settings_inner_frame, 
                      orient=tk.HORIZONTAL).grid(row=current_row, 
                                                column=0, columnspan=num_cols, sticky='ew', pady=8)
        current_row += 1
        
        ttk.Label(settings_inner_frame, 
                  text="Account Aging / Bot Behavior", style="TLabelframe.Label").grid(row=current_row, 
                                                  column=0, columnspan=num_cols, sticky="w", pady=(0,5))
        current_row += 1
        
        ttk.Checkbutton(settings_inner_frame, text="Enable Account Aging", 
                        variable=self.settings_vars["enable_account_aging"], 
                        command=self.update_manager_bool_setting("enable_account_aging"), 
                        style="TCheckbutton").grid(row=current_row, column=0, columnspan=2, sticky="w", padx=5, pady=2)
        current_row += 1
        
        self._create_spinbox_setting(settings_inner_frame, current_row, 0, "Min Age Delay:", 
                            self.settings_vars["min_age_action_delay_sec"], 1.0, 30.0, is_float=True,
                            setting_key_name_str="min_age_action_delay_sec")
        
        self._create_spinbox_setting(settings_inner_frame, current_row, 2, "Max Age Delay:", 
                            self.settings_vars["max_age_action_delay_sec"], 2.0, 60.0, is_float=True,
                            setting_key_name_str="max_age_action_delay_sec")
        current_row += 1

        self._create_spinbox_setting(settings_inner_frame, current_row, 0, "Explore Scrolls:", 
                            self.settings_vars["num_explore_scroll_loops"], 0, 10,
                            setting_key_name_str="num_explore_scroll_loops")
        
        self._create_spinbox_setting(settings_inner_frame, current_row, 2, "Profiles to Follow:", 
                            self.settings_vars["num_profiles_to_follow"], 0, 10,
                            setting_key_name_str="num_profiles_to_follow")
        current_row += 1

        self._create_spinbox_setting(settings_inner_frame, current_row, 0, "Posts to Like:", 
                            self.settings_vars["num_posts_to_like"], 0, 10,
                            setting_key_name_str="num_posts_to_like")
        current_row += 1 # Ensure row counter correctly increments
        # --- Separator and Debug/Stealth Settings Section ---
        ttk.Checkbutton(settings_inner_frame, text="Debug Mode", variable=self.settings_vars["debug_mode"], 
                        command=self.toggle_debug_mode, style="TCheckbutton").grid(
            row=current_row, column=0, columnspan=2, sticky="w", padx=5, pady=2)
        
        # Checkbuttons placed on the same `current_row`, consuming two columns each.
        ttk.Checkbutton(settings_inner_frame, text="Enable Stealth", 
                        variable=self.settings_vars["enable_stealth"], 
                        command=self.update_manager_bool_setting("enable_stealth"), 
                        style="TCheckbutton").grid(row=current_row, column=2, columnspan=2, sticky="w", padx=5, pady=2)
        current_row += 1 # Increment row after this logical group of checkbuttons

        ttk.Checkbutton(settings_inner_frame, text="Run Headless", variable=self.settings_vars["headless"], command=self.update_manager_bool_setting(
            "headless"), style="TCheckbutton").grid(row=current_row, column=0, columnspan=2, sticky="w", padx=5, pady=2)
        ttk.Checkbutton(settings_inner_frame, text="Save Screenshots", variable=self.settings_vars["save_screenshots"], command=self.update_manager_bool_setting("save_screenshots"), style="TCheckbutton").grid(row=current_row, column=2, columnspan=2, sticky="w", padx=5, pady=2)
        current_row += 1 # Increment row after this logical group
        
        # --- NEW: use Direct Connection Checkbox ---
        ttk.Checkbutton(settings_inner_frame, text="Use Direct Conn Fallback", 
                        variable=self.settings_vars["use_direct_connection_fallback"], 
                        command=self.update_manager_bool_setting("use_direct_connection_fallback"), 
                        style="TCheckbutton").grid(row=current_row, column=0, columnspan=2, sticky="w", padx=5, pady=2)
        
        # --- NEW: Force Direct Connection Checkbox ---
        ttk.Checkbutton(settings_inner_frame, text="FORCE Direct Connection", 
                        variable=self.settings_vars["force_direct_connection"], 
                        command=self.update_manager_bool_setting("force_direct_connection"), 
                        style="TCheckbutton").grid(row=current_row, column=2, columnspan=2, sticky="w", padx=5, pady=2)
        current_row += 1 
        
        # --- Separator and Timing Settings Section ---
        ttk.Separator(settings_inner_frame, 
                      orient=tk.HORIZONTAL).grid(row=current_row, 
                                                 column=0, columnspan=num_cols, sticky='ew', pady=8)
        current_row += 1
        
        ttk.Label(settings_inner_frame, 
                  text="Timing (seconds)", style="TLabelframe.Label").grid(row=current_row, 
                                                                           column=0, columnspan=num_cols, sticky="w", pady=(0,5))
        current_row += 1

        # All calls to _create_spinbox_setting NOW include setting_key_name_str!
        self._create_spinbox_setting(settings_inner_frame, current_row, 0,
                                    "Webdriver Wait Timeout:", self.settings_vars["webdriver_wait_timeout"], 5, 120,
                                    setting_key_name_str="webdriver_wait_timeout")
        self._create_spinbox_setting(settings_inner_frame, current_row, 2, "Proxy Connect Timeout:", self.settings_vars["proxy_timeout"], 1, 60,
                                    setting_key_name_str="proxy_timeout")
        current_row += 1

        self._create_spinbox_setting(settings_inner_frame, current_row, 0, "Min Action Delay:",
                                    self.settings_vars["random_delay_min"], 0.1, 60.0, is_float=True,
                                    setting_key_name_str="random_delay_min")
        self._create_spinbox_setting(settings_inner_frame, current_row, 2, "Max Action Delay:", self.settings_vars["random_delay_max"], 0.2, 120.0, is_float=True,
                                    setting_key_name_str="random_delay_max")
        current_row += 1

        self._create_spinbox_setting(settings_inner_frame, current_row, 0, "Min Acc Creation Delay:",
                                    self.settings_vars["account_creation_delay_min"], 1.0, 300.0, is_float=True,
                                    setting_key_name_str="account_creation_delay_min")
        self._create_spinbox_setting(settings_inner_frame, current_row, 2, "Max Acc Creation Delay:", self.settings_vars["account_creation_delay_max"], 2.0, 600.0, is_float=True,
                                    setting_key_name_str="account_creation_delay_max")
        current_row += 1

        self._create_spinbox_setting(settings_inner_frame, current_row, 0, "Report Interval:", self.settings_vars["report_interval_seconds"], 60, 86400,
                                    setting_key_name_str="report_interval_seconds")
        current_row += 1
        # --- New Debugging Pause Setting ---
        self._create_spinbox_setting(settings_inner_frame, current_row, 0,
                            "Pause on Fail (sec, <0 indefinite):", self.settings_vars["debug_pause_duration_on_fail"], -1, 3600, # Allows indefinite up to 1hr
                            setting_key_name_str="debug_pause_duration_on_fail")
        current_row += 1
        
        # --- Separator and Limits & Workers Section ---
        ttk.Separator(settings_inner_frame, orient=tk.HORIZONTAL).grid(row=current_row, column=0, columnspan=num_cols, sticky='ew', pady=8)
        current_row += 1
        ttk.Label(settings_inner_frame, text="Limits & Workers", style="TLabelframe.Label").grid(row=current_row, column=0, columnspan=num_cols, sticky="w", pady=(0,5))
        current_row += 1
        
        self._create_spinbox_setting(settings_inner_frame, current_row, 0,
                                    "Max Login Attempts:", self.settings_vars["max_login_attempts"], 1, 10,
                                    setting_key_name_str="max_login_attempts")
        self._create_spinbox_setting(settings_inner_frame, current_row, 2, "Max Reports / Day / Acc:", 
                                    self.settings_vars["max_reports_per_day"], 1, 1000,
                                    setting_key_name_str="max_reports_per_day")
        current_row += 1

        self._create_spinbox_setting(settings_inner_frame, current_row, 0,
                                    "Proxy Test Threads:", self.settings_vars["proxy_test_threads"], 1, 100,
                                    setting_key_name_str="proxy_test_threads")
        self._create_spinbox_setting(settings_inner_frame, current_row, 2, "Mass Report Workers:", 
                                    self.settings_vars["max_mass_report_workers"], 1, 50,
                                    setting_key_name_str="max_mass_report_workers")
        current_row += 1

        # --- Separator and Paths Section ---
        ttk.Separator(settings_inner_frame, orient=tk.HORIZONTAL).grid(row=current_row, column=0, columnspan=num_cols, sticky='ew', pady=8)
        current_row += 1
        ttk.Label(settings_inner_frame, text="Paths", style="TLabelframe.Label").grid(row=current_row, column=0, columnspan=num_cols, sticky="w", pady=(0,5))
        current_row += 1
        
        # GeoIP DB Path
        ttk.Label(settings_inner_frame, text="GeoIP DB:").grid(row=current_row, column=0, sticky="w", padx=5, pady=3)
        ttk.Entry(settings_inner_frame, textvariable=self.settings_vars["geoip_db_path"], width=45).grid(row=current_row, column=1, columnspan=2, sticky="ew", padx=5, pady=3)
        ttk.Button(settings_inner_frame, text="Browse...", command=lambda v=self.settings_vars["geoip_db_path"], t="GeoLite2 DB", ft=[("MMDB files", "*.mmdb")]: self.browse_file(v, t, ft)).grid(row=current_row, column=3, sticky="e", padx=5, pady=3)
        current_row += 1

        # ChromeDriver Path (Optional)
        ttk.Label(settings_inner_frame, text="ChromeDriver (Opt):").grid(row=current_row, column=0, sticky="w", padx=5, pady=3)
        ttk.Entry(settings_inner_frame, textvariable=self.settings_vars["chrome_driver_path"], width=45).grid(row=current_row, column=1, columnspan=2, sticky="ew", padx=5, pady=3)
        ttk.Button(settings_inner_frame, text="Browse...", command=lambda v=self.settings_vars["chrome_driver_path"], t="ChromeDriver", ft=[("Executables", "*.exe"), ("All", "*.*")]: self.browse_file(v, t, ft)).grid(row=current_row, column=3, sticky="e", padx=5, pady=3)
        current_row += 1

        # Chrome Binary Path (Optional)
        ttk.Label(settings_inner_frame, text="Chrome Binary (Opt):").grid(row=current_row, column=0, sticky="w", padx=5, pady=3)
        ttk.Entry(settings_inner_frame, textvariable=self.settings_vars["chrome_binary_path"], width=45).grid(row=current_row, column=1, columnspan=2, sticky="ew", padx=5, pady=3)
        ttk.Button(settings_inner_frame, text="Browse...", command=lambda v=self.settings_vars["chrome_binary_path"], t="Chrome", ft=[("Executables", "*.exe"), ("Apps", "*.app"), ("All", "*.*")]: self.browse_file(v, t, ft)).grid(row=current_row, column=3, sticky="e", padx=5, pady=3)
        current_row += 1

        # Save Settings Button
        self.save_settings_btn = ttk.Button(settings_inner_frame, text="💾 Save All Settings", command=self.save_gui_settings, style="TButton")
        self.save_settings_btn.grid(row=current_row, column=0, columnspan=num_cols, pady=15)
        current_row += 1 # Ensure row counter correctly increments after block
        
        paned_window.add(settings_scroll_frame) # Add the top pane to the paned window
        
        # Bottom pane for application log
        log_outer_frame = ttk.Frame(paned_window, padding=(5,0))
        log_frame = ttk.LabelFrame(log_outer_frame, text=" Application Log ", style="TLabelframe")
        log_frame.pack(fill=tk.BOTH, expand=True)
        
        self.log_text = scrolledtext.ScrolledText(log_frame, bg=self.LOG_TEXT_BG, fg=self.FG_COLOR, insertbackground=self.FG_COLOR, wrap=tk.WORD, font=("Consolas", 9), relief=tk.FLAT, highlightthickness=0, borderwidth=1, state=tk.DISABLED)
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Configure log message tags (colors for different log levels)
        self.log_text.tag_config("log_debug", foreground=self.LOG_COLOR_DEBUG)
        self.log_text.tag_config("log_info", foreground=self.LOG_COLOR_INFO)
        self.log_text.tag_config("log_warning", foreground=self.LOG_COLOR_WARNING)
        self.log_text.tag_config("log_error", foreground=self.LOG_COLOR_ERROR)
        self.log_text.tag_config("log_critical", foreground=self.LOG_COLOR_CRITICAL, font=("Consolas", 9, "bold"))
        
        paned_window.add(log_outer_frame) # Add the bottom pane to the paned window
        
        # Dynamically set initial sash position (often necessary for paned windows to display correctly initially)
        self.root.update_idletasks() # Ensures widgets are rendered and have dimensions before manipulating
        pane_height = paned_window.winfo_height()
        if pane_height > 0: # Only set if a valid height is determined
            paned_window.sashpos(0, int(pane_height * 0.55)) # Set the proportion of settings vs. log view

    def _create_spinbox_setting(self, parent, grid_row, grid_col_start, label_text, tk_var, min_val, max_val, is_float=False, setting_key_name_str: str = None):
        """ 
        Helper to create a Label + Spinbox pair for numeric settings. 
        Crucially, requires 'setting_key_name_str' to be explicitly passed 
        for robust mapping to the manager's settings dictionary key.
         """
        ttk.Label(parent, text=label_text).grid(row=grid_row, column=grid_col_start, sticky="w", padx=(5, 2), pady=3)
        increment = 0.1 if is_float else 1
        format_str = '%.1f' if is_float else '%0.f'

        # Validate that the actual setting key name is provided.
        # This prevents the problematic string derivation entirely for binding purposes.
        if setting_key_name_str is None:
            # If this error occurs, it means the *calling code* needs to be updated.
            logger.critical(
                f"Programming Error: 'setting_key_name_str' is missing when calling _create_spinbox_setting "
                f"for label: '{label_text}'. This GUI element will not function correctly. "
                f"Please update the call in setup_settings_log_tab."
            )
            # Fallback to derivation (which causes the problem), but logging critical error
            actual_setting_key = label_text.lower().replace(" ", "_").replace(":", "").replace("/", "_").replace("__","_")
        else:
            actual_setting_key = setting_key_name_str

        spin = ttk.Spinbox(
            parent, from_=min_val, to=max_val, increment=increment,
            textvariable=tk_var, width=8, style="TSpinbox", format=format_str,
            command=lambda k=actual_setting_key: self.update_manager_numeric_setting(k)
        )
        spin.grid(row=grid_row, column=grid_col_start + 1, sticky="w", padx=(0, 15), pady=3)
    
    # --- Supporting & Event Handling Methods ---
    def update_status(self, message, level="info"):
        if not self.root.winfo_exists():
            return
        try:
            self.status_var.set(message)
            style = {"error": "Error.TLabel", "success": "Success.TLabel"}.get(
                level, "Status.TLabel")
            self.status_bar.configure(style=style)
        except Exception as e:
            logger.warning(f"Status bar update error: {e}")

    def update_account_listbox(self):
        """
        Updates the account listbox with current accounts from the manager,
        preserving the selection if possible.
        """
        # Check if the root window still exists before proceeding
        if not self.root.winfo_exists():
            return

        # Store current selection index and text value before clearing
        selected_indices = self.account_listbox.curselection()
        # Get the text value to find the item again, rather than relying on index
        cur_val_text = self.account_listbox.get(
            selected_indices[0]) if selected_indices else None

        # Clear the listbox
        self.account_listbox.delete(0, tk.END)
        # Will store the index of the previously selected item, if found
        new_selection_idx = None

        # Repopulate the listbox (thread-safe access to accounts)
        with self.manager.account_lock:
            # Sort accounts alphabetically by username for consistent display
            sorted_accounts = sorted(
                self.manager.accounts, key=lambda x: x.get(
                    'username', '').lower()
            )
            # Iterate through sorted accounts and insert into listbox
            for idx, acc in enumerate(sorted_accounts):
                # Format the display string: Username - Status (Reports)
                disp = f"{acc.get('username', '?')} - {acc.get('status', '?').capitalize()} (R: {acc.get('reports_made', 0)})"
                self.account_listbox.insert(tk.END, disp)
                # Check if this item's text matches the previously selected one
                if cur_val_text and disp == cur_val_text:
                    new_selection_idx = idx  # Store the new index

        # Restore selection if the previously selected item was found
        if new_selection_idx is not None:  # <-- Colon added here
            try:  # <-- Block indented under 'if'
                self.account_listbox.selection_set(new_selection_idx)
                # Highlight the active item
                self.account_listbox.activate(new_selection_idx)
                # Ensure the selected item is visible
                self.account_listbox.see(new_selection_idx)
            # Catch potential errors (e.g., TclError if widget destroyed)
            except Exception as e:
                logger.warning(
                    f"Could not restore listbox selection for index {new_selection_idx}: {e}")
                pass  # Ignore error if index somehow becomes invalid during the update

        # Update the state of the "Login Selected Account" button based on current selection
        self.update_login_button_state()

    def on_account_select(self, event=None):
        self.update_login_button_state()

    def update_login_button_state(self):
        if not self.root.winfo_exists() or not hasattr(self, 'login_btn'):
            return
        try: self.login_btn.config(state=tk.NORMAL if self.account_listbox.curselection() else tk.DISABLED)
        except:
            pass # Ignore TclError

    def update_proxy_treeview(self):
        """Updates the proxy Treeview display with current proxy data."""
        # Check if GUI elements are still valid
        if not self.root.winfo_exists() or not hasattr(self, 'proxy_tree'):
            return

        # Store the currently selected item ID(s) to restore selection later
        # selection() returns a tuple, we usually only care about the first one
        selected_items = self.proxy_tree.selection()
        selected_id = selected_items[0] if selected_items else None

        # Clear existing items in the treeview
        for item in self.proxy_tree.get_children():
            try:
                self.proxy_tree.delete(item)
            except Exception as del_err: # Catch potential TclError or other issues
                logger.warning(f"Error deleting treeview item {item}: {del_err}")
                pass # Continue trying to clear other items

        # Access proxy data safely using the manager's lock
        with self.manager.proxies_lock:
            # Sort proxies using the manager's defined sort key
            sorted_proxies = sorted(
                self.manager.proxies, key=self.manager._proxy_sort_key
            )
            # Populate the treeview with sorted data
            for proxy in sorted_proxies:
                addr = proxy.get('address', '')
                # Display 'Direct' for empty address string
                disp_addr = addr if addr else 'Direct Connection'
                status = proxy.get('status', '?').capitalize()
                # Format latency nicely, show N/A otherwise
                latency = f"{proxy.get('latency'):.3f}" if isinstance(proxy.get('latency'), float) else "N/A"
                country = proxy.get('country') or 'N/A'
                # Format last checked timestamp, show 'Never' if unavailable
                last_checked_ts = proxy.get('last_checked', 0)
                last_chk_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(last_checked_ts)) if last_checked_ts else "Never"

                # Use unique item ID (IID) - proxy address or "DIRECT"
                item_id = addr if addr else "DIRECT"

                try:
                    # Insert the item into the treeview
                    self.proxy_tree.insert("", tk.END, iid=item_id, values=(disp_addr, status, latency, country, last_chk_str))
                except tk.TclError as insert_err:
                    # Handle potential error if trying to insert duplicate IID (shouldn't happen with proper clearing, but safety)
                    logger.warning(f"Error inserting proxy '{item_id}' into treeview: {insert_err}")
                    pass

        # Restore selection if an item was previously selected and still exists
        if selected_id and self.proxy_tree.exists(selected_id):
            try:
                # Set selection, focus, and ensure the item is visible
                self.proxy_tree.selection_set(selected_id)
                self.proxy_tree.focus(selected_id)
                self.proxy_tree.see(selected_id)
            except Exception as sel_err: # Catch potential TclError if selection fails
                logger.warning(f"Error restoring treeview selection for '{selected_id}': {sel_err}")
                pass # Ignore error if restoring selection fails
            
    def update_proxy_gui_final(self):
        """
        Finalizes GUI updates after proxy verification is complete.
        Hides progress bar, updates status, and enables actions based on results.
        """
        # Check if the root window still exists
        if not self.root.winfo_exists():
            return  # Exit if window is gone

        # Always update the treeview with the final results
        self.update_proxy_treeview()

        # Hide the progress bar if it exists and is currently shown
        if hasattr(self, 'proxy_progress') and self.proxy_progress.winfo_ismapped():
            try:
                self.proxy_progress.grid_remove()
            except tk.TclError:
                logger.warning(
                    "Error removing proxy progress bar (already gone?).")

        # Re-enable the refresh button
        try:
            self.refresh_proxies_btn.config(state=tk.NORMAL)
        except tk.TclError:
            logger.warning(
                "Error re-enabling refresh proxy button (already gone?).")

        # Determine the final status message based on verification results
        has_verified = False
        verified_count = 0
        with self.manager.proxies_lock:
            # Check if any proxy is verified and count them
            verified_list = [p for p in self.manager.proxies if p.get(
                'status') == 'verified']
            has_verified = bool(verified_list)  # True if the list is not empty
            verified_count = len(verified_list)

        # Set status message and level based on whether verified proxies exist
        if has_verified:
            msg = f"Proxy check complete. {verified_count} verified connection(s) found."
            level = "success"
        else:
            msg = "Proxy check complete. No verified connections found."
            level = "error"

        # Update the status bar
        self.update_status(msg, level)

        # Enable/disable general action buttons based on proxy availability
        # Actions should only be enabled if at least one connection works
        self.enable_actions(has_verified)

    def enable_actions(self, enabled=True):
        """
        Enables or disables common action buttons in the GUI.

        Also handles disabling certain buttons specifically when a mass report is active.

        Args:
            enabled (bool): True to enable buttons, False to disable. Defaults to True.
        """
        # Check if the root window exists before modifying widgets
        if not self.root.winfo_exists():
            return

        # Determine the target state based on the 'enabled' flag
        target_state = tk.NORMAL if enabled else tk.DISABLED

        # Enable/disable general action buttons stored in _action_buttons list
        for btn in self._action_buttons:
            # Check if the button exists, is a ttk.Button, and the widget window still exists
            if hasattr(btn, 'winfo_exists') and btn.winfo_exists() and isinstance(btn, ttk.Button):
                try:
                    btn.config(state=target_state)
                except Exception as e: # Catch potential TclError or other issues
                    logger.debug(f"Error configuring button state in enable_actions: {e}")
                    pass # Ignore if button cannot be configured

        # Special handling for the "Login Selected" button state
        if hasattr(self, 'login_btn') and self.login_btn.winfo_exists():
            try:
                # Enable only if general 'enabled' is True AND an account is selected in the listbox
                login_btn_state = tk.NORMAL if enabled and self.account_listbox.curselection() else tk.DISABLED
                self.login_btn.config(state=login_btn_state)
            except Exception as e:
                logger.debug(f"Error configuring login_btn state in enable_actions: {e}")
                pass

        # --- Override: Disable specific actions if a mass report is currently running ---
        if hasattr(self, '_mass_report_active') and self._mass_report_active.is_set():
            # List of button attribute names to disable during mass report
            button_names_to_disable = [
                "single_report_btn",
                "mass_report_btn",
                "extract_data_btn",
                "create_account_btn",
                "manual_login_btn",
                "login_btn" # Also disable selected login during mass report
            ]
            # Get the actual button widgets using getattr
            buttons_to_disable = [getattr(self, name, None) for name in button_names_to_disable]

            for btn in buttons_to_disable:
                # Check if the button exists and is valid before disabling
                if btn and hasattr(btn, 'winfo_exists') and btn.winfo_exists() and isinstance(btn, ttk.Button):
                    try:
                        btn.config(state=tk.DISABLED)
                    except Exception as e:
                        logger.debug(f"Error disabling button during mass report override: {e}")
                        pass
                    
    def check_proxy_readiness(self):
        """
        Checks if the proxy loading is complete and if any verified proxies are available.
        Updates the GUI status and enables actions accordingly. Schedules itself to run again
        if proxy loading is still in progress.
        """
        # Exit if the root window no longer exists
        if not self.root.winfo_exists():
            return

        is_ready = False # Default state

        # Check if the signal for the first available proxy has been set
        if self.manager.first_proxy_available.is_set():
            # If signaled, explicitly check if any proxies are actually 'verified'
            with self.manager.proxies_lock:
                is_ready = any(p.get('status') == 'verified' for p in self.manager.proxies)

        # --- Update GUI based on readiness ---
        if is_ready:
            # Proxies are loaded and at least one is verified
            logger.info("Proxy readiness check: Verified proxies available. Enabling actions.")
            self.enable_actions(True) # Enable general actions
            self.update_status("Ready.", "success") # Update status bar
            # No need to schedule again once ready
        elif self.manager.proxy_load_thread_active.is_set():
            # Proxies are still being loaded/verified in the background
            logger.debug("Proxy readiness check: Verification still in progress...")
            self.update_status("Verifying proxies...", "info")
            # Schedule this check to run again after a delay (e.g., 3 seconds)
            self.root.after(3000, self.check_proxy_readiness)
        else:
            # Proxy loading finished, but no verified proxies were found
            logger.warning("Proxy readiness check: Loading complete, but NO verified proxies found.")
            self.enable_actions(False) # Keep actions disabled
            self.update_status("No working connections found. Refresh proxy list.", "error")
            
    def update_log_display(self):
        """
        Periodically checks the log queue and updates the ScrolledText widget
        in the Settings & Log tab with new messages. Handles message tagging
        for colorization. Schedules itself to run repeatedly.
        """
        # Exit if the root window no longer exists
        if not self.root.winfo_exists():
            return

        # --- Process Log Queue ---
        # Define limits for processing per update cycle to keep GUI responsive
        max_lines_per_cycle = 100
        processed_count = 0

        try:
            # Process messages from the queue up to the limit
            while not self.log_queue.empty() and processed_count < max_lines_per_cycle:
                try:
                    # Get log level and message from the queue (non-blocking)
                    level, msg = self.log_queue.get_nowait()

                    # Determine the appropriate tag based on log level for coloring
                    tag = GUI_LOG_TAGS.get(level, "log_info") # Default to 'info' tag

                    # Update the ScrolledText widget
                    self.log_text.config(state=tk.NORMAL) # Enable writing
                    self.log_text.insert(tk.END, msg + "\n", tag) # Insert message with tag
                    self.log_text.config(state=tk.DISABLED) # Disable writing again
                    processed_count += 1

                except queue.Empty:
                    # Stop processing if the queue becomes empty
                    break
                except Exception as insert_err: # Catch errors during text insertion
                    print(f"Error inserting log message into GUI: {insert_err}") # Use print as logger might fail
                    # Continue trying to process other messages if possible

            # If any messages were processed, scroll to the end
            if processed_count > 0:
                self.log_text.see(tk.END)

        except Exception as e:
            # Catch errors in the main processing loop (e.g., accessing log_text widget)
            # Use print here as the logger itself might be involved or unavailable
            print(f"Error in GUI log display update loop: {e}")

        # --- Schedule Next Update ---
        # Schedule this method to run again after a short delay (e.g., 200ms)
        # This creates the polling loop for the log queue.
        self.root.after(200, self.update_log_display)

    def on_close(self):
        logger.info("User requested exit.")
        if messagebox.askokcancel("Quit", "Quit application?"):
            logger.info("Exit confirmed.")
            self._mass_report_active.set()  # Signal background threads (if they check)
            # --- NEW: Cleanup Persistent Profiles ---
            if self.manager and self.manager.settings.get("use_persistent_browser_profiles") and \
               self.manager.settings.get("cleanup_persistent_profiles"):
                profile_base_dir = LOG_DIR / "browser_profiles"
                if profile_base_dir.exists():
                    logger.info(
                        f"Cleaning up persistent browser profiles in '{profile_base_dir.resolve()}'...")
                    try:
                        shutil.rmtree(profile_base_dir)
                        logger.info(
                            "Successfully removed persistent browser profiles directory.")
                    except Exception as clean_e:
                        logger.error(
                            f"Failed to cleanup persistent browser profiles: {clean_e}", exc_info=True)
            # --- End NEW cleanup ---
            if self.manager:
                 if self.manager.driver:
                     logger.info("Closing WebDriver...")
                     self.manager.close_driver()
                 self.save_gui_settings(show_success=False) # Save settings on exit without popup
            self.root.destroy()
            logger.info("App shutdown.")
        else:
            logger.info("Exit cancelled.")

    def setup_error_handling(self):
        def handle_err(exc_type, exc_val, exc_tb):
            err_lines = traceback.format_exception(exc_type, exc_val, exc_tb)
            error_message = f"Unhandled GUI Error:\n{''.join(err_lines)}"
            logger.critical(error_message)
            messagebox.showerror("Unhandled GUI Error", "Unexpected error. Check log.")
        self.root.report_callback_exception = handle_err
        logger.debug("Global Tkinter error handler set.")

    # --- Action Methods ---
    def create_account(self):
        """
        Handles the 'Create New Account' button click.
        Disables actions, starts a background thread to create an account using the manager,
        and updates the GUI upon completion.
        """
        logger.info("GUI: Create Account button clicked.")
        self.update_status("Creating new account...", "info")
        self.enable_actions(False) # Disable buttons while task runs

        # --- Define the background task ---
        def task():
            info = None # To store result from manager
            try:
                # Call the manager's account creation method
                info = self.manager.create_temporary_account() # Semicolon removed

                # --- Update GUI based on result (using root.after for thread safety) ---
                if info:
                    # Account created (status might vary)
                    username = info.get('username', '?')
                    status = info.get('status', '?')
                    msg = f"Created: {username} (Status: {status.capitalize()})"
                    # Set status level based on whether account is immediately active
                    lvl = "success" if status == 'active' else "warning"
                    self.root.after(0, self.update_status, msg, lvl)
                    # Refresh the account listbox
                    self.root.after(0, self.update_account_listbox)
                else:
                    # Creation failed entirely
                    self.root.after(0, self.update_status, "Account creation failed. Check logs.", "error")

            except Exception as e:
                # Handle exceptions within the background thread
                logger.error(f"Account creation thread error: {e}", exc_info=True)
                self.root.after(0, self.update_status, "Creation error occurred. See log.", "error")

            finally:
                # --- Re-enable actions in the GUI (always runs) ---
                # Use lambda to ensure enable_actions(True) is called in the GUI thread
                self.root.after(100, lambda: self.enable_actions(True)) # Slight delay after status update

        # --- Start the background thread ---
        threading.Thread(target=task, daemon=True, name="AccCreateThread").start()

    def manual_login(self):
        """
        Handles the 'Login with These Credentials' button click for manual login.
        Validates input, starts a background thread to attempt login using the manager,
        and updates the GUI upon completion.
        """
        # Get credentials from GUI entries
        username = self.manual_user_entry.get().strip()
        password = self.manual_pass_entry.get() # No strip needed for password

        # Validate inputs
        if not username or not password:
            messagebox.showerror("Input Error", "Please enter both username and password.")
            return # Exit if validation fails

        logger.info(f"GUI: Manual Login button clicked for user: {username}")
        self.update_status(f"Attempting manual login as {username}...", "info")
        self.enable_actions(False) # Disable buttons during login attempt

        # Create a temporary account dictionary for the manager's login method
        # Status 'manual' is just for internal tracking if needed, manager might change it.
        manual_account = {
            "username": username,
            "password": password,
            "status": "manual" # Initial status for this attempt
        }

        # --- Define the background task for login ---
        def task():
            success = False # Flag to track login outcome
            try:
                # Call the manager's login method with the manual credentials
                success = self.manager.login(manual_account) # Manager handles WebDriver setup etc.

                # --- Update GUI based on login result (using root.after) ---
                outcome_text = 'successful' if success else 'failed'
                msg = f"Manual login {outcome_text} for {username}."
                lvl = "success" if success else "error"
                self.root.after(0, self.update_status, msg, lvl) # Update status bar

                if success:
                    logger.info(f"Manual login successful for {username}.")
                    # Optionally clear fields on success, or leave them
                    # self.manual_user_entry.delete(0, tk.END)
                    # self.manual_pass_entry.delete(0, tk.END)
                else:
                    logger.warning(f"Manual login failed for {username}.")
                    # Clear password field on failure for security/convenience
                    # Run this clear operation via root.after to ensure it's on the GUI thread
                    self.root.after(0, lambda: self.manual_pass_entry.delete(0, tk.END))

            except Exception as e:
                # Handle exceptions within the background thread
                logger.error(f"Manual login thread error for {username}: {e}", exc_info=True)
                self.root.after(0, self.update_status, f"Manual login error for {username}. See log.", "error")
                # Clear password field on exception as well
                self.root.after(0, lambda: self.manual_pass_entry.delete(0, tk.END))

            finally:
                # --- Re-enable actions in the GUI (always runs) ---
                # Use lambda to call enable_actions with True in the GUI thread
                self.root.after(100, lambda: self.enable_actions(True)) # Slight delay

        # --- Start the background thread ---
        # Use a descriptive name for the thread
        threading.Thread(target=task, daemon=True, name=f"ManualLogin-{username[:10]}").start()
        
    def login_selected_account(self):
        """
        Handles the 'Login Selected Account' button click.
        Gets the selected account from the listbox, starts a background thread
        to attempt login using the manager, and updates the GUI.
        """
        # Get the indices of the selected item(s) in the listbox
        indices = self.account_listbox.curselection()

        # Check if an item is actually selected
        if not indices:
            messagebox.showwarning("No Selection", "Please select an account from the list first.")
            return # Exit if nothing is selected

        try:
            # Get the display text of the selected item (first selected index)
            listbox_text = self.account_listbox.get(indices[0])
            # Use regex to extract the username (assumes format "username - status...")
            match = re.match(r"^([\w.-]+)", listbox_text) # Allow dots and hyphens in username
            if not match:
                logger.error(f"Could not parse username from listbox item: '{listbox_text}'")
                self.update_status("Error parsing selected account.", "error")
                return # Exit if parsing fails

            username_to_login = match.group(1)

            # Find the corresponding account dictionary in the manager's list (thread-safe)
            account = None
            with self.manager.account_lock:
                # Use next() with a generator expression for efficiency
                account = next((acc for acc in self.manager.accounts if acc.get('username') == username_to_login), None)

            # Check if the account was found in the manager's list
            if not account:
                logger.error(f"Selected username '{username_to_login}' not found in manager's internal account list.")
                self.update_status("Error finding account data.", "error")
                return # Exit if account data missing

            # Log the action and update GUI status
            logger.info(f"GUI: Login button clicked for selected account: {account['username']}")
            self.update_status(f"Attempting login as {account['username']}...", "info")
            self.enable_actions(False) # Disable buttons during login

            # --- Define the background task for login ---
            def task():
                success = False # Flag for login outcome
                try:
                    # Call the manager's login method with the found account dictionary
                    success = self.manager.login(account) # Manager handles WebDriver, status updates etc.

                    # --- Update GUI based on result (using root.after) ---
                    outcome_text = 'successful' if success else 'failed'
                    msg = f"Login {outcome_text} for {account['username']}."
                    lvl = "success" if success else "error"
                    self.root.after(0, self.update_status, msg, lvl) # Update status bar
                    # Update the account listbox to reflect potential status changes from login attempt
                    self.root.after(0, self.update_account_listbox)

                except Exception as e:
                    # Handle exceptions within the background thread
                    logger.error(f"Login thread error for {account['username']}: {e}", exc_info=True)
                    self.root.after(0, self.update_status, f"Login error for {account['username']}. See log.", "error")
                    # Update listbox even on error, as status might have changed before exception
                    self.root.after(0, self.update_account_listbox)

                finally:
                    # --- Re-enable actions in the GUI (always runs) ---
                    self.root.after(100, lambda: self.enable_actions(True)) # Slight delay

            # --- Start the background thread ---
            threading.Thread(target=task, daemon=True, name=f"LoginThread-{account['username'][:10]}").start()

        except Exception as e:
            # Catch errors during the preparation phase (getting selection, finding account)
            logger.error(f"Error preparing for selected account login: {e}", exc_info=True)
            self.update_status("Error initiating login.", "error")
            self.enable_actions(True) # Re-enable actions if setup fails
            
    def refresh_proxies(self):
        """
        Handles the 'Refresh Proxy List' button click.
        Disables actions, shows the progress bar, and starts the background
        proxy loading/verification process in the manager.
        """
        logger.info("GUI: Refresh Proxies button clicked.")
        self.update_status("Refreshing proxy list and verifying connections...", "info")

        # Disable the refresh button itself immediately to prevent double clicks
        try:
            self.refresh_proxies_btn.config(state=tk.DISABLED)
        except tk.TclError:
             logger.warning("Error disabling refresh proxy button (already gone?).")

        # Prepare and show the progress bar
        if hasattr(self, 'proxy_progress'):
            try:
                self.proxy_progress.config(value=0) # Reset progress
                # Ensure the progress bar is visible
                if not self.proxy_progress.winfo_ismapped():
                    self.proxy_progress.grid(row=0, column=0, padx=5, pady=5, sticky="ew")
            except tk.TclError:
                logger.warning("Error configuring or showing proxy progress bar.")

        # Disable other general action buttons while refreshing
        self.enable_actions(False)

        # Prepare GUI elements to pass to the background task for updates
        gui_elements = {
            'root': self.root,
            'gui_instance': self,
            'status_var': self.status_var,
            'progress_bar': getattr(self, 'proxy_progress', None) # Pass progress bar ref safely
        }

        # Start the background proxy loading process in the manager
        self.manager.start_background_proxy_load(gui_elements=gui_elements)
        
    def single_report(self):
        """
        Handles the 'Report with Logged-in Account' button click.
        Validates input, ensures user is logged in, starts a background thread
        to perform the report using the manager's current session, and updates the GUI.
        """
        # Get target and reason from GUI elements
        target = self.target_entry.get().strip()
        reason = self.report_reason_var.get()

        # --- Input Validation ---
        if not target:
            messagebox.showerror("Input Error", "Please enter a target username to report.")
            return # Exit if target is empty
        if not self.manager.driver or not self.manager.current_account:
            messagebox.showerror("Login Required", "You must be logged in with an account to send a report.")
            return # Exit if not logged in

        # Get current logged-in user for logging
        current_user = self.manager.current_account['username']
        logger.info(f"GUI: Single Report requested for '{target}' as '{reason}' by user '{current_user}'.")
        self.update_status(f"Attempting to report '{target}' as '{reason}'...", "info")
        self.enable_actions(False) # Disable buttons during report attempt

        # --- Define the background task for reporting ---
        def task():
            report_outcome = None # Store result from manager.report_account
            try:
                # Call the manager's report method using the main driver/account
                report_outcome = self.manager.report_account(target, reason)

                # --- Update GUI based on the report outcome (using root.after) ---
                if report_outcome is True:
                    msg = f"Report successfully submitted for '{target}'."
                    lvl = "success"
                    # Update account listbox to potentially show incremented report count
                    self.root.after(0, self.update_account_listbox)
                elif report_outcome == "target_not_found":
                    msg = f"Report Failed: Target username '{target}' not found or unavailable."
                    lvl = "error"
                else: # Covers False return or unexpected values
                    msg = f"Report failed or was skipped for '{target}'. Check logs for details."
                    lvl = "error"

                # Update status bar with the result message
                self.root.after(0, self.update_status, msg, lvl)

            except Exception as e:
                # Handle exceptions within the background thread
                logger.error(f"Single report thread error for target '{target}': {e}", exc_info=True)
                self.root.after(0, self.update_status, f"Error reporting '{target}'. See log.", "error")
                # Optionally update listbox even on error if needed
                # self.root.after(0, self.update_account_listbox)

            finally:
                # --- Re-enable actions in the GUI (always runs) ---
                self.root.after(100, lambda: self.enable_actions(True)) # Slight delay

        # --- Start the background thread ---
        # Use a descriptive name for the thread
        threading.Thread(target=task, daemon=True, name=f"SingleReport-{target[:10]}").start()

    def mass_report(self):
        """
        Handles the 'Mass Report' button click.
        Gathers target, reason, account selection, and worker settings.
        Confirms with the user, then starts a background thread to manage
        concurrent reporting via the manager's logic. Updates GUI during/after.
        """
        # --- Get Inputs from GUI ---
        target = self.target_entry.get().strip()
        reason = self.report_reason_var.get()

        # Validate target username
        if not target:
            messagebox.showerror("Input Error", "Please enter a target username to report.")
            return

        # --- Get Mass Report Parameters ---
        try:
            # Get max accounts to use from Spinbox, ensure it's at least 1 and not more than available
            max_accounts_wanted = self.mass_report_accounts_var.get()
            num_accounts_to_use = min(max_accounts_wanted, len(self.manager.accounts))
            num_accounts_to_use = max(1, num_accounts_to_use) # Ensure at least 1
        except tk.TclError: # Handle potential error reading spinbox value
            logger.warning("Could not read max accounts spinbox, using total available.")
            num_accounts_to_use = len(self.manager.accounts) # Fallback

        try:
            # Get number of workers from the bound settings variable/spinbox
            num_workers = self.settings_vars["max_mass_report_workers"].get()
            num_workers = max(1, num_workers) # Ensure at least 1 worker
        except tk.TclError: # Fallback if reading fails
            logger.warning("Could not read workers spinbox, using manager default.")
            num_workers = self.manager.settings.get("max_mass_report_workers", 5) # Fallback from manager settings
            num_workers = max(1, num_workers)

        # --- Select Suitable Accounts ---
        accounts_to_use = []
        with self.manager.account_lock:
            # Define statuses considered suitable for reporting
            suitable_statuses = {'active', 'unknown', 'verification_needed'} # Add others if applicable
            # Filter accounts based on status
            all_suitable_accounts = [
                acc for acc in self.manager.accounts
                if acc.get('status', 'unknown').lower() in suitable_statuses
            ]
            # Randomly sample the required number of accounts from the suitable list
            if all_suitable_accounts:
                accounts_to_use = random.sample(
                    all_suitable_accounts,
                    min(num_accounts_to_use, len(all_suitable_accounts)) # Don't sample more than available
                )

        # Check if any suitable accounts were found
        if not accounts_to_use:
            messagebox.showwarning("No Suitable Accounts", "No accounts with suitable status (Active, Unknown, Verification Needed) found for mass reporting.")
            return

        # --- Confirmation Dialog ---
        num_selected = len(accounts_to_use)
        confirm_msg = (
            f"Are you sure you want to report '{target}' "
            f"using {num_selected} account(s) with up to {num_workers} concurrent workers?\n\n"
            f"Reason: {reason}"
        )
        if not messagebox.askyesno("Confirm Mass Report", confirm_msg):
            logger.info("User cancelled mass report operation.")
            return # Exit if user cancels

        # --- Start Mass Report Process ---
        logger.info(f"GUI: Starting Mass Report. Target: '{target}', Reason: '{reason}', Accounts: {num_selected}, Workers: {num_workers}")
        self.update_status(f"Starting mass report for '{target}' ({num_selected} accounts)...", "info")
        self._mass_report_active.set() # Set the flag indicating mass report is running
        self.enable_actions(False) # Disable buttons (enable_actions checks the flag too)

        # --- Define the background task manager ---
        def task():
            try:
                # Call the manager's logic function that handles the ThreadPoolExecutor
                self.manager._mass_report_concurrent_logic(
                    target, reason, accounts_to_use, num_workers
                )
                # Final status update will be handled by _mass_report_concurrent_logic itself via GUI calls
            except Exception as e:
                # Catch errors in the manager logic invocation itself
                logger.error(f"Mass report manager thread encountered an error: {e}", exc_info=True)
                # Update GUI status with error message
                self.root.after(0, self.update_status, "Mass report encountered an error. See log.", "error")
            finally:
                # --- Cleanup after task finishes (always runs) ---
                self._mass_report_active.clear() # Clear the flag
                # Re-enable actions and refresh listbox via root.after for thread safety
                self.root.after(200, lambda: self.enable_actions(True)) # Slight delay before re-enabling
                self.root.after(250, self.update_account_listbox) # Update list shortly after enabling

        # --- Start the background thread ---
        threading.Thread(target=task, daemon=True, name="MassReportManager").start()
        
    def extract_data(self):
        """
        Handles the 'Extract Profile Data' button click.
        Validates input, ensures user is logged in, starts a background thread
        to extract data using the manager, displays the results, and enables saving.
        """
        # Get target username from the entry widget
        target = self.data_target_entry.get().strip()

        # --- Input Validation ---
        if not target:
            messagebox.showerror("Input Error", "Please enter a target username to extract data for.")
            return # Exit if target is empty
        if not self.manager.driver or not self.manager.current_account:
            messagebox.showerror("Login Required", "You must be logged in with an account to extract profile data.")
            return # Exit if not logged in

        # --- Prepare for Extraction ---
        current_user = self.manager.current_account['username']
        logger.info(f"GUI: Extract Data requested for '{target}' by user '{current_user}'.")
        self.update_status(f"Extracting data for '{target}'...", "info")
        self.enable_actions(False) # Disable actions during extraction
        # Disable save button until data is available
        try:
            self.save_data_btn.config(state=tk.DISABLED)
        except tk.TclError: pass # Ignore if button doesn't exist

        # Clear previous results and show placeholder text
        try:
            self.data_results_text.config(state=tk.NORMAL)
            self.data_results_text.delete('1.0', tk.END)
            self.data_results_text.insert('1.0', f"Extracting data for {target}...\nPlease wait.")
            self.data_results_text.config(state=tk.DISABLED)
        except tk.TclError:
            logger.error("Error updating data results text widget.")
        # Reset last extracted data
        self._last_extracted_data = None

        # --- Define the background task for data extraction ---
        def task():
            data = None # Variable to hold the extracted data dictionary
            try:
                # Call the manager's data extraction method
                data = self.manager.extract_user_data(target)
                self._last_extracted_data = data # Store the result

                # --- Prepare display text ---
                # Start with header info
                display_text = (
                    f"--- Extraction for {target} ---\n"
                    f"Status: {data.get('extraction_status', '?')}\n"
                    f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(data.get('extraction_timestamp', 0)))}\n"
                    f"{'-'*50}\n"
                )
                # Exclude bulky network responses and timestamp from main JSON dump
                data_to_print = {k: v for k, v in data.items() if k not in ['network_responses', 'extraction_timestamp']}

                # Attempt to format the main data as pretty JSON
                try:
                    display_text += json.dumps(data_to_print, indent=2, ensure_ascii=False)
                except Exception as json_err:
                    # Fallback if JSON formatting fails
                    display_text += f"\nError formatting data as JSON: {json_err}\nRaw Data:\n{data_to_print}"

                # Add summary about network responses
                net_resp_count = len(data.get('network_responses', []))
                if net_resp_count > 0:
                    display_text += f"\n\n{'-'*50}\nNetwork Analysis: Found {net_resp_count} relevant API responses (details available in saved data or logs)."
                else:
                    display_text += f"\n\n{'-'*50}\nNetwork Analysis: No relevant API responses found/captured."

                # --- Nested function to update GUI text area (ensures GUI access from main thread) ---
                def update_gui_text_area(text_content):
                    try:
                        self.data_results_text.config(state=tk.NORMAL)
                        self.data_results_text.delete('1.0', tk.END)
                        self.data_results_text.insert('1.0', text_content)
                        self.data_results_text.config(state=tk.DISABLED)
                    except tk.TclError:
                        logger.error("Failed to update data results text area (widget destroyed?).")
                    except Exception as gui_update_err:
                         logger.error(f"Unexpected error updating data results text: {gui_update_err}")

                # Schedule the GUI update using root.after
                self.root.after(0, update_gui_text_area, display_text)

                # --- Update status bar and save button state ---
                status_level = "success" if "Completed" in data.get('extraction_status', '') else "warning"
                final_status_msg = f"Extraction complete for '{target}'. Status: {data.get('extraction_status','?')}"
                self.root.after(0, self.update_status, final_status_msg, status_level)
                # Enable save button only if data extraction seemed to produce data
                save_btn_state = tk.NORMAL if data and data.get("extraction_status") != "Login Required" else tk.DISABLED
                self.root.after(0, lambda state=save_btn_state: self.save_data_btn.config(state=state))

            except Exception as e:
                # Handle exceptions within the background thread
                logger.error(f"Data extraction thread error for '{target}': {e}", exc_info=True)
                self.root.after(0, self.update_status, f"Error extracting data for '{target}'. See log.", "error")
                # Ensure save button remains disabled on error
                self.root.after(0, lambda: self.save_data_btn.config(state=tk.DISABLED))

            finally:
                # --- Re-enable actions in the GUI (always runs) ---
                self.root.after(100, lambda: self.enable_actions(True)) # Slight delay

        # --- Start the background thread ---
        threading.Thread(target=task, daemon=True, name=f"ExtractData-{target[:10]}").start()
        
    def save_extracted_data(self):
        """
        Handles the 'Save Last Extracted Data' button click.
        Prompts the user for a save location and saves the data stored in
        self._last_extracted_data as a JSON file.
        """
        # Check if there is data to save
        if not self._last_extracted_data:
            messagebox.showwarning("No Data Available", "No data has been extracted yet to save.")
            return # Exit if no data

        # --- Prepare Filename and Prompt User ---
        # Get username from data for default filename, fallback if missing
        username = self._last_extracted_data.get("username", "unknown_user")
        # Create a default filename with username and timestamp
        default_filename = f"{username}_data_{time.strftime('%Y%m%d_%H%M%S')}.json"

        # Open the 'Save As' dialog
        filepath = filedialog.asksaveasfilename(
            title="Save Extracted Profile Data",
            initialfile=default_filename,
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )

        # --- Handle Dialog Result ---
        if not filepath:
            # User cancelled the dialog
            logger.debug("Save extracted data operation cancelled by user.")
            return # Exit if no filepath selected

        # --- Save Data to File ---
        try:
            # Write the data to the selected file path as JSON
            with open(filepath, 'w', encoding='utf-8') as f:
                # Use indent for pretty printing, ensure_ascii=False for non-ASCII chars
                json.dump(self._last_extracted_data, f, indent=2, ensure_ascii=False)

            # Log success and update status bar
            logger.info(f"Successfully saved extracted data for '{username}' to: {filepath}")
            # Show only the filename in the status bar for brevity
            self.update_status(f"Data saved to {Path(filepath).name}", "success")

        except Exception as e:
            # Handle errors during file writing or JSON dumping
            logger.error(f"Failed saving extracted data to '{filepath}': {e}", exc_info=True)
            messagebox.showerror("Save Error", f"Could not save data to file:\n\n{e}")
            # Update status bar to indicate failure
            self.update_status("Failed to save extracted data.", "error")
            
    # --- Settings Tab Actions ---
    def update_manager_bool_setting(self, setting_key):
        return lambda: self._update_setting(setting_key, self.settings_vars[setting_key].get())

    def update_manager_numeric_setting(self, setting_key):
         if setting_key in self.settings_vars:
             self._update_setting(setting_key, self.settings_vars[setting_key].get())
         else: logger.error(f"Unknown numeric setting key: {setting_key}")

    def _update_setting(self, key, value):
        """
        Updates a specific setting in the manager instance based on GUI interaction.

        Args:
            key (str): The key of the setting to update (must exist in self.manager.settings).
            value: The new value for the setting from the corresponding Tkinter variable.
        """
        # Check if the setting key is valid in the manager's settings dictionary
        if key in self.manager.settings:
            # Get the current value for comparison (mainly for logging type changes)
            current_manager_value = self.manager.settings[key]

            # Log if the type changes significantly (e.g., bool to str, but ignore int<->float)
            # This check prevents noisy logs when a float like 5.0 is treated as an int 5.
            if type(current_manager_value) != type(value) and not \
               (isinstance(current_manager_value, (int, float)) and isinstance(value, (int, float))):
                logger.debug(
                    f"Setting '{key}' type changing from "
                    f"{type(current_manager_value).__name__} to {type(value).__name__}"
                )

            # Update the setting in the manager instance
            self.manager.settings[key] = value
            # Log the update and notify the user via the status bar
            logger.info(f"Setting '{key}' updated via GUI to: {value}")
            self.update_status(f"Setting '{key}' updated.", "info")

        else:
            # Log an error if the GUI tries to update a setting that doesn't exist
            logger.error(
                f"Attempted to update non-existent setting key from GUI: '{key}'")

    def toggle_debug_mode(self):
        is_debug = self.settings_vars["debug_mode"].get()
        self.manager.settings["debug_mode"] = is_debug; new_level = logging.DEBUG if is_debug else logging.INFO; setup_global_logging(level=new_level, queue_ref=self.log_queue); logger.info(f"Log level set to {logging.getLevelName(new_level)}."); self.update_status(f"Log Level: {logging.getLevelName(new_level)}", "info")

    def browse_file(self, path_var, title, filetypes):
        initial_dir = "."; current_path = path_var.get()
        if current_path and Path(current_path).exists():
            initial_dir = Path(current_path).parent if Path(current_path).is_file() else current_path
        filepath = filedialog.askopenfilename(title=f"Select {title}", filetypes=filetypes, initialdir=initial_dir)
        if filepath:
            path_var.set(filepath); logger.debug(f"User selected path for {title}: {filepath}")

    def save_gui_settings(self, show_success=True):
        logger.info("Saving GUI settings...")
        for key, tk_var in self.settings_vars.items():
            if key in self.manager.settings:
                 try:
                     current_gui_value = tk_var.get()
                 except Exception as e: logger.error(f"Error reading GUI var '{key}': {e}"); continue
                 self.manager.settings[key] = current_gui_value
            else:
                logger.warning(f"GUI var '{key}' not in manager settings.")
        self.manager._validate_numeric_settings() # Validate after reading ALL values
        for key, tk_var in self.settings_vars.items():  # Update GUI vars back in case validation changed them
             if key in self.manager.settings:
                 try: tk_var.set(self.manager.settings[key]) 
                 except: 
                     pass
        self.manager.load_geoip_database()
        self.manager.save_persistent_settings()
        if show_success:
            messagebox.showinfo("Settings Saved", "Settings saved & validated.")
        self.update_status("All settings saved.", "success")


# === Main Execution Entry Point ===
def main():
    initial_log_level = logging.INFO
    setup_global_logging(level=initial_log_level, queue_ref=None)
    for name in ['WDM',
                 'selenium.webdriver.remote',
                 'selenium.webdriver.common',
                 'urllib3', 'hpack', 'PIL']:
        logging.getLogger(name).setLevel(logging.WARNING)
    logger.info("="*25 + " Application Starting " + "="*25);
    logger.info(f"Version: 2.5.1"); # Assuming version is hardcoded here or loaded elsewhere
    logger.info(f"Python: {sys.version.split()[0]}, Platform: {sys.platform}");
    logger.info(f"PID: {os.getpid()}, CWD: {Path.cwd()}")
    try:
        LOG_DIR.mkdir(exist_ok=True);
        SCREENSHOT_DIR.mkdir(exist_ok=True)
    except Exception as dir_err:
        logger.error(f"Cannot create dirs: {dir_err}")

    manager = None # Initialize for finally block
    try:
        manager = EnhancedInstagramManager()
        root = tk.Tk()
        root.withdraw()
        if sys.platform == "win32":
            try:
                # Try modern API (Win 8.1+)
                ctypes.windll.shcore.SetProcessDpiAwareness(2)
                logger.info("DPI awareness set (Per-Monitor v2).")
            except (AttributeError, OSError):
                # Fallback for older systems (Vista+)
                try:
                    ctypes.windll.user32.SetProcessDPIAware()
                    logger.info("DPI awareness set (System Aware).")
                except Exception as e_old:
                    logger.warning(f"SetProcessDPIAware (old method) failed: {e_old}")
            except Exception as e_modern:
                 # Catch other errors with modern API call
                 logger.warning(f"SetProcessDpiAwareness (modern method) failed: {e_modern}")

        app = EnhancedInstagramManagerGUI(root, manager)
        root.deiconify()
        root.mainloop()
        logger.info("GUI main loop exited.")
    except tk.TclError as e:
        logger.critical(f"Fatal Tkinter error: {e}", exc_info=True)
        print(f"\nFATAL TKINTER ERROR: {e}", file=sys.stderr)
        # Consider exiting differently if manager/driver needs cleanup
        sys.exit(1)
    except ImportError as e:
        logger.critical(f"Fatal Import Error: {e}",
                        exc_info=True)
        print(f"\nFATAL IMPORT ERROR: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        logger.critical(f"Critical application error: {e}",
                        exc_info=True)
        print(f"\nFATAL APP ERROR: {e}",
              file=sys.stderr)
        # Attempt to provide log path for user
        try:
            log_path = LOG_DIR.resolve() / LOG_FILENAME
            print(f"Check log: '{log_path}'.", file=sys.stderr)
        except NameError:
             print("Log path variables (LOG_DIR, LOG_FILENAME) not defined.", file=sys.stderr)

        # Attempt graceful WebDriver shutdown if possible
        if 'manager' in locals() and manager and hasattr(manager, 'driver') and manager.driver:
            print("Attempting to close WebDriver due to error...")
            try:
                manager.close_driver()
            except Exception as close_err:
                print(f"Error closing webdriver: {close_err}", file=sys.stderr)
        sys.exit(1) # Exit after logging/cleanup attempt
    finally:
        # This will run even if sys.exit() was called in except blocks
        print("\n" + "="*25 + " Application Exited " + "="*25)
if __name__ == "__main__":
    main()
