# --- START OF FILE v2.6_godfather_rebuilt.py ---
import re
import os
import sys
import time
import queue
import random
import string
import logging
import hashlib
import threading
import traceback
import requests
import json
import concurrent.futures
import base64
import urllib.parse
import csv
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from pathlib import Path
from urllib3.exceptions import MaxRetryError

# --- Dependency Checks ---
try:
    import colorama
    colorama.init(autoreset=True)  # Initialize colorama for terminal colors
except ImportError:
    print("Warning: colorama not found (pip install colorama). Terminal logs will lack color.")
    colorama = None

try:
    from selenium_stealth import stealth
except ImportError:
    print("ERROR: selenium-stealth not found. Please install it: pip install selenium-stealth")
    sys.exit(1)

try:
    from webdriver_manager.chrome import ChromeDriverManager
except ImportError:
    print("ERROR: webdriver-manager not found. Please install it: pip install webdriver-manager")
    sys.exit(1)

try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options as ChromeOptions
    from selenium.webdriver.chrome.service import Service as ChromeService
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.common.exceptions import (
        TimeoutException, NoSuchElementException, WebDriverException,
        SessionNotCreatedException, ElementNotInteractableException,
        ElementClickInterceptedException, StaleElementReferenceException
    )
except ImportError:
    print("ERROR: selenium not found. Please install it: pip install selenium")
    sys.exit(1)

try:
    from fake_useragent import UserAgent
except ImportError:
    print("ERROR: fake-useragent not found. Please install it: pip install fake-useragent")
    sys.exit(1)

# === Constants ===
ACCOUNT_CSV_FILENAME = "generated_accounts_enhanced.csv"
LOG_FILENAME = "instagram_manager_enhanced.log"
SCREENSHOT_DIR = Path("screenshots")
LOG_DIR = Path("logs")
GUI_LOG_TAGS = {
    logging.DEBUG: "log_debug",
    logging.INFO: "log_info",
    logging.WARNING: "log_warning",
    logging.ERROR: "log_error",
    logging.CRITICAL: "log_critical"
}

# Log Levels for Coloring
LOG_COLORS = {
    logging.DEBUG: 'DIM',    # Greyed out for Debug
    logging.INFO: 'GREEN',  # Green for Info
    logging.WARNING: 'YELLOW',  # Yellow for Warning
    logging.ERROR: 'RED',    # Red for Error
    logging.CRITICAL: 'RED',  # Bright Red for Critical
}

# Tkinter Text Widget Tags for Coloring
GUI_LOG_TAGS = {
    logging.DEBUG: "log_debug",
    logging.INFO: "log_info",
    logging.WARNING: "log_warning",
    logging.ERROR: "log_error",
    logging.CRITICAL: "log_critical",
}


# --- Helper: Enhanced Email Creator ---
class EnhancedEmailCreator:
    def __init__(self, logger):
        self.logger = logger
        self.session = requests.Session()
        self.api_user_agent = "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0"
        self.session.headers.update({'User-Agent': self.api_user_agent})

    def create_temporary_email(self):
        # Create temporary email using different services with fallback.
        self.logger.debug("Attempting to create temporary email...")
        email_methods = [
            self._create_1secmail_email,
            self._create_guerrillamail_email,
            self._create_tempmail_lol_manual,
            self._create_mailtm_email,
            self._create_maildrop_email,
            self._create_generic_fallback_email
        ]
        random.shuffle(email_methods)

        for method in email_methods:
            email = None
            method_name = method.__name__
            try:
                self.logger.debug(f"Trying email provider: {method_name}")
                email = method()
                if email:
                    self.logger.info(
                        f"Successfully created email using {method_name}: {email}")
                    return email
            except Exception as e:
                self.logger.warning(
                    f"Failed to create email with {method_name}: {e}")
                time.sleep(random.uniform(0.3, 0.8))
        self.logger.error(
            "Failed to create temporary email with any service. Using final fallback.")
        return self._create_generic_fallback_email() or f"fallback_{int(time.time())}@example.com"

    def _create_guerrillamail_email(self):
        try:
            headers = {'Origin': 'https://www.guerrillamail.com',
                       'Referer': 'https://www.guerrillamail.com/'}
            response = self.session.get(
                "https://www.guerrillamail.com/ajax.php?f=get_email_address", headers=headers, timeout=10)
            response.raise_for_status()
            data = response.json()
            if data and 'email_addr' in data:
                return data['email_addr']
            raise Exception(f"Invalid response: {data}")
        except Exception as e:
            raise Exception(f"Guerrilla Mail error: {e}")

    def _create_tempmail_lol_manual(self):
        try:
            username = ''.join(random.choices(
                string.ascii_lowercase + string.digits, k=12))
            domains = ["tempmail.lol", "tempr.email",
                       "tmpmail.org", "mailisku.com"]
            return f"{username}@{random.choice(domains)}"
        except Exception as e:
            raise Exception(f"Tempmail.lol generation error: {e}")

    def _create_maildrop_email(self):
        try:
            username = ''.join(random.choices(
                string.ascii_lowercase + string.digits, k=10))
            return f"{username}@maildrop.cc"
        except Exception as e:
            raise Exception(f"Maildrop generation error: {e}")

    def _create_mailtm_email(self):
        # Often requires JS, API calls might fail.
        try:
            domain_url = "https://api.mail.tm/domains?page=1"
            headers = {'Accept': 'application/json'}
            response = self.session.get(
                domain_url, headers=headers, timeout=10)
            response.raise_for_status()
            domains_data = response.json()
            if not domains_data or 'hydra:member' not in domains_data or not domains_data['hydra:member']:
                raise Exception("No domains found or invalid response")
            domain = random.choice(domains_data['hydra:member'])['domain']

            account_url = "https://api.mail.tm/accounts"
            username = ''.join(random.choices(
                string.ascii_lowercase + string.digits, k=12))
            password = self.generate_password()
            payload = {"address": f"{username}@{domain}", "password": password}
            headers['Content-Type'] = 'application/json'
            response = self.session.post(
                account_url, headers=headers, json=payload, timeout=15)

            if response.status_code == 201:
                return f"{username}@{domain}"
            else:
                try:
                    error_details = response.json()
                except:
                    error_details = response.text
                raise Exception(
                    f"Account creation failed: {response.status_code} - {error_details}")
        except Exception as e:
            raise Exception(f"Mail.tm error: {e}")

    def _create_1secmail_email(self):
        try:
            response = requests.get(
                "https://www.1secmail.com/api/v1/?action=genRandomMailbox&count=1",
                headers={'User-Agent': self.api_user_agent}, timeout=10, proxies=None
            )
            response.raise_for_status()
            email_list = response.json()
            return email_list[0] if email_list else None
        except Exception as e:
            raise Exception(f"1secmail error: {e}")

    def _create_generic_fallback_email(self):
        try:
            domains = ["mailinator.com", "yopmail.com",
                       "inboxkitten.com", "throwawaymail.com"]
            username = ''.join(random.choices(
                string.ascii_lowercase + string.digits, k=12))
            domain = random.choice(domains)
            return f"{username}@{domain}"
        except Exception as e:
            self.logger.error(f"Generic fallback generation failed: {e}")
            return f"very_fallback_{int(time.time())}@example.com"

    def generate_password(self, length=14):
        try:
            length = max(12, min(length, 20))
            password = [
                random.choice(string.ascii_lowercase), random.choice(
                    string.ascii_uppercase),
                random.choice(string.digits), random.choice(
                    "!@#$%^&*()_+-=[]{}|;:,.<>?")
            ]
            remaining_length = length - len(password)
            chars = string.ascii_letters + string.digits + "!@#$%^&*()_+-=[]{}|;:,.<>?"
            password.extend(random.choice(chars)
                            for _ in range(remaining_length))
            random.shuffle(password)
            return ''.join(password)
        except Exception as e:
            self.logger.error(f"Error generating password: {e}")
            return ''.join(random.choices(string.ascii_letters + string.digits, k=12))

# === Custom Logging Handlers ===


class ColorizingFormatter(logging.Formatter):
    # Custom formatter to add colors to terminal output
    def format(self, record):
        log_message = super().format(record)
        color = LOG_COLORS.get(record.levelno)
        if color and colorama:
            # Dynamically get color attribute from colorama.Fore or Style
            color_attr = getattr(colorama.Fore, color,
                                 getattr(colorama.Style, color, None))
            if color_attr:
                log_message = color_attr + log_message + colorama.Style.RESET_ALL
        return log_message


class QueueHandler(logging.Handler):
    # Pushes formatted log records with level info to a queue for the GUI
    def __init__(self, log_queue):
        super().__init__()
        self.log_queue = log_queue

    def emit(self, record):
        log_entry = self.format(record)
        # Put tuple (level, message) for GUI coloring
        self.log_queue.put((record.levelno, log_entry))


# === Core Logic: Enhanced Instagram Account Manager ===
class EnhancedInstagramManager:
    def __init__(self, log_queue=None):
        # Main lists
        self.accounts = []
        self.proxies = []  # Holds the final list after full verification

        # Incremental Proxy Handling
        # Holds proxies as they pass verification
        self.verified_proxies_queue = queue.Queue()
        # Signalled when first usable proxy is found
        self.first_proxy_available = threading.Event()
        # Keep track of proxies currently in use by drivers
        self._currently_used_proxies = set()
        # Lock for accessing shared proxy resources if needed
        self._proxy_lock = threading.Lock()

        # Driver/Session state
        self.current_proxy = None
        self.current_account = None
        self.driver = None
        self.session = requests.Session()  # Primarily for proxy checks etc.

        # Utils
        self.user_agent_generator = UserAgent()
        self.current_user_agent = self.user_agent_generator.random

        # Logging
        self.log_queue = log_queue
        self.logger = logging.getLogger(__name__)

        # Settings
        self.settings = {
            "max_accounts": 100, 
            "max_reports_per_day": 15, 
            "report_interval_seconds": 1800,
            "random_delay_min": 1.0, 
            "random_delay_max": 3.0,  # Slightly reduced max delay
            # Reduced attempts maybe
            "max_login_attempts": 2, 
            "account_creation_delay": (5, 15),
            # Slightly shorter timeout, more threads
            "proxy_timeout": 8, 
            "proxy_test_threads": 75,
            "use_direct_connection_fallback": True, 
            "browser_type": "chrome", 
            "headless": True,
            "enable_stealth": True, 
            "save_screenshots": False, 
            "debug_mode": False,
            "chrome_binary_path": "", 
            "chrome_driver_path": "",
            "backoff_factor": 1.5, 
            "webdriver_wait_timeout": 15,
            "max_mass_report_workers": 5,  # Limit concurrent reporting "bots"
        }

        self.platform_urls = {
            "base": "https://www.instagram.com/", "login": "https://www.instagram.com/accounts/login/",
            "signup": "https://www.instagram.com/accounts/emailsignup/", "graphql": "https://www.instagram.com/graphql/query/",
        }

        self.setup_logging()
        self.email_creator = EnhancedEmailCreator(self.logger)
        LOG_DIR.mkdir(exist_ok=True)
        SCREENSHOT_DIR.mkdir(exist_ok=True)

        self.logger.info("Starting Enhanced Instagram Account Manager...")
        self.load_accounts_from_csv()  # Load existing accounts first

        # Start proxy load thread in background
        self.proxy_load_thread = threading.Thread(
            target=self._load_and_verify_proxies_background, daemon=True)
        self.proxy_load_thread.start()

    def setup_logging(self):
        if self.logger.hasHandlers():
            self.logger.handlers.clear()

        log_level = logging.DEBUG if self.settings.get(
            "debug_mode", False) else logging.INFO
        self.logger.setLevel(log_level)

        # Use simplified format for GUI, Colorizing for Console
        gui_log_format = '%(asctime)s - %(levelname)s - %(message)s'
        console_log_format = '%(asctime)s - %(levelname)-8s - [%(filename)s:%(lineno)d] - %(message)s' if log_level == logging.DEBUG else gui_log_format

        # File Handler (always use detailed format)
        file_formatter = logging.Formatter(console_log_format)
        try:
            file_handler = logging.FileHandler(
                LOG_DIR / LOG_FILENAME, encoding='utf-8', mode='a')
            file_handler.setLevel(log_level)
            file_handler.setFormatter(file_formatter)
            self.logger.addHandler(file_handler)
        except Exception as e:
            print(f"Error setting up file logger: {e}", file=sys.stderr)

        # Console Handler (with colors)
        console_formatter = ColorizingFormatter(console_log_format)
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(log_level)
        console_handler.setFormatter(console_formatter)
        self.logger.addHandler(console_handler)

        # GUI Queue Handler (with its own simpler formatter)
        if self.log_queue:
            gui_formatter = logging.Formatter(gui_log_format)
            queue_handler = QueueHandler(self.log_queue)
            queue_handler.setLevel(log_level)
            queue_handler.setFormatter(gui_formatter)
            self.logger.addHandler(queue_handler)

        self.logger.propagate = False

    # --- Proxy Handling (Revised for Incremental Availability) ---
    def _load_and_verify_proxies_background(self, progress_bar=None, status_var=None, root_after=None):
        # Runs in a thread, fetches raw proxies and launches verification workers.
        # Puts verified proxies into self.verified_proxies_queue.
        self.logger.info(
            "Background Proxy Check: Starting fetch and verification...")
        raw_proxies = []
        try:
            raw_proxies = self._fetch_raw_proxies()
            if not raw_proxies:
                self.logger.warning(
                    "Background Proxy Check: No raw proxies found from internet sources.")
            else:
                self.logger.info(
                    f"Background Proxy Check: Found {len(raw_proxies)} potential proxies. Starting verification...")

            # Include direct connection in the list to be verified if fallback enabled
            to_verify = list(raw_proxies)  # Make a copy
            fallback_enabled = self.settings.get(
                "use_direct_connection_fallback", True)
            if fallback_enabled and "" not in to_verify:
                self.logger.debug(
                    "Background Proxy Check: Adding direct connection ('') to verification list.")
                to_verify.insert(0, "")  # Verify direct first if possible

            if not to_verify:
                self.logger.error(
                    "Background Proxy Check: No proxies and no direct connection to verify.")
                self.first_proxy_available.set()  # Signal that check is 'done' (with no results)
                # Also update the main self.proxies list
                with self._proxy_lock:
                    self.proxies = []
                return

            # Verify in parallel, using the queue mechanism now. _verify_proxies_parallel puts results in queue.
            # It still returns the final full list.
            final_verified_list = self._verify_proxies_parallel(
                to_verify, progress_bar, status_var, root_after
            )

            # Store the fully verified list for later full access or round-robin
            with self._proxy_lock:
                self.proxies = final_verified_list
            self.logger.info(
                f"Background Proxy Check: Full verification complete. Final list contains {len(final_verified_list)} options.")

        except Exception as e:
            self.logger.error(
                f"Background Proxy Check: Error during loading/verification: {e}", exc_info=True)
        finally:
            # Ensure event is set even if errors occurred or no proxies found
            if not self.first_proxy_available.is_set():
                self.logger.warning("Background Proxy Check: Finished, but no proxies were successfully verified and queued.")
                self.first_proxy_available.set()  # Signal completion anyway
            else:
                self.logger.info("Background Proxy Check: Verification process finished.")
             # Final check on the proxies list if needed after thread done.

    def _verify_proxies_parallel(self, proxy_list, progress_bar=None, status_var=None, root_after=None):
        # Verifies proxies, Puts successful ones into self.verified_proxies_queue
        # Returns the final complete list of verified proxies
        verified_proxies_set = set()
        total_proxies = len(proxy_list)
        processed_count = 0
        max_threads = self.settings.get("proxy_test_threads", 50)

        if total_proxies == 0:
            return []

        self.logger.info(
            f"Verifying {total_proxies} proxies using up to {max_threads} threads...")

        # Reset and show progress bar if GUI elements provided
        gui_update_active = progress_bar and status_var and root_after
        if gui_update_active:
            # Schedule GUI updates in main thread
            try:
                def setup_gui_progress():
                    if progress_bar.winfo_exists():
                        progress_bar.config(value=0, maximum=total_proxies)
                    if status_var and hasattr(status_var, 'set'):
                        status_var.set(
                            f"Verifying 0/{total_proxies} (0%)...")
                    if progress_bar.winfo_exists():
                        progress_bar.grid()  # Ensure visible

                    root_after(0, setup_gui_progress)
            except Exception as gui_err:
                self.logger.error(f"Error setting up GUI progress: {gui_err}")
                gui_update_active = False

        first_found = False  # Track if we've set the event yet

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
            future_to_proxy = {executor.submit(
                self._verify_proxy, proxy): proxy for proxy in proxy_list}

            for future in concurrent.futures.as_completed(future_to_proxy):
                proxy_original = future_to_proxy[future]
                processed_count += 1

                # GUI Update Logic
                if gui_update_active:
                    try:
                        percent_done = int(
                            (processed_count / total_proxies) * 100)

                        def update_gui_progress(p=processed_count, t=total_proxies, pct=percent_done):
                            if progress_bar.winfo_exists():
                                progress_bar.config(value=p)
                            if status_var and hasattr(status_var, 'set'):
                                status_var.set(
                                    f"Verifying {p}/{t} ({pct}%)...")
                        root_after(0, update_gui_progress)
                    except Exception as gui_err:
                        self.logger.error(
                            f"Error updating GUI progress: {gui_err}")
                        gui_update_active = False

                # Process Result
                try:
                    result_proxy = future.result()  # Returns "ip:port", "", or None
                    if result_proxy is not None:
                        proxy_display_name = result_proxy if result_proxy else "Direct Connection"
                        # Log success to console too
                        self.logger.debug(
                            f"Proxy Verification Success: {proxy_display_name}")
                        verified_proxies_set.add(result_proxy)
                        # Put into the queue for immediate use
                        self.verified_proxies_queue.put(result_proxy)
                        # Signal if this is the first one
                        if not first_found:
                            self.logger.info(
                                f"First usable proxy found ({proxy_display_name}). Signaling availability.")
                            self.first_proxy_available.set()
                            first_found = True
                    # No need to log failure here, _verify_proxy already does debug logs for failures
                except Exception as e:
                    self.logger.error(f"Error processing verification result for proxy {proxy_original}: {e}", exc_info=self.settings.get(
                        "debug_mode", False))

        # Final GUI Cleanup
        if gui_update_active:
            try:
                def finalize_gui_progress():
                    if progress_bar.winfo_exists():
                        progress_bar.grid_forget()
                    if status_var and hasattr(
                            status_var, 'set'):
                        status_var.set("")
                root_after(0, finalize_gui_progress)
            except Exception as gui_err:
                self.logger.error(f"Error finalizing GUI progress: {gui_err}")

        # Final processing and return
        verified_list = list(verified_proxies_set)
        if "" in verified_list:
            verified_list.remove("")
            verified_list.insert(0, "")
        self.logger.info(
            f"Full verification complete. {len(verified_list)} total working options found.")
        return verified_list

    def _get_random_proxy(self):
        # Tries to get a proxy: 1) From queue 2) Waits briefly for first proxy 3) Falls back to full list
        self.logger.debug("Attempting to get a random proxy...")

        with self._proxy_lock:  # Ensure atomic check/get from queue/list
            # Try immediate non-blocking queue check first
            try:
                proxy = self.verified_proxies_queue.get_nowait()
                # Ensure proxy isn't currently in use? Basic check for now.
                # A more robust system would mark proxies as busy/free.
                # For simplicity, we just get one and hope for the best in high concurrency.
                self.logger.debug(
                    f"Got proxy from verification queue: {proxy if proxy else 'Direct Connection'}")
                # Optional: Add to a 'currently_used' set temporarily? Needs matching release.
                # self._currently_used_proxies.add(proxy)
                return proxy
            except queue.Empty:
                self.logger.debug(
                    "Proxy verification queue is currently empty.")
                pass  # Queue empty, proceed to next check

            # If queue is empty, check if the final 'self.proxies' list is populated
            if self.proxies:
                available_proxies = [
                    p for p in self.proxies if p not in self._currently_used_proxies]
                if available_proxies:
                    proxy = random.choice(available_proxies)
                    self.logger.debug(
                        f"Got proxy from fully verified list: {proxy if proxy else 'Direct Connection'}")
                    # self._currently_used_proxies.add(proxy)
                    return proxy
                else:
                    # All proxies from final list are somehow 'in use' or list only had unavailable ones. Rare.
                    self.logger.warning(
                        "No available proxies in the final verified list (all marked as 'in use'?).")

            # If both queue and final list yield nothing, wait briefly for the FIRST proxy event
            self.logger.debug(
                "Neither queue nor final list yielded proxy, waiting for first availability signal...")
            signaled = self.first_proxy_available.wait(
                timeout=10.0)  # Wait up to 10 seconds

            if signaled:
                self.logger.debug(
                    "First proxy availability signaled. Trying queue again.")
                try:
                    proxy = self.verified_proxies_queue.get_nowait()
                    self.logger.debug(
                        f"Got proxy from queue after waiting: {proxy if proxy else 'Direct Connection'}")
                    # self._currently_used_proxies.add(proxy)
                    return proxy
                except queue.Empty:
                    # This case is odd: event set but queue empty. Fallback to list maybe?
                    if self.proxies:
                        # Pick from final list again as last resort
                        proxy = random.choice(self.proxies)
                        self.logger.warning(
                            f"Signal set but queue empty. Picked from final list: {proxy if proxy else 'Direct'}")
                        return proxy
                    else:
                        self.logger.error(
                            "Signal set, but queue and final list are empty. No connection available.")
                        return None
            else:
                # Timeout waiting for signal - means no proxy became available
                self.logger.error(
                    "Timed out waiting for the first proxy/direct connection to become available.")
                return None  # No proxy available within reasonable time

    def release_proxy(self, proxy):
        # Placeholder if we implement marking proxies as busy/free
        # with self._proxy_lock:
        #     if proxy in self._currently_used_proxies:
        #         self._currently_used_proxies.remove(proxy)
        #     self.logger.debug(f"Released proxy: {proxy if proxy else 'Direct'}")
        pass

    def _fetch_raw_proxies(self):
        # Fetches potential proxy IPs from various sources. (Keep implementation from v2.5_fixed)
        self.logger.debug("Fetching raw proxy lists...")
        headers = {'User-Agent': self.user_agent_generator.random,
                   'Accept': 'text/plain,*/*'}
        proxy_sources = {
            'proxyscrape_http': {
                'url': 'https://api.proxyscrape.com/v3/free-proxy-list/get?request=displayproxies&protocol=http&proxy_format=ipport&format=text',
                'parser': self._parse_plain_text},
            'proxyscrape_https': {
                'url': 'https://api.proxyscrape.com/v3/free-proxy-list/get?request=displayproxies&protocol=https&proxy_format=ipport&format=text',
                'parser': self._parse_plain_text},
            'geonode': {
                'url': 'https://proxylist.geonode.com/api/proxy-list?limit=100&page=1&sort_by=lastChecked&sort_type=desc&protocols=http%2Chttps',
                'parser': self._parse_geonode},
            'openproxy_space_http': {
                'url': 'https://openproxy.space/list/http',
                'parser': self._parse_openproxy_space},
            'free_proxy_list': {'url': 'https://free-proxy-list.net/', 'parser': self._parse_table_proxies_fpl},
            'ssl_proxies': {'url': 'https://www.sslproxies.org/', 'parser': self._parse_table_proxies_fpl},
        }
        all_proxies = set()
        fetch_session = requests.Session()
        retries = requests.adapters.Retry(
            total=3, backoff_factor=0.5, status_forcelist=[500, 502, 503, 504])
        fetch_session.mount(
            'https://', requests.adapters.HTTPAdapter(max_retries=retries))
        fetch_session.headers.update(headers)

        for source_name, source_info in proxy_sources.items():
            try:
                self.logger.debug(f"Fetching raw from {source_name}...")
                response = fetch_session.get(source_info['url'], timeout=20, proxies={
                                             "http": None, "https": None})
                response.raise_for_status()
                content_type = response.headers.get('content-type', '').lower()
                if 'json' in content_type:
                    content = response.text
                elif 'html' in content_type:
                    content = response.text
                elif 'text' in content_type:
                    content = response.text
                else:
                    self.logger.warning(
                        f"Unknown content type '{content_type}' from {source_name}")
                    content = response.text

                parsed_proxies = source_info['parser'](content)
                ip_port_pattern = re.compile(
                    r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}:\d{1,5}$")
                valid_format = {
                    p for p in parsed_proxies if ip_port_pattern.match(p)}
                count = len(valid_format)

                if count > 0:
                    self.logger.debug(
                        f"Got {count} valid proxies from {source_name}")
                    all_proxies.update(valid_format)
                else:
                    self.logger.debug(
                        f"No valid format proxies from {source_name}")

            except requests.exceptions.RequestException as e:
                self.logger.error(
                    f"Error fetching raw from {source_name}: {e}")
            except Exception as e:
                self.logger.error(f"Error parsing raw from {source_name}: {e}")
            time.sleep(random.uniform(0.3, 0.9))

        fetch_session.close()
        self.logger.info(
            f"Fetched {len(all_proxies)} total potential proxies.")
        return list(all_proxies)

    def _parse_plain_text(self, text_content): return [line.strip(
    ) for line in text_content.strip().splitlines() if ':' in line.strip()]

    def _parse_geonode(self, json_text):
        proxies = set()
        try:
            data = json.loads(json_text)
            for p in data.get('data', []):
                if p.get('ip') and p.get('port') and any(proto in ['http', 'https'] for proto in p.get('protocols', [])):
                    proxies.add(f"{p['ip']}:{p['port']}")
        except Exception as e:
            self.logger.error(f"Error parsing geonode: {e}")
        return list(proxies)

    def _parse_openproxy_space(self, text_content):
        proxies = set()
        ip_port_pattern = re.compile(
            r"(\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}:\d{1,5}\b)")
        for line in text_content.strip().splitlines():
            match = ip_port_pattern.search(line)
            if match:
                proxies.add(match.group(1))
        return list(proxies)

    def _parse_table_proxies_fpl(self, html_content):
        proxies = set()
        pattern = re.compile(
            r"<tr>\s*<td>((?:\d{1,3}\.){3}\d{1,3})</td>\s*<td>(\d+)</td>.*?</tr>", re.VERBOSE | re.IGNORECASE | re.DOTALL)
        for ip, port in pattern.findall(html_content):
            proxies.add(f"{ip}:{port}")
        return list(proxies)

    def _verify_proxy(self, proxy):
        # Verifies a single proxy ("ip:port" or "" for direct).
        # Logs detailed success/failure info.
        test_url = self.platform_urls["login"]
        proxy_dict = None
        proxy_display_name = "Direct Connection"
        if proxy:
            proxy_dict = {"http": f"http://{proxy}",
                          "https": f"http://{proxy}"}
            proxy_display_name = proxy
        self.logger.debug(
            f"Verifying connection: {proxy_display_name} against {test_url}")

        try:
            start_time = time.time()
            response = self.session.get(test_url, proxies=proxy_dict, timeout=self.settings["proxy_timeout"], headers={
                                        'User-Agent': self.user_agent_generator.random})
            latency = time.time() - start_time
            if response.status_code == 200:
                self.logger.debug(
                    f"[V] SUCCESS: {proxy_display_name} (Status: {response.status_code}, Latency: {latency:.2f}s)")
                return proxy  # Return original string or ""
            else:
                self.logger.debug(
                    f"[X] FAIL: {proxy_display_name} - Status: {response.status_code}")
                return None
        except (requests.exceptions.ProxyError, requests.exceptions.ConnectTimeout, requests.exceptions.SSLError) as e:
            self.logger.debug(
                f"[X] FAIL: {proxy_display_name} - Conn/Proxy Error: {type(e).__name__}")
            return None
        except requests.exceptions.Timeout:
            self.logger.debug(
                f"[X] FAIL: {proxy_display_name} - Timeout ({self.settings['proxy_timeout']}s)")
            return None
        except requests.exceptions.RequestException as e:
            self.logger.debug(
                f"[X] FAIL: {proxy_display_name} - RequestException: {type(e).__name__}")
            return None
        except Exception as e:
            self.logger.warning(
                f"Unexpected error verifying {proxy_display_name}: {e}")
            return None

    # --- WebDriver Setup (Revised) ---
    def _setup_driver(self):
        # Initializes WebDriver, using available proxy.
        if self.driver:
            self.logger.warning(
                "Closing existing driver before creating new.")
            self.close_driver()

        self.current_proxy = self._get_random_proxy()
        self.current_user_agent = self.user_agent_generator.random
        browser_type = self.settings.get("browser_type", "chrome").lower()
        headless_mode = self.settings.get("headless", True)
        use_stealth = self.settings.get("enable_stealth", True)

        self.logger.info(f"Setting up {browser_type} WebDriver...")
        self.logger.debug(
            f"  Headless: {headless_mode}, Stealth: {use_stealth}")
        self.logger.debug(f"  User Agent: {self.current_user_agent}")

        if self.current_proxy is None:  # Check if _get_random_proxy failed
            self.logger.error(
                "Driver setup failed: No proxy/direct connection became available.")
            return False  # Critical failure
        elif self.current_proxy == "":
            self.logger.info("  Using Direct Connection")
            proxy_arg = None
        else:
            self.logger.info(f"  Using Proxy: {self.current_proxy}")
            proxy_arg = f"--proxy-server=http://{self.current_proxy}"

        try:
            if browser_type == "chrome":
                options = ChromeOptions()
                # Common options first
                options.add_argument(
                    "--disable-blink-features=AutomationControlled")
                options.add_argument('--no-sandbox')
                options.add_argument('--disable-dev-shm-usage')
                options.add_argument('--disable-gpu')
                options.add_argument('--log-level=3')
                options.add_experimental_option(
                    "excludeSwitches", ["enable-automation"])
                options.add_experimental_option(
                    'useAutomationExtension', False)
                # User agent & window size
                options.add_argument(f"user-agent={self.current_user_agent}")
                options.add_argument("--window-size=1280,800")
                # Headless & Proxy
                if headless_mode:
                    options.add_argument("--headless=new")
                if proxy_arg:
                    options.add_argument(proxy_arg)

                # Paths (Binary & Driver)
                chrome_binary = self.settings.get(
                    "chrome_binary_path", "").strip()
                if chrome_binary and Path(chrome_binary).is_file():
                    options.binary_location = chrome_binary
                    self.logger.debug(
                        f"Using custom Chrome binary: {chrome_binary}")
                manual_driver_path = self.settings.get(
                    "chrome_driver_path", "").strip()
                service_args = ['--log-level=OFF']
                service = None

                if manual_driver_path and Path(manual_driver_path).is_file():
                    self.logger.info(
                        f"Using manual ChromeDriver: {manual_driver_path}")
                    service = ChromeService(
                        executable_path=manual_driver_path, service_args=service_args)
                else:
                    if manual_driver_path:
                        self.logger.warning(
                            f"Manual ChromeDriver path invalid, using WebDriver Manager: {manual_driver_path}")
                    self.logger.info("Using WebDriver Manager for ChromeDriver...")
                    try:
                        service = ChromeService(
                            ChromeDriverManager().install(), service_args=service_args)
                    except Exception as wdm_error:
                        self.logger.error(
                            f"WebDriver Manager failed: {wdm_error}")
                        return False  # Cannot proceed without driver

                self.logger.debug("Initializing Chrome Driver instance...")
                self.driver = webdriver.Chrome(
                    service=service, options=options)
                self.logger.debug("Chrome Driver Initialized.")

            else:
                self.logger.error(f"Unsupported browser: {browser_type}")
                return False

            # Stealth Apply
            if self.driver and use_stealth:
                self.logger.debug("Applying Selenium Stealth...")
                try:
                    stealth(self.driver, languages=["en-US", "en"], vendor="Google Inc.", platform="Win32",
                            webgl_vendor="Intel Inc.", renderer="Intel Iris OpenGL Engine", fix_hairline=True)
                    self.logger.debug("Stealth applied.")
                except Exception as stealth_err:
                    self.logger.warning(
                        f"Stealth application error: {stealth_err}")

            self.logger.info("WebDriver setup successful.")
            return True

        except SessionNotCreatedException as e:
            self.logger.error(f"WebDriver Session Creation Failed: {e}")
            if "only supports Chrome version" in str(e):
                self.logger.error(
                    ">>> ChromeDriver version likely Mismatched! <<< Update Chrome or provide correct ChromeDriver path.")
            if self.driver:
                try:
                    self.driver.quit()
                except:
                    pass
                self.driver = None
            return False
        except WebDriverException as e:
            self.logger.error(
                f"General WebDriver setup error: {e}", exc_info=self.settings.get("debug_mode"))
            if "net::ERR_PROXY_CONNECTION_FAILED" in str(e):
                self.logger.error(
                    f"Proxy connection FAILED for {self.current_proxy}.")
            if self.driver:
                try:
                    self.driver.quit()
                except:
                    pass
                self.driver = None
            return False
        except Exception as e:
            self.logger.error(
                f"Unexpected WebDriver setup error: {e}", exc_info=True)
            if self.driver:
                try:
                    self.driver.quit()
                except:
                    pass
                self.driver = None
            return False

    # --- Account Generation & Management (Logging added) ---

    def generate_password(
        self, length=14): return self.email_creator.generate_password(length)

    def generate_username(self, max_attempts=20):
        # (Implementation from v2.5_fixed - slightly more robust)
        self.logger.debug("Generating username...")
        prefixes = ["the", "real", "official", "its", "mr", "mrs", "dr"]
        nouns = ["photo", "pixel", "insta", "gram",
                 "snapshot", "view", "scene", "travel", "art"]
        suffixes = ["life", "vibes", "world", "pics", "shots", "daily"]
        separators = ["", ".", "_"]
        numbers = [str(random.randint(10, 999)),
                   str(random.randint(1980, 2010))]
        for attempt in range(max_attempts):
            try:
                parts = []
                sep = random.choice(separators)
                if random.random() < 0.3:
                    parts.append(random.choice(prefixes))
                parts.append(random.choice(nouns))
                if random.random() < 0.4:
                    parts.append(random.choice(suffixes))
                if random.random() < 0.5:
                    parts.append(random.choice(numbers))
                username = sep.join(parts)[:28]
                username = re.sub(r'[^a-z0-9._]', '', username.lower())
                username = re.sub(r'[._]{2,}', '.', username)
                username = username.strip('._')
                if 3 <= len(username) <= 30:
                    self.logger.debug(
                        f"Generated potential username: {username} (Attempt {attempt+1})")
                    return username
            except Exception as e:
                self.logger.warning(
                    f"Username gen attempt {attempt+1} error: {e}")
        fallback = f"user_{int(time.time())}_{random.randint(100, 999)}"[:30]
        self.logger.warning(
            f"Username gen failed after {max_attempts}. Using fallback: {fallback}")
        return fallback

    def create_temporary_account(self, email=None, username=None, password=None):
        # Attempts account creation via Selenium.
        action_id = ''.join(random.choices(
            string.ascii_lowercase + string.digits, k=6))  # For tracing logs
        self.logger.info(
            f"AccCreate-{action_id}: Starting creation attempt...")
        account_info = None
        driver_created = False
        used_proxy = None

        try:
            if not self.driver:
                driver_created = self._setup_driver()  # Sets self.current_proxy
                if not driver_created:
                    # Will be caught below
                    raise Exception("WebDriver setup failed")
                used_proxy = self.current_proxy  # Capture proxy used by this driver
            else:
                driver_created = True
                used_proxy = self.current_proxy  # Use existing driver

            creation_email = email or self.email_creator.create_temporary_email()
            if not creation_email:
                raise Exception("Failed to obtain temporary email")
            self.logger.info(
                f"AccCreate-{action_id}: Using email: {creation_email}")

            creation_username = username or self.generate_username()
            self.logger.info(
                f"AccCreate-{action_id}: Attempting username: {creation_username}")
            creation_password = password or self.generate_password()
            self.logger.info(
                f"AccCreate-{action_id}: Using generated/provided password.")

            # Selenium Signup Flow
            self.logger.debug(
                f"AccCreate-{action_id}: Starting Selenium signup process...")
            signup_successful = self.signup_with_selenium(
                creation_email, creation_username, creation_password)

            if not signup_successful:
                # Specific errors logged within signup_with_selenium
                raise Exception(
                    f"Selenium signup process failed for {creation_username}")

            # Post-Signup Checks (Birthday already handled in signup_with_selenium if needed)
            # Add checks for other potential immediate popups/challenges here if necessary
            self.logger.debug(
                f"AccCreate-{action_id}: Selenium signup returned success. Performing final checks...")
            self._random_delay(1, 3)  # Small delay for page state to settle

            current_url = "Unknown"
            status = "unknown"
            try:
                current_url = self.driver.current_url
            except WebDriverException:
                self.logger.warning(
                    "Could not get current URL after signup (driver died?)")
                current_url = "Error"
                status = "error"

            self.logger.debug(
                f"AccCreate-{action_id}: URL after signup process: {current_url}")

            # Check final URL state
            if any(marker in current_url for marker in ["login", "/challenge/", "suspended", "disabled", "emailsignup"]):
                status = "verification_needed" if "/challenge/" in current_url or "/confirm/" in current_url else "failed_creation"
                self.logger.error(
                    f"AccCreate-{action_id}: Signup blocked/failed post-process. URL: {current_url}, Status: {status}")
                if self.settings.get("save_screenshots", False):
                    self._save_screenshot(
                        f"creation_blocked_{creation_username}")
            elif status != "error":  # If no obvious error URL and no driver error getting URL
                # Assume active if landed somewhere reasonable
                self.logger.info(
                    f"AccCreate-{action_id}: Account '{creation_username}' seems successfully created.")
                status = "active"
                self._handle_common_popups(
                    "Not Now", timeout=5)  # Dismiss final popups

            # Create account info dict (even if needs verification)
            if status != "failed_creation" and status != "error":
                account_info = {
                    "email": creation_email, "username": creation_username, "password": creation_password,
                    "created_at": time.time(), "reports_made": 0, "last_report_time": 0,
                    "status": status,  # active or needs_verification
                    "proxy_used": used_proxy or "Direct",
                    "user_agent": self.current_user_agent
                }
                self._save_account_to_csv(account_info)
                self.accounts.append(account_info)
                self.logger.info(
                    f"AccCreate-{action_id}: Saved account {creation_username} with status {status}.")
            else:
                # Handle explicit failed_creation/error state
                self.logger.error(
                    f"AccCreate-{action_id}: Creation attempt failed definitively for {creation_username}.")

        except Exception as e:
            self.logger.error(
                f"AccCreate-{action_id}: Account creation failed: {e}", exc_info=self.settings.get("debug_mode"))
            if self.settings.get("save_screenshots", False):
                self._save_screenshot(
                    f"creation_exception_{username or 'random'}")
        finally:
            # Manage driver closure and delays
            if account_info is None and self.driver:  # If failed, close the driver created for this attempt
                self.logger.debug(
                    f"AccCreate-{action_id}: Closing driver after failed attempt.")
                self.close_driver()  # Also releases proxy (placeholder)
            elif self.driver:  # Success or needs_verification, driver might stay open for next action
                self.logger.debug(
                    f"AccCreate-{action_id}: Driver potentially kept open after creation.")

            # Add delay regardless of success/failure before next potential creation
            delay = random.uniform(
                self.settings["account_creation_delay"][0], self.settings["account_creation_delay"][1])
            self.logger.debug(f"AccCreate-{action_id}: Waiting {delay:.1f}s.")
            time.sleep(delay)
            return account_info

    def signup_with_selenium(self, email, username, password):
        # Uses Selenium to fill signup form. Logs more details. Returns True on reaching a potentially good state, False otherwise.
        if not self.driver:
            self.logger.error("Signup Failed: Driver not available.")
            return False
        wait_timeout = self.settings.get(
            "webdriver_wait_timeout", 15)
        wait = WebDriverWait(self.driver, wait_timeout)

        try:
            signup_url = self.platform_urls['signup']
            self.logger.debug(f"Navigating to signup page: {signup_url}")
            self.driver.get(signup_url)
            self._random_delay(2, 4)

            # Cookie Consent (Best effort)
            self.logger.debug("Checking for cookie consent banners...")
            consent_selectors = ["//button[contains(text(), 'Allow all')]", "//button[contains(text(), 'Accept All')]",
                                 "//button[text()='Allow essential']", "//div[@role='dialog']//button[position()=1]"]
            for i, selector in enumerate(consent_selectors):
                try:
                    WebDriverWait(self.driver, 2).until(
                        EC.element_to_be_clickable((By.XPATH, selector))).click()
                    self.logger.info(f"Clicked cookie consent ({i+1}).")
                    self._random_delay(0.5, 1)
                    break
                except:
                    pass
            else:
                self.logger.debug("No obvious cookie consent banner found.")

            # Fill Form
            self.logger.debug("Filling signup form fields...")
            self._human_type(wait.until(EC.presence_of_element_located(
                (By.NAME, "emailOrPhone"))), email)
            full_name = f"{random.choice(['Alex', 'Jamie', 'Chris', 'Sam'])} {random.choice(['Lee', 'Smith', 'Kim', 'Jones'])}"
            self._human_type(wait.until(EC.presence_of_element_located(
                (By.NAME, "fullName"))), full_name)
            self.logger.debug(f"Using name: {full_name}")
            username_field = wait.until(
                EC.presence_of_element_located((By.NAME, "username")))
            self._human_type(username_field, username)
            self._random_delay(1.5, 3)  # Wait for validation check

            # Check for username error icon (simple visual check)
            try:
                username_field.find_element(
                    By.XPATH, "./following-sibling::span/*[local-name()='svg'][@aria-label='Error']")
                self.logger.error(
                    f"Signup Failed: Username '{username}' marked unavailable on form.")
                return False
            except:
                self.logger.debug("No immediate username error icon.")

            self._human_type(wait.until(
                EC.presence_of_element_located((By.NAME, "password"))), password)
            self._random_delay(0.5, 1.5)

            # Submit
            self.logger.debug("Submitting signup form...")
            submit_xpath = "//button[@type='submit'][contains(., 'Sign up') or contains(., 'Next')]"
            submit_button = None
            try:
                submit_button = wait.until(
                    EC.element_to_be_clickable((By.XPATH, submit_xpath)))
            except:
                self.logger.error(
                    "Signup Failed: Submit button not found/clickable.")
                return False
            try:
                submit_button.click()
            except:
                self.logger.warning("JS click needed for submit")
                self.driver.execute_script(
                    "arguments[0].click();", submit_button)
            self.logger.info("Clicked 'Sign up'. Waiting for result...")
            self._random_delay(5, 8)

            # Outcome Check
            current_url = self.driver.current_url
            self.logger.debug(f"URL after submit: {current_url}")
            page_source_lower = self.driver.page_source.lower()

            if "emailsignup" in current_url:  # Still on signup page?
                if any(err in page_source_lower for err in ["username isn't available", "username is taken", "username you entered belongs", "another account is using"]):
                    self.logger.error(f"Signup Fail: Username taken error.")
                    return False
                elif any(err in page_source_lower for err in ["enter a valid email", "use a different email"]):
                    self.logger.error("Signup Fail: Email invalid/blocked.")
                    return False
                elif any(err in page_source_lower for err in ["something went wrong", "try again", "rate limit"]):
                    self.logger.error(f"Signup Fail: General error msg.")
                    return False
                else:
                    self.logger.error(
                        "Signup Fail: Stuck on signup (CAPTCHA?).")
                    return False
            elif "/birthday/" in current_url:
                self.logger.info("Signup -> Birthday prompt. Handling...")
                if self._handle_birthday_prompt():
                    current_url_after_bday = self.driver.current_url
                    self.logger.debug(
                        f"URL after birthday: {current_url_after_bday}")
                    if any(m in current_url_after_bday for m in ["login", "challenge", "suspended", "disabled"]):
                        self.logger.error("Signup blocked after birthday.")
                        return False
                    else:
                        self.logger.info("Birthday handled successfully.")
                        return True
                else:
                    self.logger.error(
                        "Signup Fail: Failed to handle birthday.")
                    return False
            elif "/challenge/" in current_url:
                # Let caller decide status
                self.logger.warning("Signup -> Immediate Challenge.")
                return True
            elif "/confirm/" in current_url:
                # Let caller decide status
                self.logger.warning("Signup -> Email Confirmation Needed.")
                return True
            elif "/suspended/" in current_url or "/disabled/" in current_url:
                self.logger.error("Signup Fail: Account Immediately Banned.")
                return False
            else:  # Assume success if not on known failure pages
                self.logger.info(
                    "Signup appears successful (not on known failure page).")
                return True

        except Exception as e:
            self.logger.error(
                f"Signup automation unexpected error: {e}", exc_info=True)
            if self.settings.get("save_screenshots", False):
                self._save_screenshot(f"signup_exception_{username}")
            return False

    def _human_type(self, element, text):
        # Simulates typing. (Keep implementation from v2.5_fixed)
        if not element or not text:
            return
        try:
            try:
                element.clear()
            except:
                pass
            self._random_delay(0.1, 0.3)  # Shorten delays slightly
            for char in text:
                element.send_keys(char)
                self._random_delay(0.04, 0.15)
            self._random_delay(0.2, 0.5)
        except StaleElementReferenceException:
            self.logger.warning("Human type failed: Stale element.")
        except Exception as e:
            self.logger.error(f"Human type error: {e}")
            try:
                element.clear()
                element.send_keys(text)  # Fallback
            except Exception as fb_e:
                self.logger.error(f"Fallback send_keys failed: {fb_e}")

    def _random_delay(self, min_sec=None, max_sec=None):
        # Sleeps for a random duration. (Keep implementation)
        min_d = min_sec if min_sec is not None else self.settings["random_delay_min"]
        max_d = max_sec if max_sec is not None else self.settings["random_delay_max"]
        delay = random.uniform(min_d, max_d)
        self.logger.debug(f"Waiting {delay:.2f}s...")
        time.sleep(delay)

    def _save_screenshot(self, prefix="screenshot"):
        # Saves screenshot if enabled. (Keep implementation)
        if not self.driver or not self.settings.get("save_screenshots", False):
            return
        try:
            SCREENSHOT_DIR.mkdir(exist_ok=True)
            filename = SCREENSHOT_DIR / \
                f"{prefix}_{time.strftime('%Y%m%d_%H%M%S')}.png"
            if self.driver.save_screenshot(str(filename)):
                self.logger.info(f"Saved screenshot: {filename}")
            else:
                self.logger.warning(
                    f"Failed to save screenshot (driver false): {filename}")
        except WebDriverException as e:
            self.logger.error(
                f"Screenshot WebDriver error: {e}")
            self.close_driver()
        except Exception as e:
            self.logger.error(f"Screenshot unexpected error: {e}")

    def _handle_birthday_prompt(self, timeout=10):
        # Handles birthday prompt. (Keep implementation, added more logging)
        if not self.driver:
            return False
        wait = WebDriverWait(self.driver, timeout)
        try:
            self.logger.debug("Looking for birthday prompt elements...")
            month_dp = wait.until(EC.presence_of_element_located(
                (By.XPATH, "//select[@title='Month:']")))
            day_dp = wait.until(EC.presence_of_element_located(
                (By.XPATH, "//select[@title='Day:']")))
            year_dp = wait.until(EC.presence_of_element_located(
                (By.XPATH, "//select[@title='Year:']")))
            current_year = time.localtime().tm_year
            b_year, b_month, b_day = random.randint(
                current_year-35, current_year-19), random.randint(1, 12), random.randint(1, 28)
            self.logger.info(f"Setting birthday: {b_month}/{b_day}/{b_year}")
            month_dp.click()
            self._random_delay(0.2, 0.5)
            wait.until(EC.element_to_be_clickable(
                (By.XPATH, f".//option[@value='{b_month}']"))).click()
            day_dp.click()
            self._random_delay(0.2, 0.5)
            wait.until(EC.element_to_be_clickable(
                (By.XPATH, f".//option[@value='{b_day}']"))).click()
            year_dp.click()
            self._random_delay(0.2, 0.5)
            wait.until(EC.element_to_be_clickable(
                (By.XPATH, f".//option[text()='{b_year}']"))).click()
            self._random_delay(0.4, 0.8)
            next_btn = wait.until(EC.element_to_be_clickable(
                (By.XPATH, "//button[contains(text(), 'Next')]")))
            next_btn.click()
            self.logger.debug("Submitted birthday.")
            self._random_delay(3, 5)
            return True
        except Exception as e:
            self.logger.error(f"Error handling birthday: {e}")
            return False

    def _handle_common_popups(self, button_text="Not Now", timeout=5):
        # Clicks common popups. (Keep implementation)
        if not self.driver:
            return
        self.logger.debug(f"Checking for popup: '{button_text}'...")
        try:
            xpath = f"//div[@role='dialog']//button[contains(text(),'{button_text}')]"
            WebDriverWait(self.driver, timeout).until(
                EC.element_to_be_clickable((By.XPATH, xpath))).click()
            self.logger.info(f"Clicked '{button_text}' popup.")
            self._random_delay(0.5, 1.5)
        except:
            self.logger.debug(
                f"Popup '{button_text}' not found or intractable.")

    def _save_account_to_csv(self, account):
        # Appends account to CSV. (Keep implementation)
        file_exists = Path(ACCOUNT_CSV_FILENAME).is_file()
        fieldnames = ["username", "email", "password", "status", "created_at",
                      "reports_made", "last_report_time", "proxy_used", "user_agent"]
        try:
            with open(ACCOUNT_CSV_FILENAME, "a", newline="", encoding='utf-8') as file:
                writer = csv.DictWriter(
                    file, fieldnames=fieldnames, extrasaction='ignore')
                if not file_exists or os.path.getsize(ACCOUNT_CSV_FILENAME) == 0:
                    writer.writeheader()
                row_data = account.copy()
                try:
                    row_data["created_at"] = time.strftime(
                        "%Y-%m-%d %H:%M:%S", time.localtime(float(account.get("created_at", 0))))
                except:
                    row_data["created_at"] = ""
                try:
                    last_report = account.get("last_report_time")
                    row_data["last_report_time"] = time.strftime(
                        "%Y-%m-%d %H:%M:%S", time.localtime(float(last_report))) if last_report else ""
                except:
                    row_data["last_report_time"] = ""
                for field in ["username", "email", "password", "status"]:
                    row_data.setdefault(field, "")
                writer.writerow(row_data)
                self.logger.debug(
                    f"Saved account '{account.get('username')}' to CSV.")
        except Exception as e:
            self.logger.error(
                f"Failed saving '{account.get('username')}' to CSV: {e}")

    def load_accounts_from_csv(self, filename=ACCOUNT_CSV_FILENAME):
        # Loads accounts from CSV. (Keep implementation)
        if not Path(filename).is_file():
            self.logger.warning(f"Account file '{filename}' not found.")
            self.accounts = []
            return
        loaded = []
        try:
            with open(filename, "r", newline="", encoding='utf-8') as file:
                reader = csv.DictReader(file)
                required = ["username", "password"]
                if not reader.fieldnames or not all(f in reader.fieldnames for f in required):
                    self.logger.error(
                        f"CSV '{filename}' missing required columns or empty.")
                    self.accounts = []
                    return
                for i, row in enumerate(reader):
                    try:
                        if not row.get("username") or not row.get("password"):
                            self.logger.warning(
                                f"Skipping row {i+1}: Missing username/password.")
                            continue
                        created_ts = 0
                        last_report_ts = 0
                        try:
                            created_str = row.get("created_at", "").strip()
                            created_ts = time.mktime(
                                time.strptime(created_str, "%Y-%m-%d %H:%M:%S")) if created_str else 0
                        except:
                            self.logger.warning(
                                f"Invalid created_at in row {i+1}. Using 0.")
                        try:
                            last_report_str = row.get(
                                "last_report_time", "").strip()
                            last_report_ts = time.mktime(
                                time.strptime(last_report_str, "%Y-%m-%d %H:%M:%S")) if last_report_str else 0
                        except:
                            self.logger.warning(
                                f"Invalid last_report_time in row {i+1}. Using 0.")
                        account = {"username": row.get("username"), "email": row.get("email", ""), "password": row.get("password"), "status": row.get("status", "unknown").lower(
                        ), "created_at": created_ts, "reports_made": int(row.get("reports_made", 0)), "last_report_time": last_report_ts, "proxy_used": row.get("proxy_used", ""), "user_agent": row.get("user_agent", "")}
                        loaded.append(account)
                    except Exception as row_err:
                        self.logger.warning(
                            f"Error processing row {i+1} (User: {row.get('username')}): {row_err}")
            self.accounts = loaded
            self.logger.info(
                f"Loaded {len(self.accounts)} accounts from {filename}.")
        except Exception as e:
            self.logger.error(
                f"Failed loading accounts from {filename}: {e}")
            self.accounts = []

    # --- Core Actions (Login, Report, Extract) (Logging added) ---
    def login(self, account=None):
        # Logs in, handles multiple attempts, updates account status.
        selected_account = None
        if not account:
            eligible = [acc for acc in self.accounts if acc.get(
                "status") not in ["banned", "locked", "challenge", "login_failed"]]
            if not eligible:
                self.logger.error("Login failed: No eligible accounts.")
                return False
            selected_account = random.choice(eligible)
            self.logger.info(
                f"Attempting login with random eligible account: {selected_account['username']}")
        else:
            selected_account = account
            self.logger.info(
                f"Attempting login with specified account: {selected_account['username']}")

        # Tentative, until login succeeds/fails
        self.current_account = selected_account
        login_success = False
        max_attempts = self.settings.get("max_login_attempts", 2)

        for attempt in range(max_attempts):
            self.logger.info(
                f"Login attempt {attempt + 1}/{max_attempts} for {selected_account['username']}...")
            driver_is_ready = self.driver or self._setup_driver()
            if not driver_is_ready:
                self.logger.warning(
                    f"Login {attempt+1} failed: WebDriver setup failed.")
                continue
            # Longer wait for login
            wait = WebDriverWait(
                self.driver, self.settings["webdriver_wait_timeout"] + 5)

            try:
                login_url = self.platform_urls['login']
                self.logger.debug(f"Navigating to login page: {login_url}")
                self.driver.get(login_url)
                self._random_delay(1, 2.5)
                self._handle_common_popups("Allow all", timeout=3)
                self._handle_common_popups("Accept", timeout=2)  # Cookies

                self.logger.debug("Entering credentials...")
                self._human_type(wait.until(EC.presence_of_element_located(
                    (By.NAME, "username"))), selected_account["username"])
                self._human_type(wait.until(EC.presence_of_element_located(
                    (By.NAME, "password"))), selected_account["password"])
                self._random_delay(0.5, 1.5)

                self.logger.debug("Clicking login button...")
                login_xpath = "//button[@type='submit'][.//div[contains(text(), 'Log in')] or contains(text(), 'Log in')]"
                login_btn = wait.until(
                    EC.element_to_be_clickable((By.XPATH, login_xpath)))
                try:
                    login_btn.click()
                except:
                    self.logger.warning("JS click for login")
                    self.driver.execute_script(
                        "arguments[0].click();", login_btn)
                self.logger.info("Login submitted. Waiting for outcome...")

                # Outcome Wait & Check
                try:
                    WebDriverWait(self.driver, 25).until(EC.any_of(  # Wait 25s for any known outcome
                        EC.url_contains(
                            "instagram.com/?__coig_login"), EC.url_matches(r"https://www.instagram.com/$"),
                        EC.presence_of_element_located(
                            (By.XPATH, "//*[local-name()='svg'][@aria-label='Home']")),
                        EC.presence_of_element_located(
                            (By.ID, "slfErrorAlert")),
                        EC.presence_of_element_located(
                            (By.XPATH, "//*[contains(text(), 'password was incorrect')]")),
                        EC.presence_of_element_located(
                            (By.XPATH, "//*[contains(text(), 'find your account')]")),
                        EC.url_contains(
                            "/challenge/"), EC.url_contains("/suspended/"),
                        EC.url_contains("/disabled/"), EC.url_contains("/login/error")))
                    self._random_delay(1, 2)
                except TimeoutException:
                    self.logger.error(f"Login timeout after {25}s.")
                    continue

                # Analyze Outcome
                current_url = self.driver.current_url
                page_source = self.driver.page_source.lower()
                self.logger.debug(f"Login Outcome URL: {current_url}")

                if "password was incorrect" in page_source or "slfErrorAlert" in page_source or "find your account" in page_source:
                    self.logger.error("Login Fail: Incorrect Credentials.")
                    # Don't retry bad creds
                    selected_account["status"] = "login_failed"
                    break
                elif "/challenge/" in current_url:
                    self.logger.error("Login Fail: Challenge Required.")
                    selected_account["status"] = "challenge"
                    break
                elif "/suspended/" in current_url or "/disabled/" in current_url:
                    self.logger.error("Login Fail: Account Banned.")
                    selected_account["status"] = "banned"
                    break
                elif "/login/error" in current_url:
                    self.logger.error("Login Fail: Generic Login Error page.")
                    continue
                # Unknown reason, retry
                elif "/login" in current_url:
                    self.logger.error("Login Fail: Stuck on login page.")
                    continue
                else:  # Likely Success
                    self.logger.info(
                        f"Login SUCCESS for {selected_account['username']}")
                    login_success = True
                    selected_account["status"] = "active"
                    # Exit attempts loop
                    self._handle_common_popups("Not Now", timeout=5)
                    self._handle_common_popups("Save Info", timeout=3)
                    break

            except StaleElementReferenceException as e:
                self.logger.warning(
                    f"Login Stale element {attempt+1}. Retrying interaction...")
                continue
            except WebDriverException as e:
                self.logger.error(f"Login WebDriverException {attempt+1}: {e}")
                self.close_driver()
                continue  # Need new driver
            except Exception as e:
                self.logger.error(
                    f"Login unexpected error {attempt+1}: {e}", exc_info=True)
                continue

        # After Loop Logic
        if not login_success:
            self.logger.error(
                f"All {max_attempts} login attempts FAILED for {selected_account['username']}.")
            if self.driver:
                self.close_driver()  # Ensure driver is closed if final attempt failed
            self.current_account = None  # Clear if login failed
        else:
            # Successfully logged in, keep driver open. current_account is already set.
            self.logger.debug(
                f"Driver remains open for {selected_account['username']}")

        # Save potentially updated account status back to CSV
        self._save_account_to_csv(selected_account)
        return login_success

    def report_account(self, target_username, reason="spam"):
        # Reports target profile. Returns True (success), False (skipped), None (target not found)
        if not self.driver or not self.current_account:
            self.logger.error("Report Fail: Not logged in.")
            return False
        current_acc_username = self.current_account['username']
        self.logger.info(
            f"Report: Account '{current_acc_username}' reporting '{target_username}' for '{reason}'...")

        # Cooldown/Limit Check
        now = time.time()
        reports_made = self.current_account.get(
            "reports_made", 0)
        last_report = self.current_account.get("last_report_time", 0)
        if (now - last_report) > 86400:
            reports_made = 0  # Daily reset
        if reports_made >= self.settings["max_reports_per_day"]:
            self.logger.warning(
                f"Report SKIPPED: Daily limit reached for {current_acc_username}.")
            return False
        if (now - last_report) < self.settings["report_interval_seconds"]:
            wait = self.settings["report_interval_seconds"] - (now-last_report)
            self.logger.info(
                f"Report SKIPPED: Cooldown active for {current_acc_username}. Wait {wait:.0f}s.")
            return False

        wait = WebDriverWait(
            self.driver, self.settings["webdriver_wait_timeout"])
        short_wait = WebDriverWait(self.driver, 8)
        profile_url = f"{self.platform_urls['base']}{target_username}/"

        try:
            # Navigation & Check Profile Exists
            self.logger.debug(f"Navigating to target: {profile_url}")
            self.driver.get(profile_url)
            self._random_delay(2, 4)
            if "Sorry, this page isn't available" in self.driver.page_source or "Page not found" in self.driver.title:
                self.logger.error(
                    f"Report Fail: Target '{target_username}' not found.")
                return None

            # Click Options (...)
            self.logger.debug("Clicking options '...' button...")
            opts_xpath = "//button[contains(@aria-label,'Options')] | //header//button//*[local-name()='svg'][@aria-label='Options'] | (//header//button)[last()]"
            options_btn = wait.until(
                EC.element_to_be_clickable((By.XPATH, opts_xpath)))
            options_btn.click()
            self._random_delay(0.6, 1.2)

            # Click Report Menu Item
            self.logger.debug("Clicking 'Report' in menu...")
            report_xpath = "//div[@role='dialog']//button[contains(normalize-space(), 'Report')] | //div[@role='menu']//button[contains(normalize-space(), 'Report')]"
            report_opt = short_wait.until(
                EC.element_to_be_clickable((By.XPATH, report_xpath)))
            report_opt.click()
            self._random_delay(1, 2)

            # Handle Report Flow (Simplified, NEEDS MAINTENANCE based on IG UI)
            stage1_map = {"spam": "It's spam", "scam or fraud": "Scam or fraud", "hate speech": "Hate speech or symbols", "impersonation": "Impersonation", "self-injury": "Self-injury", "nudity or sexual activity": "Nudity or sexual activity",
                          "violence": "Violence or dangerous", "bullying or harassment": "Bullying or harassment", "intellectual property": "Intellectual property violation", "false information": "False information", "default": "It's inappropriate"}
            stage1_text = stage1_map.get(reason.lower())
            fallback_stage1 = stage1_map["default"]
            if not stage1_text:
                stage1_text = "Something else" if reason.lower(
                    # Heuristic fallback
                ) in ["scam or fraud", "hate speech"] else fallback_stage1
            self.logger.debug(
                f"Selecting report stage 1: '{stage1_text}' for reason '{reason}'")
            stage1_xpath = f"//div[@role='dialog']//*[self::button or self::div[@role='button'] or @role='radio' or self::label][contains(normalize-space(.), \"{stage1_text}\")]"
            wait.until(EC.element_to_be_clickable(
                (By.XPATH, stage1_xpath))).click()
            self.logger.debug("Clicked stage 1.")
            self._random_delay(1, 2)

            # TODO: Handle stage 2 based on stage 1 choice (complex, depends on reason) - This example is too simple.

            # Click Final Submit/Next/Done
            self.logger.debug("Looking for final submit button...")
            final_xpaths = ["//div[@role='dialog']//button[contains(., 'Submit')]", "//div[@role='dialog']//button[contains(., 'Report')]",
                            "//div[@role='dialog']//button[contains(., 'Next')]", "//div[@role='dialog']//button[contains(., 'Done')]"]
            submitted = False
            for xpath in final_xpaths:
                try:
                    short_wait.until(EC.element_to_be_clickable(
                        (By.XPATH, xpath))).click()
                    self.logger.info(
                        f"Clicked final report button via {xpath}")
                    submitted = True
                    break
                except:
                    pass
            if not submitted:
                self.logger.warning(
                    "Could not find distinct final submit button. Assuming implicit submit/flow change.")
            self._random_delay(2, 4)

            # Check for confirmation/dialog close
            try:
                WebDriverWait(self.driver, 8).until(EC.any_of(EC.presence_of_element_located((By.XPATH, "//*[contains(text(),'Thanks')]")), EC.invisibility_of_element_located(
                    (By.XPATH, "//div[@role='dialog']"))))
                self.logger.debug(
                    "Report confirmation detected/dialog closed.")
            except:
                self.logger.warning(
                    "Report confirmation/dialog close not detected.")
            self._handle_common_popups("Close", timeout=3)
            self._handle_common_popups("Done", timeout=3)

            # Update stats on success
            self.current_account["reports_made"] = reports_made + 1
            self.current_account["last_report_time"] = now
            self._save_account_to_csv(
                self.current_account)
            self.logger.info(
                f"Report SUCCESS for '{target_username}' by '{current_acc_username}' (Count: {self.current_account['reports_made']})")
            return True

        except WebDriverException as e:
            self.logger.error(
                f"Report WebDriver Error for {target_username}: {e}")
            self.close_driver()
            return False
        except Exception as e:
            self.logger.error(
                f"Report Unexpected Error for {target_username}: {e}", exc_info=self.settings.get("debug_mode"))
            return False

    def extract_user_data(self, username):
        # Extracts public data via Selenium. (Keep implementation, logging added/refined)
        if not self.driver or not self.current_account:
            self.logger.error("Extract Fail: Login Required.")
            return {"username": username, "extraction_status": "Login Required"}
        self.logger.info(f"Extracting data for: {username}")
        profile_url = f"{self.platform_urls['base']}{username}/"
        wait = WebDriverWait(
            self.driver, self.settings["webdriver_wait_timeout"])
        user_data = {"username": username, "extraction_timestamp": time.time(), "extraction_status": "pending", "profile_url": profile_url, "user_id": None, "full_name": None, "profile_pic_url": None,
                     "is_private": None, "is_verified": False, "follower_count": None, "following_count": None, "media_count": None, "biography": None, "external_url": None, "category_name": None, "recent_posts": []}

        try:
            self.logger.debug(f"Navigating to profile: {profile_url}")
            self.driver.get(profile_url)
            self._random_delay(3, 5)

            # Availability/Privacy Checks
            page_title = self.driver.title.lower()
            page_source = self.driver.page_source.lower()
            if "page not found" in page_title or "not available" in page_source:
                user_data["extraction_status"] = "Profile not found"
                self.logger.warning(f"Profile {username} not found.")
                return user_data
            private_xpath = "//h2[contains(text(), 'Private')]"
            user_data["is_private"] = False
            try:
                if self.driver.find_elements(By.XPATH, private_xpath):
                    user_data["is_private"] = True
                    self.logger.info(
                        "Profile is private.")
            except WebDriverException:
                user_data["is_private"] = None
                self.logger.warning("Privacy check WebDriver error.")
            if user_data["is_private"]:
                user_data["extraction_status"] = "Completed (Private)"

            # Header Extraction (Inside try/except blocks for resilience)
            self.logger.debug("Extracting header info...")
            try:
                header = wait.until(
                    EC.visibility_of_element_located((By.XPATH, "//header")))
            # Critical if header fails
            except:
                self.logger.error("Header not found.")
                user_data["extraction_status"] = "Header Failed"
                return user_data
            try:
                user_data["full_name"] = header.find_element(
                    By.XPATH, ".//h1 | .//span[contains(@class, '_aa_c')]").text.strip()
            except:
                self.logger.debug("Full name not extracted.")
            try:
                user_data["biography"] = header.find_element(
                    By.XPATH, ".//div[h1]/span | .//div/span[@class='_aa_c']//following-sibling::span").text.strip()
            except:
                self.logger.debug("Biography not extracted.")
            try:
                counts_text = ' '.join([el.text for el in header.find_elements(
                    By.XPATH, ".//li | .//div[contains(@class,'_ac2a')]") if el.text]).lower()

                def parse_count(t): n = t.lower().replace(',', ''); m = 1000000 if 'm' in n else (
                    1000 if 'k' in n else 1); n = n.replace('m', '').replace('k', ''); return int(float(n)*m)
                if m := re.search(r'([\d,km.]+)\s+posts?', counts_text):
                    user_data["media_count"] = parse_count(m.group(1))
                if m := re.search(
                        r'([\d,km.]+)\s+followers?', counts_text):
                    user_data["follower_count"] = parse_count(m.group(1))
                if m := re.search(r'([\d,km.]+)\s+following', counts_text):
                    user_data["following_count"] = parse_count(m.group(1))
            except Exception as e:
                self.logger.warning(f"Counts parsing error: {e}")
            try:
                header.find_element(
                    By.XPATH, ".//*[local-name()='svg'][@aria-label='Verified']")
                user_data["is_verified"] = True
            except:
                user_data["is_verified"] = False
            # ... Add extraction for External URL, Category,

            # Post Extraction (If Public)
            if not user_data["is_private"]:
                self.logger.debug("Extracting recent posts...")
                try:
                    post_container = wait.until(EC.presence_of_element_located(
                        (By.XPATH, "//div[contains(@class,'_aabd')] | //article//div[@style='display: flex; flex-direction: column;']")))
                    post_links = post_container.find_elements(
                        By.XPATH, ".//a[contains(@href, '/p/')]")[:12]
                    for link in post_links:
                        try:
                            url = link.get_attribute('href')
                            code = url.split(
                                '/p/')[1].split('/')[0] if url and '/p/' in url else None
                            thumb = None
                            try:
                                thumb = link.find_element(
                                    By.TAG_NAME, "img").get_attribute('src')
                            except:
                                pass
                            if code:
                                user_data["recent_posts"].append(
                                    {"url": url, "code": code, "thumbnail_url": thumb})
                        except Exception:
                            pass  # Ignore errors for single post link
                    self.logger.info(
                        f"Extracted {len(user_data['recent_posts'])} post links.")
                except Exception as e:
                    self.logger.warning(f"Post extraction error: {e}")
                if user_data["extraction_status"] == "pending":
                    user_data["extraction_status"] = "Completed (Public)"

            if user_data["extraction_status"] == "pending":
                user_data["extraction_status"] = "Completed (Unknown State)"
            self.logger.info(
                f"Data extraction finished with status: {user_data['extraction_status']}")
            return user_data

        except WebDriverException as e:
            self.logger.error(f"Extract WebDriver Error: {e}")
            self.close_driver()
            user_data["extraction_status"] = "WebDriver Error"
            return user_data
        except Exception as e:
            self.logger.error(f"Extract Unexpected Error: {e}", exc_info=True)
            user_data["extraction_status"] = "Unexpected Error"
            return user_data

    def close_driver(self):
        # Closes the WebDriver instance.
        if self.driver:
            proxy_in_use = self.current_proxy
            self.logger.debug(
                f"Closing WebDriver instance (Proxy: {proxy_in_use or 'Direct'})...")
            try:
                self.driver.quit()
                self.logger.info("WebDriver closed.")
            except WebDriverException as e:
                if "cannot determine loading status" not in str(e).lower():
                    self.logger.warning(f"Error closing WebDriver: {e}")
            except Exception as e:
                self.logger.warning(f"Unexpected error closing WebDriver: {e}")
            finally:
                try:
                    self.session.close()
                    self.logger.debug("Requests session closed.")
                except:
                    pass
                # Release proxy if tracking usage
                self.release_proxy(proxy_in_use)

    def close(self):
        # Cleans up resources.
        self.logger.info("Shutting down Manager...")
        self.close_driver()
        if self.session:
            try:
                self.session.close()
                self.logger.debug("Requests session closed.")
            except:
                pass
        self.logger.info("Cleanup complete.")
        logging.shutdown()

# === Graphical User Interface (Enhanced) ===


class EnhancedInstagramManagerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Enhanced Instagram Manager v2.6")
        # Geometry and styling from v2.5_fixed seems fine, reuse that.
        width = 1000
        height = 750
        sw = root.winfo_screenwidth()
        sh = root.winfo_screenheight()
        x = (sw//2)-(width//2)
        y = (sh//2)-(height//2)
        self.root.geometry(
            f"{width}x{height}+{x}+{y}")
        self.root.minsize(900, 650)
        # --- Theme Colors ---
        self.bg_color = "#2E2E2E"
        self.fg_color = "#EAEAEA"
        self.accent_color = "#C13584"
        self.secondary_color = "#5851DB"
        self.widget_bg = "#3C3C3C"
        self.widget_fg = "#FFFFFF"
        self.error_color = "#FF6B6B"
        self.success_color = "#6BCB77"
        self.log_text_bg = "#252525"
        self.log_color_debug = "grey60"
        self.log_color_info = "#EAEAEA"
        self.log_color_warning = "orange"
        # Specific GUI colors
        self.log_color_error = "#FF8080"
        self.log_color_critical = "#FF5050"
        self.root.configure(bg=self.bg_color)
        self.style = ttk.Style()
        try:
            self.style.theme_use('clam')
        except tk.TclError:
            logging.warning("Clam theme not found, using default.")
        # --- Styles --- (Reusing v2.5 style config)
        self.style.configure(".", background=self.bg_color, foreground=self.fg_color,
                             fieldbackground=self.widget_bg, insertcolor=self.widget_fg, font=("Segoe UI", 9))
        self.style.configure("TFrame", background=self.bg_color)
        self.style.configure(
            "TLabel", background=self.bg_color, foreground=self.fg_color)
        self.style.configure(
            "Header.TLabel", foreground=self.accent_color, font=("Segoe UI", 14, "bold"))
        self.style.configure(
            "Status.TLabel", foreground=self.secondary_color, font=("Segoe UI", 9))
        self.style.configure(
            "Error.TLabel", foreground=self.error_color, font=("Segoe UI", 9))
        self.style.configure(
            "Success.TLabel", foreground=self.success_color, font=("Segoe UI", 9))
        self.style.configure("TButton", background=self.accent_color, foreground=self.widget_fg, font=(
            "Segoe UI", 10, "bold"), borderwidth=1, padding=6)
        self.style.map("TButton", background=[
                       ('active', self.secondary_color)])
        self.style.configure(
            "TNotebook", background=self.bg_color, borderwidth=0)
        self.style.configure("TNotebook.Tab", background=self.widget_bg, foreground=self.fg_color, font=(
            "Segoe UI", 10), padding=[10, 5], borderwidth=0)
        self.style.map(
            "TNotebook.Tab", background=[("selected", self.secondary_color)], foreground=[("selected", self.widget_fg)], expand=[("selected", [1, 1, 1, 0])])
        self.style.configure(
            "TLabelframe", background=self.bg_color, borderwidth=1)
        self.style.configure("TLabelframe.Label", background=self.bg_color,
                             foreground=self.secondary_color, font=("Segoe UI", 10, "italic"))
        self.style.configure("TEntry", foreground=self.widget_fg,
                             fieldbackground=self.widget_bg, borderwidth=1)
        self.style.configure("TSpinbox", foreground=self.widget_fg,
                             fieldbackground=self.widget_bg, borderwidth=1)
        self.style.configure(
            "TCombobox", foreground=self.widget_fg, fieldbackground=self.widget_bg, borderwidth=1, arrowcolor=self.fg_color)
        self.style.configure("Horizontal.TProgressbar", troughcolor=self.widget_bg,
                             background=self.secondary_color, borderwidth=0)
        self.root.option_add('*TCombobox*Listbox.background', self.widget_bg)
        self.root.option_add('*TCombobox*Listbox.foreground', self.widget_fg)
        self.root.option_add('*TCombobox*Listbox.selectBackground',
                             self.secondary_color)
        self.root.option_add(
            '*TCombobox*Listbox.selectForeground', self.widget_fg)

        # --- Initialize Manager & Connect Logger ---
        self.log_queue = queue.Queue()
        # Basic config for early manager init
        logging.basicConfig(level=logging.INFO,
                            format='%(asctime)s - %(levelname)s - %(message)s')
        self.manager = EnhancedInstagramManager(log_queue=self.log_queue)
        self.logger = self.manager.logger  # Use manager's logger from now on

        # --- Main Layout ---
        self.main_frame = ttk.Frame(self.root, padding="10")
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        header_frame = ttk.Frame(self.main_frame)
        header_frame.pack(fill=tk.X, pady=(0, 10))
        ttk.Label(
            header_frame, text="Enhanced Instagram Manager v2.6", style="Header.TLabel").pack(side=tk.LEFT)
        self.tab_control = ttk.Notebook(self.main_frame)
        self.account_tab = ttk.Frame(self.tab_control, padding="10")
        self.report_tab = ttk.Frame(self.tab_control, padding="10")
        self.data_tab = ttk.Frame(self.tab_control, padding="10")
        self.settings_tab = ttk.Frame(self.tab_control, padding="10")
        self.tab_control.add(self.account_tab, text=" Accounts ")
        self.tab_control.add(self.report_tab, text=" Reporting ")
        self.tab_control.add(self.data_tab, text=" Data Extraction ")
        self.tab_control.add(self.settings_tab, text=" Settings & Log ")
        self.tab_control.pack(fill=tk.BOTH, expand=True, pady=5)

        # Status Bar
        self.status_var = tk.StringVar()
        self.status_var.set("Initializing...")
        self.status_bar = ttk.Label(self.root, textvariable=self.status_var,
                                    style="Status.TLabel", relief=tk.SUNKEN, anchor=tk.W, padding=(5, 2))
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

        # --- Setup Tab Content ---
        # Need access to widgets in other methods, so call them here.
        # Define widget variables within setup methods if only used there.
        self._action_buttons = []  # Store buttons to enable/disable
        self.setup_account_tab()
        self.setup_report_tab()
        self.setup_data_tab()
        self.setup_settings_tab()

        # --- Final Init ---
        self.update_account_listbox()
        self.enable_actions(False)  # Start disabled
        # Check sooner if proxies available
        self.root.after(500, self.check_proxy_readiness)
        self.update_log_display()  # Start log polling
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.setup_error_handling()  # Global handler

        self.logger.info("GUI Initialized.")

    # --- GUI Helper: Enable/Disable Network Actions ---
    def enable_actions(self, enable=True):
        # Enable/disable buttons stored in self._action_buttons
        state = tk.NORMAL if enable else tk.DISABLED
        self.logger.debug(
            f"Setting action button state to: {'ENABLED' if enable else 'DISABLED'}")
        for btn in self._action_buttons:
            try:
                if btn and btn.winfo_exists():
                    btn.config(state=state)
            except tk.TclError:
                pass  # Widget might be destroyed
            except Exception as e:
                self.logger.warning(f"Error toggling button state: {e}")

    # --- GUI Setup Methods (Store action buttons) ---

    def setup_account_tab(self):
        # (Setup layout as before, but add buttons to self._action_buttons)
        create_frame = ttk.LabelFrame(
            self.account_tab, text="Create Account", padding="10")
        create_frame.pack(fill=tk.X, pady=(
            0, 10))
        create_frame.columnconfigure(1, weight=1)
        ttk.Label(create_frame, text="Email (opt):").grid(
            row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.acc_email_var = tk.StringVar()
        ttk.Entry(create_frame,
                  textvariable=self.acc_email_var).grid(row=0, column=1, padx=5, pady=5, sticky=tk.EW)
        ttk.Label(create_frame, text="Username (opt):").grid(
            row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.acc_username_var = tk.StringVar()
        ttk.Entry(create_frame,
                  textvariable=self.acc_username_var).grid(row=1, column=1, padx=5, pady=5, sticky=tk.EW)
        ttk.Label(create_frame, text="Password (opt):").grid(
            row=2, column=0, padx=5, pady=5, sticky=tk.W)
        self.acc_password_var = tk.StringVar()
        ttk.Entry(create_frame, textvariable=self.acc_password_var,
                  show="*").grid(row=2, column=1, padx=5, pady=5, sticky=tk.EW)
        btn_frame = ttk.Frame(create_frame)
        btn_frame.grid(row=3, column=0, columnspan=2, pady=10, sticky=tk.W)
        btn_create_specific = ttk.Button(
            btn_frame, text="Create with Details", command=self.create_specific_account_gui)
        btn_create_specific.pack(side=tk.LEFT, padx=(0, 10))
        btn_create_random = ttk.Button(
            btn_frame, text="Create Random Account", command=self.create_random_account_gui)
        btn_create_random.pack(side=tk.LEFT, padx=5)
        self._action_buttons.extend([btn_create_specific, btn_create_random])

        list_frame = ttk.LabelFrame(
            self.account_tab, text="Account Management", padding="10")
        list_frame.pack(fill=tk.BOTH, expand=True)
        list_frame.grid_rowconfigure(
            0, weight=1)
        list_frame.grid_columnconfigure(0, weight=1)
        self.account_listbox = tk.Listbox(list_frame, 
                                          background=self.widget_bg, 
                                          fg=self.widget_fg, 
                                          selectbackground=self.secondary_color, 
                                          selectforeground=self.widget_fg,
                                          borderwidth=0, 
                                          highlightthickness=1, 
                                          highlightbackground=self.secondary_color, 
                                          exportselection=False, 
                                          font=("Segoe UI", 9))
        scrollbar = ttk.Scrollbar(
            list_frame, orient=tk.VERTICAL, command=self.account_listbox.yview)
        self.account_listbox.configure(yscrollcommand=scrollbar.set)
        self.account_listbox.grid(
            row=0, column=0, sticky="nsew", padx=(0, 5))
        scrollbar.grid(row=0, column=1, sticky="ns")
        action_frame = ttk.Frame(list_frame)
        action_frame.grid(row=1, column=0, columnspan=2,
                          sticky="ew", pady=(10, 0))
        btn_login_sel = ttk.Button(
            action_frame, text="Login with Selected", command=self.login_selected_account_gui)
        btn_login_sel.pack(side=tk.LEFT, padx=(0, 10))
        # Keep remove/export enabled always
        ttk.Button(action_frame, text="Remove Selected",
                   command=self.remove_selected_account_gui).pack(side=tk.LEFT, padx=5)
        ttk.Button(action_frame, text="Export All Accounts",
                   command=self.export_accounts_gui).pack(side=tk.RIGHT, padx=5)
        self._action_buttons.append(btn_login_sel)

    def setup_report_tab(self):
        # (Setup layout as before, add buttons to self._action_buttons)
        single_report_frame = ttk.LabelFrame(
            self.report_tab, text="Single Report", padding="10")
        single_report_frame.pack(fill=tk.X, pady=(0, 15))
        single_report_frame.columnconfigure(1, weight=1)
        ttk.Label(single_report_frame, text="Target Username:").grid(
            row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.report_target_var = tk.StringVar()
        ttk.Entry(single_report_frame,
                  textvariable=self.report_target_var).grid(row=0, column=1, padx=5, pady=5, sticky=tk.EW)
        ttk.Label(single_report_frame, text="Report Reason:").grid(
            row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.report_reason_var = tk.StringVar()
        reasons = ["spam", "scam or fraud", "hate speech", "impersonation", "self-injury", "nudity or sexual activity",
                   "violence", "bullying or harassment", "intellectual property", "false information", "other"]
        self.report_reason_var.set(reasons[0])
        self.report_reason_combo = ttk.Combobox(
            single_report_frame, textvariable=self.report_reason_var, values=reasons, state="readonly")
        self.report_reason_combo.grid(
            row=1, column=1, padx=5, pady=5, sticky=tk.EW)
        btn_frame = ttk.Frame(single_report_frame)
        btn_frame.grid(row=2, column=0, columnspan=2, pady=10)
        btn_report = ttk.Button(
            btn_frame, text="Report Target (using current login)", command=self.report_account_gui)
        btn_report.pack()
        self._action_buttons.append(btn_report)

        mass_frame = ttk.LabelFrame(
            self.report_tab, text="Mass Reporting ('Bots')", padding="10")
        mass_frame.pack(fill=tk.BOTH, expand=True,
                        pady=10)
        mass_frame.columnconfigure(1, weight=1)
        ttk.Label(mass_frame, text="(Uses Target/Reason above. Runs concurrently up to limit set below.)",
                  font=("Segoe UI", 8, "italic")).grid(row=0, column=0, columnspan=2, pady=(0, 5), sticky=tk.W)
        ttk.Label(mass_frame, text="Accounts to Use:").grid(
            row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.mass_num_accounts_var = tk.IntVar()
        max_acc = max(1, len(self.manager.accounts))
        self.mass_num_accounts_var.set(min(5, max_acc))
        self.mass_num_accounts_spinbox = ttk.Spinbox(
            mass_frame, from_=1, to=max_acc, textvariable=self.mass_num_accounts_var, width=5, state="readonly")
        self.mass_num_accounts_spinbox.grid(
            row=1, column=1, padx=5, pady=5, sticky=tk.W)
        ttk.Label(mass_frame, text="Max Concurrent 'Bots':").grid(
            row=2, column=0, padx=5, pady=5, sticky=tk.W)
        self.mass_max_workers_var = tk.IntVar(
            value=self.manager.settings.get("max_mass_report_workers", 5))
        ttk.Spinbox(mass_frame, from_=1, to=20, textvariable=self.mass_max_workers_var, width=5, state="readonly").grid(
            row=2, column=1, padx=5, pady=5, sticky=tk.W)  # Allow up to 20 concurrent
        # ttk.Label(mass_frame, text="Delay between Bots (sec):").grid(row=3, column=0, padx=5, pady=5, sticky=tk.W); self.mass_delay_var=tk.IntVar(); self.mass_delay_var.set(random.randint(5,15)) # Delay between LAUNCHING bots
        # ttk.Spinbox(mass_frame, from_=1, to=60, textvariable=self.mass_delay_var, width=5).grid(row=3, column=1, padx=5, pady=5, sticky=tk.W)
        btn_frame_mass = ttk.Frame(mass_frame)
        btn_frame_mass.grid(row=4, column=0, columnspan=2, pady=10)
        btn_mass_report = ttk.Button(
            btn_frame_mass, text="Start Mass Report", command=self.start_mass_report_gui)
        btn_mass_report.pack()
        self._action_buttons.append(btn_mass_report)

    def setup_data_tab(self):
        # (Setup layout as before, add button to self._action_buttons)
        target_frame = ttk.Frame(self.data_tab)
        target_frame.pack(fill=tk.X, pady=(
            0, 10))
        target_frame.columnconfigure(1, weight=1)
        ttk.Label(target_frame, text="Target Username:").grid(
            row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.data_target_var = tk.StringVar()
        ttk.Entry(target_frame,
                  textvariable=self.data_target_var).grid(row=0, column=1, padx=5, pady=5, sticky=tk.EW)
        btn_frame = ttk.Frame(self.data_tab)
        btn_frame.pack(pady=5)
        btn_extract = ttk.Button(
            btn_frame, text="Extract Visible User Data (using current login)", command=self.extract_user_data_gui)
        btn_extract.pack()
        self._action_buttons.append(btn_extract)
        results_frame = ttk.LabelFrame(
            self.data_tab, text="Extraction Results", padding="10")
        results_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        results_frame.rowconfigure(
            0, weight=1)
        results_frame.columnconfigure(0, weight=1)
        self.data_results_text = scrolledtext.ScrolledText(results_frame, wrap=tk.WORD, background=self.widget_bg, fg=self.widget_fg, insertbackground=self.widget_fg, font=(
            "Consolas", 9), borderwidth=0, relief=tk.FLAT, state=tk.DISABLED)
        self.data_results_text.grid(
            row=0, column=0, columnspan=2, sticky="nsew", pady=(0, 10))
        btn_frame_res = ttk.Frame(results_frame)
        btn_frame_res.grid(row=1, column=0, columnspan=2, sticky=tk.E)
        ttk.Button(btn_frame_res, text="Export Results to JSON",
                   command=self.export_user_data_gui).pack(side=tk.RIGHT, padx=5, pady=5)

    def setup_settings_tab(self):
        # 1. Main Frame
        tab_content_frame = ttk.Frame(self.settings_tab)
        tab_content_frame.pack(fill=tk.BOTH, expand=True)
        tab_content_frame.grid_rowconfigure(0, weight=1)
        tab_content_frame.grid_columnconfigure(0, weight=1)
        # 2. Canvas
        canvas = tk.Canvas(tab_content_frame,
                           bg=self.bg_color, highlightthickness=0)
        # 3. Scrollbar
        scrollbar = ttk.Scrollbar(
            tab_content_frame, orient=tk.VERTICAL, command=canvas.yview)
        canvas.configure(yscrollcommand=scrollbar.set)
        # 4. Scrollable Frame (Content goes here!)
        scrollable_frame = ttk.Frame(canvas)
        scrollable_frame.columnconfigure(0, weight=1)
        # 5. Link Frame to Canvas
        canvas_window = canvas.create_window(
            (0, 0), window=scrollable_frame, anchor="nw")
        # 6. Bindings for resize/scroll

        def configure_scrollregion(e): canvas.configure(
            scrollregion=canvas.bbox("all"))
        scrollable_frame.bind("<Configure>", configure_scrollregion)

        def configure_frame_width(e): canvas.itemconfig(
            canvas_window, width=e.width)
        canvas.bind("<Configure>", configure_frame_width)
        def on_mousewheel(e): delta = 0; d = e.delta; n = e.num; delta = -1 if (n == 4 or d > 0) else (
            1 if (n == 5 or d < 0) else 0); canvas.yview_scroll(delta, "units") if delta else None
        for seq in ("<MouseWheel>", "<Button-4>", "<Button-5>"):
            # Simpler bind_all approach for robustness
            canvas.bind_all(seq, on_mousewheel)

        # Grid Canvas/Scrollbar
        canvas.grid(row=0, column=0, sticky="nsew")
        scrollbar.grid(row=0, column=1, sticky="ns")

        # --- Proxy Settings ---
        pf = ttk.LabelFrame(
            scrollable_frame, text="Proxy Settings", padding="10")
        pf.pack(fill=tk.X, pady=(5, 10), padx=10)
        pf.columnconfigure(1, weight=1)
        self.proxy_count_var = tk.StringVar(value="Proxies: Init...")
        ttk.Label(pf, textvariable=self.proxy_count_var).grid(
            row=0, column=0, padx=(0, 10), pady=5, sticky=tk.W)
        self.proxy_verify_status_var = tk.StringVar(value="")
        ttk.Label(pf, textvariable=self.proxy_verify_status_var, style="Status.TLabel",
                  wraplength=300).grid(row=0, column=1, padx=5, pady=2, sticky=tk.EW)
        self.proxy_progress = ttk.Progressbar(
            pf, orient=tk.HORIZONTAL, length=150, mode='determinate', style="Horizontal.TProgressbar")
        self.proxy_progress.grid(row=0, column=2, padx=(10, 0), pady=5, sticky=tk.E)
        self.proxy_progress.grid_remove()
        btn_refresh_proxy = ttk.Button(pf, text="Refresh Public Proxies", command=self.refresh_proxies_gui)
        
        # Note: MUST define refresh_proxies_gui
        btn_refresh_proxy.grid(
            row=1, column=0, columnspan=3, pady=5, sticky=tk.W)
        # Allow enabling this after init check maybe?
        self._action_buttons.append(btn_refresh_proxy)
        mpf = ttk.Frame(pf)
        mpf.grid(row=2, column=0, columnspan=3, sticky=tk.EW,
                 pady=(5, 0))
        mpf.columnconfigure(1, weight=1)
        ttk.Label(mpf, text="Add Proxy (IP:Port):").grid(
            row=0, column=0, padx=(0, 5), pady=5, sticky=tk.W)
        self.manual_proxy_var = tk.StringVar()
        ttk.Entry(mpf, textvariable=self.manual_proxy_var).grid(
            row=0, column=1, padx=5, pady=5, sticky=tk.EW)
        btn_add_proxy = ttk.Button(
            mpf, text="Verify & Add", width=12, command=self.add_manual_proxy_gui)
        btn_add_proxy.grid(row=0, column=2, padx=(5, 0), pady=5)
        # self._action_buttons.append(btn_add_proxy) # Keep Add button always enabled

        # --- Browser & Driver ---
        bdf = ttk.LabelFrame(
            scrollable_frame, text="Browser & Driver Settings", padding="10")
        bdf.pack(fill=tk.X, pady=10, padx=10)
        bdf.columnconfigure(1, weight=1)
        ttk.Label(bdf, text="Browser Type:").grid(
            row=0, column=0, padx=(0, 5), pady=5, sticky=tk.W)
        self.browser_type_var = tk.StringVar(
            value=self.manager.settings.get("browser_type", "chrome"))
        ttk.Combobox(
            bdf, textvariable=self.browser_type_var, values=["chrome"], state="readonly").grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)
        ttk.Label(bdf, text="Chrome/Chromium Binary (Opt):").grid(row=1,
                                                                  column=0, padx=(0, 5), pady=5, sticky=tk.W)
        self.chrome_binary_path_var = tk.StringVar(
            value=self.manager.settings.get("chrome_binary_path", ""))
        ttk.Entry(bdf, textvariable=self.chrome_binary_path_var, width=50).grid(
            row=1, column=1, padx=5, pady=5, sticky=tk.EW)
        ttk.Button(bdf, text="Browse...", command=self._browse_chrome_binary_path_gui).grid(
            row=1, column=2, padx=(5, 0), pady=5)
        ttk.Label(bdf, text="ChromeDriver Path (Opt):").grid(
            row=2, column=0, padx=(0, 5), pady=5, sticky=tk.W)
        self.chrome_driver_path_var = tk.StringVar(
            value=self.manager.settings.get("chrome_driver_path", ""))
        ttk.Entry(bdf, textvariable=self.chrome_driver_path_var, width=50).grid(
            row=2, column=1, padx=5, pady=5, sticky=tk.EW)
        ttk.Button(
            bdf, text="Browse...", command=self._browse_chrome_driver_path_gui).grid(row=2, column=2, padx=(5, 0), pady=5)
        ttk.Button(bdf, text="?", width=2, command=self.show_chromedriver_help_gui).grid(
            row=2, column=3, padx=(2, 0), pady=5)
        ttk.Label(bdf, text="Leave blank to use WebDriver Manager.", font=(
            "Segoe UI", 8, "italic")).grid(row=3, column=1, columnspan=2, sticky=tk.W, padx=5)

        # --- General Settings ---
        gsf = ttk.LabelFrame(
            scrollable_frame, text="General Settings", padding="10")
        gsf.pack(fill=tk.X, pady=10, padx=10)
        self.headless_var = tk.BooleanVar(
            value=self.manager.settings.get("headless", True))
        ttk.Checkbutton(gsf, text="Run Headless",
                        variable=self.headless_var).pack(anchor=tk.W, pady=2)
        self.stealth_var = tk.BooleanVar(
            value=self.manager.settings.get("enable_stealth", True))
        ttk.Checkbutton(gsf, text="Enable Selenium Stealth",
                        variable=self.stealth_var).pack(anchor=tk.W, pady=2)
        self.screenshot_var = tk.BooleanVar(
            value=self.manager.settings.get("save_screenshots", False))
        ttk.Checkbutton(gsf, text="Save Screenshots on Errors",
                        variable=self.screenshot_var).pack(anchor=tk.W, pady=2)
        self.debug_mode_var = tk.BooleanVar(
            value=self.manager.settings.get("debug_mode", False))
        ttk.Checkbutton(gsf, text="Enable Debug Logging", variable=self.debug_mode_var,
                        command=self.update_log_level_gui).pack(anchor=tk.W, pady=2)

        # --- Reporting Limits ---
        rsf = ttk.LabelFrame(
            scrollable_frame, text="Reporting Limits", padding="10")
        rsf.pack(fill=tk.X, pady=10, padx=10)
        rsf.columnconfigure(
            1, weight=0)
        rsf.columnconfigure(3, weight=0)
        ttk.Label(rsf, text="Max Reports/Day/Acc:").grid(row=0,
                                                         column=0, padx=(0, 5), pady=5, sticky=tk.W)
        self.max_reports_var = tk.IntVar(
            value=self.manager.settings.get("max_reports_per_day", 15))
        ttk.Spinbox(
            rsf, from_=1, to=100, textvariable=self.max_reports_var, width=5, state="readonly").grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)
        ttk.Label(rsf, text="Min Interval (sec):").grid(
            row=0, column=2, padx=(15, 5), pady=5, sticky=tk.W)
        self.interval_var = tk.IntVar(
            value=self.manager.settings.get("report_interval_seconds", 1800))
        ttk.Spinbox(
            rsf, from_=60, to=86400, increment=60, textvariable=self.interval_var, width=7, state="readonly").grid(row=0, column=3, padx=5, pady=5, sticky=tk.W)

        # --- Save Settings Button ---
        sbf = ttk.Frame(scrollable_frame)
        sbf.pack(pady=(15, 5), padx=10)
        ttk.Button(sbf, text="Save All Settings",
                   command=self.save_settings_gui).pack()

        # --- Log Console ---
        lcf = ttk.LabelFrame(
            scrollable_frame, text="Activity Log", padding="5")
        lcf.pack(fill=tk.BOTH, expand=True, pady=(
            10, 10), padx=10)  # Expand AND Fill Both
        self.log_console_text = scrolledtext.ScrolledText(lcf, wrap=tk.WORD, bg=self.log_text_bg, fg=self.fg_color, insertbackground=self.widget_fg, font=(
            "Consolas", 9), borderwidth=0, relief=tk.FLAT, height=10, state=tk.DISABLED)
        self.log_console_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        # Add Tag configurations for log colors
        self.log_console_text.tag_config(
            GUI_LOG_TAGS[logging.DEBUG], foreground=self.log_color_debug)
        self.log_console_text.tag_config(
            GUI_LOG_TAGS[logging.INFO], foreground=self.log_color_info)
        self.log_console_text.tag_config(
            GUI_LOG_TAGS[logging.WARNING], foreground=self.log_color_warning)
        self.log_console_text.tag_config(
            GUI_LOG_TAGS[logging.ERROR], foreground=self.log_color_error, font=("Consolas", 9, "bold"))
        self.log_console_text.tag_config(
            GUI_LOG_TAGS[logging.CRITICAL], foreground=self.log_color_critical, font=("Consolas", 9, "bold"))

        # --- Clear Log Button ---
        # Place inside the log frame for proximity
        clear_btn_frame = ttk.Frame(lcf)
        clear_btn_frame.pack(fill=tk.X, padx=5, pady=(0, 5)
                             )  # Pack below the text area
        ttk.Button(clear_btn_frame, text="Clear Log Display",
                   # Align right
                   command=self.clear_log_display_gui).pack(side=tk.RIGHT)
    
    def update_log_display(self):
        """Poll the log queue and update the GUI log console."""
        try:
            if not hasattr(self, 'log_console_text') or not self.log_console_text.winfo_exists():
                self.root.after(250, self.update_log_display)
                return

            max_lines = 50
            count = 0
            while not self.log_queue.empty() and count < max_lines:
                try:
                    levelno, message = self.log_queue.get_nowait()
                    tag = GUI_LOG_TAGS.get(levelno, "log_info")

                    self.log_console_text.config(state=tk.NORMAL)
                    self.log_console_text.insert(tk.END, message + "\n", tag)
                    self.log_console_text.see(tk.END)
                    self.log_console_text.config(state=tk.DISABLED)
                    count += 1
                except queue.Empty:
                    break
                except Exception as e:
                    print(f"Log display error: {e}")
                    break
        except Exception as e:
            print(f"Log update error: {e}")
        finally:
            if hasattr(self, 'root') and self.root.winfo_exists():
                self.root.after(150, self.update_log_display)

    # --- Utility and Update Methods ---

    def update_status(self, message, level="info"):  # Keep previous implementation
        if not hasattr(self, 'status_var') or not self.root.winfo_exists():
            return
        try:
            self.status_var.set(message)
            style = {"error": "Error.TLabel", "success": "Success.TLabel",
                     "warning": "Error.TLabel"}.get(level, "Status.TLabel")
            self.status_bar.configure(style=style)
            self.root.update_idletasks()
        except Exception as e:
            print(f"GUI Status Update Error: {e}")

    def update_log_level_gui(self):  # Keep previous implementation
        new_level = logging.DEBUG if self.debug_mode_var.get() else logging.INFO
        if self.manager.logger.level != new_level:
            self.manager.settings["debug_mode"] = self.debug_mode_var.get()
            self.manager.setup_logging()
            self.logger.info(
                f"Log level set to {logging.getLevelName(new_level)}")
    # Polls queue and updates GUI console with colors
        try:
            if not hasattr(self, 'log_console_text') or not self.log_console_text.winfo_exists():
                self.root.after(250, self.update_log_display)
                return

            max_lines_to_process = 50  # Process in batches to prevent blocking GUI
            count = 0
            while not self.log_queue.empty() and count < max_lines_to_process:
                try:
                    levelno, message = self.log_queue.get_nowait()  # Get tuple (level, message)
                    # Get tag name based on level
                    tag = GUI_LOG_TAGS.get(levelno, None)
                    self.log_console_text.config(state=tk.NORMAL)
                    self.log_console_text.insert(
                        tk.END, message + "\n", tag)  # Apply tag on insert
                    self.log_console_text.see(tk.END)
                    self.log_console_text.config(state=tk.DISABLED)
                    count += 1
                except queue.Empty:
                    break
                except tk.TclError as e:
                    if "destroyed" in str(e):
                        return
                    else:
                        print(f"GUI log TkErr: {e}")
                        break
                except Exception as e:
                    print(f"GUI log Err: {e}")
                    break
        finally:
            if self.root.winfo_exists():
                self.root.after(150, self.update_log_display)

    def clear_log_display_gui(self):
        # Clears the log console text widget
        try:
            if self.log_console_text and self.log_console_text.winfo_exists():
                self.log_console_text.config(state=tk.NORMAL)
                self.log_console_text.delete(1.0, tk.END)
                self.log_console_text.config(state=tk.DISABLED)
                self.logger.info("Log display cleared.")
        except Exception as e:
            self.logger.error(f"Failed to clear log display: {e}")

    def check_proxy_readiness(self):
        # Checks if first proxy is available, enables actions
        # Renamed from check_proxy_load_status for clarity on function
        if self.manager.first_proxy_available.is_set():
            self.logger.info("First proxy/direct connection is available.")
            # Check if the queue or final list actually contains something usable
            # Is the final list populated?
            proxies_list_ok = bool(self.manager.proxies)
            queue_ok = not self.manager.verified_proxies_queue.empty()
            if proxies_list_ok or queue_ok:
                self.enable_actions(True)
                # Show approximate count if only queue used so far
                count = len(self.manager.proxies) if proxies_list_ok else "~"
                options = self.manager.proxies if proxies_list_ok else [
                    "(Checking...)"]
                self.update_status(
                    f"Ready. {count} connection option(s) available.", "success")
                self.logger.info(
                    f"Enabling actions. Available options sample: {options[:5]}")
                # Update count label once fully loaded if not already
                if not proxies_list_ok and self.manager.proxy_load_thread.is_alive():
                    # If still loading, schedule another update later
                    # Update final count after 5s
                    self.root.after(5000, self._update_proxy_count_gui)
                else:
                    self._update_proxy_count_gui()  # Update final count now if thread finished
            else:
                self.logger.error(
                    "Proxy availability event was set, but no proxies available in queue or list!")
                self.enable_actions(False)
                self.update_status(
                    "ERROR: Proxy check finished, but NO options available!", "error")
                messagebox.showerror(
                    "Network Error", "Proxy verification completed, but no working proxy or direct connection was found. Network actions are disabled.")
                self._update_proxy_count_gui()  # Show 0
        else:
            self.logger.debug("Waiting for first proxy/direct connection...")
            self.update_status(
                "Waiting for usable proxy/direct connection...", "info")
            # Re-check in 1 second
            self.root.after(1000, self.check_proxy_readiness)

    def setup_error_handling(self):  # Keep implementation from v2.5_fixed
        original_excepthook = sys.excepthook

        def handle_exception(exc_type, exc_value, exc_traceback):
            log_message = "".join(traceback.format_exception(
                exc_type, exc_value, exc_traceback))
            if hasattr(self, 'logger'):
                self.logger.critical(f"Unhandled Exception:\n{log_message}")
            else:
                print(
                    f"Unhandled Exception (Logger unavailable):\n{log_message}", file=sys.stderr)
            try:
                messagebox.showerror(
                    "Unhandled Application Error", f"Critical error:\n\n{exc_type.__name__}: {exc_value}\n\nCheck logs. App might close.")
            except:
                pass  # Avoid error if Tkinter gone
        sys.excepthook = handle_exception
        self.logger.debug("Global exception handler set up.")

    # --- Account Tab Actions (Check readiness before run) ---

    # Keep implementation from v2.5_fixed
    def _run_in_thread(self, target_func, args=(), callback=None):
        def thread_wrapper():
            result, error = None, None
            try:
                result = target_func(*args)
            except Exception as e:
                self.logger.error(
                    f"Thread Err ({target_func.__name__}): {e}", exc_info=True)
                error = e
            finally:
                if callback and self.root.winfo_exists():
                    self.root.after(0, lambda r=result,
                                    err=error: callback(r, err))
        thread = threading.Thread(target=thread_wrapper, daemon=True)
        thread.start()

    def _ensure_network_ready(self):
        # Check if any proxy option is available before network action
        if not self.manager.proxies and self.manager.verified_proxies_queue.empty():
            # Maybe wait briefly again? Or just error out.
            # Short wait
            if not self.manager.first_proxy_available.wait(timeout=0.5):
                messagebox.showerror(
                    "Network Error", "No proxy/direct connection ready. Please wait or check settings/network.")
                self.update_status(
                    "Action failed: No network ready.", "error")
                return False
            elif not self.manager.proxies and self.manager.verified_proxies_queue.empty():
                # Even after wait, still nothing.
                messagebox.showerror(
                    "Network Error", "No proxy/direct connection ready. Please wait or check settings/network.")
                self.update_status(
                    "Action failed: No network ready.", "error")
                return False

    def create_specific_account_gui(self):
        if not self._ensure_network_ready():
            return  # Check before running
        email = self.acc_email_var.get().strip() or None
        username = self.acc_username_var.get().strip() or None
        password = self.acc_password_var.get().strip() or None
        if not email and not username and not password:
            self.create_random_account_gui()
            return  # Use random if all empty
        self.update_status("Creating specific account...", "info")
        self._run_in_thread(self.manager.create_temporary_account, args=(
            email, username, password), callback=self._update_after_account_creation_gui)

    def create_random_account_gui(self):
        if not self._ensure_network_ready():
            return  # Check before running
        self.update_status("Creating random account...", "info")
        self.acc_email_var.set("")
        self.acc_username_var.set("")
        self.acc_password_var.set("")
        self._run_in_thread(self.manager.create_temporary_account, args=(
            None, None, None), callback=self._update_after_account_creation_gui)

    # Keep implementation from v2.5_fixed
    def _update_after_account_creation_gui(self, account_info, error):
        if error:
            self.update_status(f"Account creation failed: {error}", "error")
        elif account_info:
            self.update_account_listbox()
            status_msg = f"Account '{account_info['username']}' created (Status: {account_info['status']})."
            lvl = "success" if account_info['status'] == 'active' else "warning"
            self.update_status(status_msg, lvl)
        else:
            self.update_status(
                "Account creation failed (check logs).", "error")

    # Keep implementation from v2.5_fixed (color coding included)
    def update_account_listbox(self):
        if not hasattr(self, 'account_listbox') or not self.root.winfo_exists():
            return
        try:
            sel = self.account_listbox.curselection()
            self.account_listbox.config(state=tk.NORMAL)
            self.account_listbox.delete(0, tk.END)
            for i, acc in enumerate(self.manager.accounts):
                status = acc.get("status", "?")
                reports = acc.get("reports_made", 0)
                display = f"{acc.get('username', 'N/A')} ({status}) - R:{reports}"
                self.account_listbox.insert(tk.END, display)
                color = self.error_color if status in ["banned", "login_failed", "locked"] else (self.secondary_color if status in [
                                                                                                 "challenge", "needs_verification"] else (self.success_color if status == "active" else self.widget_fg))
                self.account_listbox.itemconfig(i, {'fg': color})
            if sel and sel[0] < self.account_listbox.size():
                self.account_listbox.selection_set(sel[0])
                self.account_listbox.activate(sel[0])
                self.account_listbox.see(sel[0])
            max_a = max(1, len(self.manager.accounts))
            if hasattr(self, 'mass_num_accounts_spinbox') and self.mass_num_accounts_spinbox.winfo_exists():
                self.mass_num_accounts_spinbox.config(to=max_a)
                self.mass_num_accounts_var.set(
                    min(self.mass_num_accounts_var.get(), max_a))
        except Exception as e:
            self.logger.error(f"Listbox update failed: {e}")

    def get_selected_account_gui(self):  # Keep implementation from v2.5_fixed
        if not hasattr(self, 'account_listbox') or not self.root.winfo_exists():
            return None
        try:
            idx = self.account_listbox.curselection()
            if not idx:
                messagebox.showwarning(
                    "Selection Error", "Select an account first.")
                return None
            if 0 <= idx[0] < len(self.manager.accounts):
                return self.manager.accounts[idx[0]]
            else:
                messagebox.showerror("Error", "Invalid selection index.")
                return None
        except Exception as e:
            messagebox.showerror("Error", f"Get selected account error:\n{e}")
            return None

    def login_selected_account_gui(self):  # Added readiness check
        if not self._ensure_network_ready():
            return
        account = self.get_selected_account_gui()
        if not account:
            return
        if self.manager.driver and self.manager.current_account and self.manager.current_account['username'] == account['username']:
            messagebox.showinfo("Already Logged In",
                                f"Already logged in as {account['username']}.")
            return
        if self.manager.driver and not messagebox.askyesno("Confirm Login", f"Logged in as {self.manager.current_account['username']}.\nClose session and log in as {account['username']}?"):
            return
        elif self.manager.driver:
            self.manager.close_driver()
        self.update_status(f"Logging in as {account['username']}...", "info")
        self._run_in_thread(self.manager.login, args=(
            account,), callback=self._update_after_login_gui)

    # Keep implementation from v2.5_fixed
    def _update_after_login_gui(self, login_success, error):
        user = self.manager.current_account.get(
            'username', 'selected') if self.manager.current_account else 'selected'
        if error:
            self.update_status(f"Login error for {user}: {error}", "error")
            messagebox.showerror(
                "Login Error", f"Error logging in as {user}:\n{error}")
            self.update_account_listbox()
        elif login_success:
            self.update_status(f"Logged in as {user}. Ready.", "success")
            self.update_account_listbox()
        else:
            status = self.manager.current_account.get(
                'status', 'failed') if self.manager.current_account else 'failed'
            fail_reason = f"Login failed for {user}. Reason: {status}."
            self.update_status(fail_reason, "error")
            messagebox.showerror(
                "Login Failed", fail_reason)
            self.update_account_listbox()

    # Keep implementation from v2.5_fixed
    def remove_selected_account_gui(self):
        acc = self.get_selected_account_gui()
        if not acc:
            return
        user = acc.get('username', 'N/A')
        if not messagebox.askyesno("Confirm", f"Remove '{user}'? (Removes from list only, save/export to persist)"):
            return
        try:
            self.manager.accounts.remove(acc)
            self.logger.info(f"Removed account '{user}'.")
            self.update_account_listbox()
            self.update_status(
                f"Account removed: {user}", "info")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to remove: {e}")

    def export_accounts_gui(self):  # Keep implementation from v2.5_fixed
        if not self.manager.accounts:
            messagebox.showinfo("Export", "No accounts to export.")
            return
        fp = filedialog.asksaveasfilename(defaultextension=".csv", initialfile=f"ig_accounts_{time.strftime('%Y%m%d')}.csv", filetypes=[
                                          ("CSV", "*.csv")], title="Save Accounts")
        if not fp:
            return
        try:
            std = ["username", "email", "password", "status", "created_at",
                   "reports_made", "last_report_time", "proxy_used", "user_agent"]
            keys = set(k for a in self.manager.accounts for k in a.keys())
            fields = [f for f in std if f in keys] + \
                [f for f in sorted(keys) if f not in std]
            with open(fp, "w", newline="", encoding='utf-8') as f:
                writer = csv.DictWriter(
                    f, fieldnames=fields, extrasaction='ignore')
                writer.writeheader()
                for acc in self.manager.accounts:
                    row = acc.copy()
                    try:
                        row["created_at"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(
                            float(acc.get("created_at", 0)))) if acc.get("created_at") else ""
                    except:
                        row["created_at"] = ""
                    try:
                        row["last_report_time"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(
                            float(acc.get("last_report_time", 0)))) if acc.get("last_report_time") else ""
                    except:
                        row["last_report_time"] = ""
                    writer.writerow(row)
            messagebox.showinfo(
                "Success", f"Exported {len(self.manager.accounts)} accounts to {os.path.basename(fp)}")
            self.update_status("Accounts exported.", "success")
        except Exception as e:
            messagebox.showerror("Error", f"Export failed: {e}")
            self.update_status("Export failed.", "error")

    # --- Report Tab Actions (Added readiness check, concurrent mass report) ---

    def report_account_gui(self):
        if not self._ensure_network_ready():
            return  # Check readiness
        target = self.report_target_var.get().strip()
        reason = self.report_reason_var.get()
        if not target:
            messagebox.showerror("Input Error", "Target Username empty.")
            return
        if not self.manager.driver or not self.manager.current_account:
            messagebox.showwarning(
                "Login Required", "Login via 'Accounts' tab first.")
            self.tab_control.select(self.account_tab)
            return
        user = self.manager.current_account['username']
        self.update_status(
            f"'{user}' reporting '{target}' for '{reason}'...", "info")
        self._run_in_thread(self.manager.report_account, args=(
            target, reason), callback=self._update_after_report_gui)

    # Keep implementation from v2.5_fixed
    def _update_after_report_gui(self, report_status, error):
        target = self.report_target_var.get().strip()
        user = self.manager.current_account.get(
            'username', 'Current') if self.manager.current_account else 'Current'
        if error:
            self.update_status(f"Error reporting '{target}': {error}", "error")
            messagebox.showerror(
                "Report Error", f"Error reporting '{target}':\n{error}")
        elif report_status is True:
            self.update_status(
                f"Report submitted for '{target}' by {user}.", "success")
            self.update_account_listbox()
        elif report_status is False:
            self.update_status(
                # Simplified msg
                f"Report for '{target}' by {user} skipped (Limit/Cooldown).", "warning")
        elif report_status is None:
            self.update_status(
                f"Report failed: Target '{target}' not found.", "error")
            messagebox.showerror(
                "Report Failed", f"Target profile '{target}' not found.")
        else:
            self.update_status(
                f"Report '{target}' status: {report_status}. Check logs.", "warning")
        self.update_account_listbox()  # Update listbox regardless

    def start_mass_report_gui(self):
        # Revised for concurrent execution
        if not self._ensure_network_ready():
            return
        target = self.report_target_var.get().strip()
        reason = self.report_reason_var.get()
        try:
            num_acc_req = self.mass_num_accounts_var.get()
        except:
            messagebox.showerror("Input", "Invalid number of accounts.")
            return
        try:
            max_workers = self.mass_max_workers_var.get()
        except:
            messagebox.showerror("Input", "Invalid max concurrent bots.")
            return
        if not target or not reason:
            messagebox.showerror("Input", "Target and Reason required.")
            return
        if num_acc_req <= 0:
            messagebox.showerror("Input", "# Accounts must be > 0")
            return
        if max_workers <= 0:
            messagebox.showerror("Input", "Max concurrent bots must be > 0")
            return

        eligible = [a for a in self.manager.accounts if a.get(
            "status") not in ["banned", "locked", "challenge", "login_failed"]]
        num_avail = len(eligible)
        if num_avail == 0:
            messagebox.showerror("Error", "No usable accounts.")
            return

        actual_to_use = min(num_acc_req, num_avail)
        if actual_to_use != num_acc_req:
            messagebox.showwarning(
                "Warning", f"Requested {num_acc_req}, only {num_avail} usable. Using {actual_to_use}.")
            self.mass_num_accounts_var.set(actual_to_use)

        msg = f"Start Mass Report ('Bots')?\n\nTarget: {target}\nReason: {reason}\nUsing: {actual_to_use} accounts\nMax Concurrent: {max_workers}\n\n(Each bot logs in, reports, logs out.)"
        if not messagebox.askyesno("Confirm Concurrent Mass Report", msg):
            self.update_status("Mass report cancelled.")
            return

        # Update manager settings potentially? Or just pass value
        # self.manager.settings["max_mass_report_workers"] = max_workers
        self.update_status(
            f"Starting mass report on '{target}' ({actual_to_use} accounts, max {max_workers} concurrent)...", "info")
        accounts_to_run_with = random.sample(
            eligible, actual_to_use)  # Shuffle selection
        self._run_in_thread(self._mass_report_concurrent_logic, args=(
            target, reason, accounts_to_run_with, max_workers), callback=self._update_after_mass_report_gui)

    def _mass_report_worker(self, account, target, reason):
        # Worker function for a single account in mass report. Runs in its own thread (via ThreadPoolExecutor).
        # Creates its OWN manager instance (or separate driver) to be thread-safe? No, share manager is complex.
        # Instead, create a short-lived manager instance *or* handle driver creation/closing cleanly here.
        # For now, let's use the main manager but accept potential race conditions if not careful.
        # Best practice would involve a dedicated pool of pre-initialized drivers or instance-per-thread.
        # --- Simplified Approach (uses shared manager, acquires driver) ---
        username = account.get("username", "N/A")
        self.logger.info(f"Bot [{username}]: Starting...")
        login_ok = False
        report_status = "init"
        driver_instance_for_bot = None  # Avoid using self.driver directly
        manager_ref = self.manager  # Local ref

        try:
            # --- Driver Setup ---
            self.logger.debug(f"Bot [{username}]: Setting up driver...")
            # Get a fresh driver using shared settings/proxy pool
            driver_instance_for_bot = manager_ref._setup_driver()
            if not driver_instance_for_bot:
                raise WebDriverException(
                    f"Bot [{username}]: Failed to setup driver.")

            # Hacky: Temporarily assign driver to main manager instance for login/report methods
            # THIS IS NOT IDEALLY THREAD SAFE. Need manager refactoring for true safety.
            manager_ref.driver = driver_instance_for_bot  # !!! Race Condition Risk !!!

            # --- Login ---
            self.logger.debug(f"Bot [{username}]: Attempting login...")
            # Use manager's login, which now uses the temporary driver assignment
            login_ok = manager_ref.login(account)

            if login_ok:
                self.logger.info(f"Bot [{username}]: Login SUCCESS.")
                manager_ref._random_delay(1, 3)
                # --- Report ---
                self.logger.debug(f"Bot [{username}]: Attempting report...")
                # Uses manager's report, again using the temporary driver assignment
                report_status_code = manager_ref.report_account(target, reason)
                if report_status_code is True:
                    report_status = "success"
                elif report_status_code is False:
                    report_status = "skipped"
                elif report_status_code is None:
                    report_status = "target_not_found"
                else:
                    report_status = "failed_report"  # Other failure
                self.logger.info(
                    f"Bot [{username}]: Report status - {report_status}")
            else:
                report_status = "failed_login"
                self.logger.error(
                    f"Bot [{username}]: Login FAILED (Status: {account.get('status')})")

        except Exception as e:
            report_status = "exception"
            self.logger.error(
                f"Bot [{username}]: EXCEPTION -> {e}", exc_info=True)
        finally:
            # Clean up driver SPECIFICALLY for this bot
            if manager_ref.driver == driver_instance_for_bot:  # Check if it's still assigned
                manager_ref.close_driver()  # Close and clear manager's ref
            elif driver_instance_for_bot:  # If assignment was lost/changed, try closing directly
                try:
                    driver_instance_for_bot.quit()
                    self.logger.debug(f"Bot [{username}] explicit quit")
                except:
                    pass
            self.logger.info(
                f"Bot [{username}]: Finished. Status: {report_status}")
            # Return result
            return {"username": username, "outcome": report_status}

    def _mass_report_concurrent_logic(self, target, reason, accounts_to_use, max_workers):
        # Manages the thread pool for concurrent reporting.
        results = {"success": 0, "failed_login": 0, "failed_report": 0, "skipped": 0, "target_not_found": 0,
                   "exception": 0, "total": len(accounts_to_use), "target": target, "details": []}
        actual_workers = min(max_workers, len(accounts_to_use))
        self.logger.info(
            f"Mass Report Concurrency: Starting {results['total']} jobs with max {actual_workers} workers...")

        with concurrent.futures.ThreadPoolExecutor(max_workers=actual_workers) as executor:
            # Map worker function to accounts list
            future_to_account = {executor.submit(
                self._mass_report_worker, acc, target, reason): acc for acc in accounts_to_use}

            for future in concurrent.futures.as_completed(future_to_account):
                account = future_to_account[future]
                username = account.get("username", "N/A")
                try:
                    # {"username":..., "outcome":...}
                    job_result = future.result()
                    if job_result and "outcome" in job_result:
                        outcome = job_result["outcome"]
                        results["details"].append(job_result)
                        if outcome == "success":
                            results["success"] += 1
                        elif outcome == "skipped":
                            results["skipped"] += 1
                        elif outcome == "target_not_found":
                            results["target_not_found"] += 1
                        elif outcome == "failed_login":
                            results["failed_login"] += 1
                        elif outcome == "failed_report":
                            results["failed_report"] += 1
                        else:
                            # Assume exception if not known
                            results["exception"] += 1
                        # Update account status in main list? Be careful with thread safety.
                        # Best to just update listbox from GUI thread after all done.
                    else:
                        results["exception"] += 1
                        results["details"].append(
                            {"username": username, "outcome": "error_no_result"})
                except Exception as exc:
                    self.logger.error(
                        f"Mass Report: Error getting result for {username}: {exc}")
                    results["exception"] += 1
                    results["details"].append(
                        {"username": username, "outcome": f"exception_{exc}"})
                finally:
                    # GUI update for progress? Difficult with concurrent pool. Just status update?
                    completed = len(results["details"])
                    self.root.after(0, lambda c=completed, t=results['total']: self.update_status(
                        f"Mass Report: {c}/{t} bots completed...", "info"))
                    # Update account listbox after EACH COMPLETION to refresh statuses if changed
                    self.root.after(0, self.update_account_listbox)

        self.logger.info(
            f"Mass Report Concurrency for '{target}' FINISHED. Aggregated Results: {
                {k: v for k, v in results.items() if k != 'details'} }")
        # Calculate overall failure count for final message
        results["failed"] = results["failed_login"] + \
            results["failed_report"] + results["exception"]
        return results

    # Adjusted for new keys
    def _update_after_mass_report_gui(self, results, error):
        if error:
            self.update_status(f"Mass report filed: {error}", "error")
            messagebox.showerror("Mass Report Error", f"Error: {error}")
            return
        if results:
            tgt = results.get("target", "N/A")
            total = results.get("total", 0)
            success = results.get("success", 0)
            failed = results.get(
                "failed_login", 0)+results.get("failed_report", 0)+results.get("exception", 0)
            skipped = results.get("skipped", 0)
            notfound = results.get("not_found", 0)
            summary = f"Concurrent Mass Report for '{tgt}' Complete.\n\nSuccess: {success}\nFailed: {failed}\nSkipped: {skipped}\nTarget Not Found: {notfound}\nTotal Attempted: {total}"
            lvl = "success" if success > 0 else "warning" if skipped > 0 else "error"
            msg = f"Mass Report '{tgt}': S:{success}, F:{failed}, K:{skipped}, NF:{notfound} / T:{total}"
            self.update_status(msg, lvl)
            messagebox.showinfo("Mass Report Complete", summary)
        else:
            self.update_status(
                "Mass report finished with no results.", "warning")
        self.update_account_listbox()  # Final list update

    # --- Data Tab Actions (Added readiness check) ---
    def extract_user_data_gui(self):
        if not self._ensure_network_ready():
            return
        target = self.data_target_var.get().strip()
        if not target:
            messagebox.showerror("Input", "Target Username empty.")
            return
        if not self.manager.driver or not self.manager.current_account:
            messagebox.showwarning("Login Required", "Login first.")
            self.tab_control.select(self.account_tab)
            return
        try:
            self.data_results_text.config(state=tk.NORMAL)
            self.data_results_text.delete(1.0, tk.END)
            self.data_results_text.insert(
                tk.END, f"Extracting data for '{target}'...\n")
            self.data_results_text.config(state=tk.DISABLED)
        except:
            self.logger.error("Data results widget gone.")
            return
        user = self.manager.current_account['username']
        self.update_status(f"'{user}' extracting '{target}'...", "info")
        self._last_extracted_target = target
        self._last_extracted_data = None
        self._run_in_thread(self.manager.extract_user_data, args=(
            target,), callback=self._update_after_extraction_gui)

    # Keep most implementation, add logging
    def _update_after_extraction_gui(self, user_data, error):
        target = self._last_extracted_target
        if error:
            self.update_status(
                f"Extract error for '{target}': {error}", "error")
            messagebox.showerror("Extract Error", f"Error: {error}")
            self._last_extracted_data = None
            return
        if not user_data:
            self.update_status(f"Extract fail '{target}' (No data).", "error")
            self._last_extracted_data = None
            return
        self._last_extracted_data = user_data  # Store data for export

        status = user_data.get("extraction_status", "Unknown")
        user = user_data.get("username", "N/A")
        # Format display ( reusing formatting from v2.5_fixed example )
        ts = time.strftime(
            '%Y-%m-%d %H:%M:%S', time.localtime(user_data.get('extraction_timestamp', time.time())))
        url = user_data.get('profile_url', 'N/A')
        line = "-"*40
        disp = f"=== Data for: {user} | Status: {status} ===\nTimestamp: {ts}\nURL: {url}\n{line}\n"
        disp += f"Full Name: {user_data.get('full_name', 'N/A')}\nVerified: {'Yes' if user_data.get('is_verified', False) else 'No'}\nPrivate: {'Yes' if user_data.get('is_private') else ('No' if user_data.get('is_private') == False else 'Unknown')}\n{line}\n"
        disp += f"Followers: {user_data.get('follower_count', 'N/A')}\nFollowing: {user_data.get('following_count', 'N/A')}\nPosts: {user_data.get('media_count', 'N/A')}\n{line}\n"
        disp += f"Bio:\n{user_data.get('biography', 'N/A')}\n{line}\n"
        disp += f"External URL: {user_data.get('external_url', 'N/A')}\nProfile Pic: {user_data.get('profile_pic_url', 'N/A')}\n{line}\n"
        posts = user_data.get('recent_posts', [])
        disp += f"Recent Posts ({len(posts)}):\n" if posts else "Recent Posts: None/Private\n"
        for i, p in enumerate(posts, 1):
            disp += f"  {i}. {p.get('code', 'N/A')} ({p.get('url', '')})\n"
        try:
            self.data_results_text.config(state=tk.NORMAL)
            self.data_results_text.delete(1.0, tk.END)
            self.data_results_text.insert(tk.END, disp)
            self.data_results_text.config(state=tk.DISABLED)
        except:
            pass
        lvl = "success" if "Complete" in status else (
            "error" if "Error" in status or "Fail" in status else "info")
        self.update_status(f"Extraction for {user}: {status}", lvl)

    def export_user_data_gui(self):  # Keep implementation from v2.5_fixed
        if not hasattr(self, '_last_extracted_data') or not self._last_extracted_data:
            messagebox.showerror("Error", "No data extracted yet.")
            return
        user = self._last_extracted_data.get("username", "exported")
        fp = filedialog.asksaveasfilename(defaultextension=".json", initialfile=f"{user}_ig_data_{time.strftime('%Y%m%d')}.json", filetypes=[
                                          ("JSON", "*.json")], title="Save Data")
        if not fp:
            return
        try:
            with open(fp, "w", encoding='utf-8') as f:
                json.dump(self._last_extracted_data, f,
                          indent=4, ensure_ascii=False)
            messagebox.showinfo(
                "Success", f"Data saved to {os.path.basename(fp)}")
            self.update_status("Data exported.", "success")
        except Exception as e:
            messagebox.showerror("Error", f"Export failed: {e}")
            self.update_status("Data export failed.", "error")

    # --- Settings Tab Actions ---
    # Fix the missing method name: rename function definition
    def refresh_proxies_gui(self):
        # Correct method name matching the button command
        if hasattr(self, '_refresh_thread') and self._refresh_thread.is_alive():
            self.update_status("Proxy refresh already running.", "info")
            messagebox.showinfo("In Progress", "Refresh running.")
            return

        self.update_status("Starting proxy list refresh...", "info")
        self.proxy_verify_status_var.set("Fetching lists...")
        self.proxy_progress.grid()
        self.proxy_progress.config(value=0, maximum=100)  # Show/Reset progress

        # Run background refresh using helper
        def refresh_thread_target_wrapper():
            try:
                self.manager._load_and_verify_proxies_background(
                    progress_bar=self.proxy_progress, status_var=self.proxy_verify_status_var, root_after=self.root.after)
            except Exception as e:
                self.logger.error(
                    f"Proxy refresh thread error: {e}", exc_info=True)
                self.root.after(0, lambda: self.update_status(
                    "Proxy refresh failed.", "error"))
                self.root.after(
                    0, lambda: self.proxy_verify_status_var.set("Refresh Error"))
            finally:
                # Always update count
                self.root.after(0, self._update_proxy_count_gui)

        self._refresh_thread = threading.Thread(
            target=refresh_thread_target_wrapper, daemon=True)
        self._refresh_thread.start()

    def _update_proxy_count_gui(self):  # Keep implementation from v2.5_fixed
        if not hasattr(self, 'proxy_count_var') or not self.root.winfo_exists():
            return
        try:
            count = len(self.manager.proxies) 
            direct = "" if "" not in self.manager.proxies else " (incl. Direct)"
            self.proxy_count_var.set(f"Proxies Available: {count}{direct}")
        except Exception as e:
            self.logger.error(f"Update proxy count label error: {e}")
            self.proxy_count_var.set("Proxies: Error")

    def add_manual_proxy_gui(self):  # Keep implementation from v2.5_fixed
        proxy = self.manual_proxy_var.get().strip()
        if not proxy:
            messagebox.showerror("Input", "Proxy address empty.")
            return
        if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,5}$", proxy):
            messagebox.showerror("Input", "Invalid format (IP:PORT).")
            return
        if self.manager.proxies and proxy in self.manager.proxies:
            self.update_status(f"Proxy {proxy} already in list.", "info")
            self.manual_proxy_var.set("")
            return
        self.update_status(f"Verifying manual proxy {proxy}...", "info")
        self._run_in_thread(self.manager._verify_proxy, args=(
            proxy,), callback=lambda res, err: self._update_after_manual_proxy_add_gui(proxy, res, err))

    # Keep implementation from v2.5_fixed
    def _update_after_manual_proxy_add_gui(self, proxy, result, error):
        if error:
            self.update_status(f"Error verifying {proxy}: {error}", "error")
            messagebox.showerror("Verify Error", f"Error: {error}")
        elif result is not None:  # Success if verify_proxy didn't return None
            if proxy not in self.manager.proxies:
                self.manager.proxies.append(proxy)
                self.logger.info(f"Added manual proxy: {proxy}")
                self._update_proxy_count_gui()
            self.update_status(f"Added proxy: {proxy}", "success")
            self.manual_proxy_var.set("")
        else:
            self.update_status(
                f"Manual proxy {proxy} FAILED verification.", "error")
            messagebox.showerror("Failed", f"Proxy {proxy} failed check.")

    # Keep implementation from v2.5_fixed (added mass worker limit)
    def save_settings_gui(self):
        self.logger.debug("Saving GUI settings...")
        try:
            # Validation
            bin_path = self.chrome_binary_path_var.get().strip()
            driv_path = self.chrome_driver_path_var.get().strip()
            if bin_path and not Path(bin_path).is_file():
                raise ValueError(f"Invalid Chrome binary: {bin_path}")
            if driv_path and not Path(driv_path).is_file():
                raise ValueError(f"Invalid ChromeDriver: {driv_path}")
            if driv_path and not os.path.basename(driv_path).lower().startswith('chromedriver') and not messagebox.askyesno("Confirm Path", f"Path:\n{driv_path}\ndoes not look like chromedriver.exe.\nUse anyway?"):
                raise ValueError("ChromeDriver path selection cancelled.")
            # Save
            self.manager.settings["browser_type"] = self.browser_type_var.get()
            self.manager.settings["chrome_binary_path"] = bin_path
            self.manager.settings["chrome_driver_path"] = driv_path
            self.manager.settings["headless"] = self.headless_var.get()
            self.manager.settings["enable_stealth"] = self.stealth_var.get()
            self.manager.settings["save_screenshots"] = self.screenshot_var.get(
            )
            debug_changed = self.manager.settings["debug_mode"] != self.debug_mode_var.get(
            )
            self.manager.settings["debug_mode"] = self.debug_mode_var.get()
            if debug_changed:
                self.update_log_level_gui()
            self.manager.settings["max_reports_per_day"] = self.max_reports_var.get(
            )
            self.manager.settings["report_interval_seconds"] = self.interval_var.get(
            )
            # Save concurrent worker limit
            self.manager.settings["max_mass_report_workers"] = self.mass_max_workers_var.get(
            )
            self.logger.info("Settings saved.")
            self.update_status("Settings saved.", "success")
            messagebox.showinfo("Settings Saved", "Settings updated.")
        except ValueError as ve:
            self.logger.error(f"Settings validation failed: {ve}")
            self.update_status(f"Settings validate failed: {ve}", "error")
            messagebox.showerror("Validation Error", str(ve))
        except Exception as e:
            self.logger.error(f"Save settings error: {e}", exc_info=True)
            self.update_status("Settings save failed.", "error")
            messagebox.showerror("Error", f"Failed to save: {e}")

    # Keep implementation from v2.5_fixed
    def _browse_path_gui(self, title, filetypes, target_var):
        curr = target_var.get()
        initdir = os.path.dirname(curr) if curr and os.path.exists(
            os.path.dirname(curr)) else str(Path.home())
        fp = filedialog.askopenfilename(
            title=title, filetypes=filetypes, initialdir=initdir)
        if fp:
            target_var.set(fp)

    def _browse_chrome_binary_path_gui(self): self._browse_path_gui(
        "Select Chrome/Chromium", [("Exe/App", "*.exe *.app"), ("All", "*.*")], self.chrome_binary_path_var)

    def _browse_chrome_driver_path_gui(self): self._browse_path_gui("Select ChromeDriver", [(
        "ChromeDriver", "chromedriver.exe chromedriver"), ("All", "*.*")], self.chrome_driver_path_var)

    def show_chromedriver_help_gui(self): messagebox.showinfo("ChromeDriver Help",  # Keep implementation from v2.5_fixed
                                                              "ChromeDriver Setup:\n\n1. Auto (Recommended):\n   - Leave path blank.\n   - Ensure Chrome installed.\n   - Downloads automatically.\n\n2. Manual:\n   a. Check Chrome Version (Help -> About)\n   b. Go to: https://googlechromelabs.github.io/chrome-for-testing/\n   c. Download matching MAJOR version for your OS.\n   d. Extract chromedriver.exe (or chromedriver).\n   e. Browse to select the extracted file.\n\n* Version MUST Match! (e.g., Chrome 121 -> ChromeDriver 121)")

    # --- Window Close ---

    def on_close(self):  # Keep implementation from v2.5_fixed
        if messagebox.askyesno("Quit", "Are you sure you want to quit?"):
            self.update_status("Shutting down...", "info")
            self.logger.info("Shutdown initiated.")
            cleanup_thread = threading.Thread(
                target=self.manager.close, daemon=False)
            cleanup_thread.start()
            self.root.after(1500, self.root.destroy)  # Close GUI after delay
        else:
            self.logger.debug("Quit cancelled.")

    # === Main Execution ===


def main():
    """Entry point for the Instagram Manager application."""
    # Configure basic logging first
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s %(levelname)s:%(message)s',
        handlers=[
            logging.FileHandler(LOG_DIR / LOG_FILENAME, encoding='utf-8'),
            logging.StreamHandler()
        ]
    )

    try:
        root = tk.Tk()
        root.withdraw()  # Hide main window during initialization

        # Set DPI awareness on Windows
        try:
            from ctypes import windll, WinDLL
            if hasattr(windll, 'shcore'):
                windll.shcore.SetProcessDpiAwareness(1)
                logging.info("Set DPI awareness for high-resolution displays")
        except (ImportError, AttributeError, OSError) as e:
            logging.debug(f"DPI awareness not set: {e}")

        # Create and show the application
        app = EnhancedInstagramManagerGUI(root)
        root.deiconify()  # Show the main window

        # Start the main loop
        root.mainloop()

    except tk.TclError as e:
        logging.critical(f"Tkinter initialization failed: {e}", exc_info=True)
        print(
            "\nFATAL: Tkinter Error - This usually means Tkinter is not properly installed.\n"
            f"Error details: {e}\n"
            "On Linux, try: sudo apt-get install python3-tk\n"
            "On Windows/Mac, reinstall Python with Tkinter support.",
            file=sys.stderr
        )
        sys.exit(1)

    except Exception as e:
        logging.critical(f"Application startup failed: {e}", exc_info=True)
        print(
            f"\nFATAL STARTUP ERROR:\n{str(e)}\n"
            "Please check the log file for more details.",
            file=sys.stderr
        )
        sys.exit(1)


if __name__ == "__main__":
    # Ensure the log directory exists
    LOG_DIR.mkdir(exist_ok=True)

    # Start the application
    main()

    # --- END OF FILE v2.6_godfather_rebuilt.py ---
