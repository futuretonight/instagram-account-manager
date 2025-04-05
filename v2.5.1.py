import base64 
import calendar # Not used in the provided snippet, but kept if needed elsewhere
import concurrent.futures
import csv
import ctypes # For DPI awareness
import datetime # Not used in the provided snippet, but kept if needed elsewhere
import hashlib
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
import traceback
import urllib.parse
import urllib3  # For disabling warnings# GUI Imports (Tkinter)
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext

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
    "fake_useragent": "pip install fake-useragent",
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
DEFAULT_SETTINGS = {
    # Core Behavior
    "max_accounts": 100, "headless": True, "enable_stealth": True, "browser_type": "chrome",
    "save_screenshots": False, "debug_mode": False,
    # Timing & Delays
    "random_delay_min": 0.8, "random_delay_max": 2.5,
    "account_creation_delay_min": 4.0, "account_creation_delay_max": 10.0,
    "report_interval_seconds": 1800, "webdriver_wait_timeout": 15,
    "proxy_timeout": 7,
    # Limits & Attempts
    "max_login_attempts": 2, "max_reports_per_day": 15,
    # Concurrency
    "proxy_test_threads": 30, "max_mass_report_workers": 5,
    # Paths (Persistent)
    "chrome_binary_path": "", "chrome_driver_path": "", "geoip_db_path": "",
    # Misc
    "use_direct_connection_fallback": True,
}


GUI_LOG_TAGS = {
    logging.DEBUG: "log_debug", logging.INFO: "log_info",
    logging.WARNING: "log_warning", logging.ERROR: "log_error",
    logging.CRITICAL: "log_critical",
}
LOG_COLORS = {
    logging.DEBUG: 'DIM', logging.INFO: 'GREEN', logging.WARNING: 'YELLOW',
    logging.ERROR: 'RED', logging.CRITICAL: 'RED',
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
    Generates temporary email addresses using various online services.
    """

    def __init__(self):
        self.session = requests.Session()
        self.api_user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36"
        self.session.headers.update({'User-Agent': self.api_user_agent})
        logger.debug("Email Creator initialized.")

    def create_temporary_email(self):
        logger.debug("Attempting to create temporary email...")
        email_methods = [
            self._create_1secmail_email,
            self._create_tempmail_lol_manual,
            self._create_guerrillamail_email_v2,
            self._create_mailtm_email,
            self._create_maildrop_email,
            self._create_generic_fallback_email  # Keep fallback last
        ]
        random.shuffle(email_methods)

        for method in email_methods:
            email = None
            method_name = method.__name__.replace('_create_', '').replace(
                '_email', '').replace('_v2', ' (v2)')
            try:
                logger.debug(f"Trying email provider: {method_name}")
                email = method()
                if email and '@' in email:
                    logger.info(
                        f"Successfully created email using {method_name}: {email}")
                    return email
                elif email:
                    logger.warning(
                        f"Provider {method_name} returned invalid format: {email}")
            except Exception as e:
                logger.warning(
                    f"Failed to create email with {method_name}: {e}", exc_info=logger.level == logging.DEBUG)
                time.sleep(random.uniform(0.3, 0.8))

        logger.error(
            "Failed to create temporary email with any primary service.")
        final_fallback = self._create_generic_fallback_email(
        ) or f"fallback_{int(time.time())}@example.com"
        logger.warning(f"Using final fallback email: {final_fallback}")
        return final_fallback

    def _create_guerrillamail_email_v2(self):
        base_url = "https://www.guerrillamail.com"
        ajax_url = f"{base_url}/ajax.php"
        headers = {'Origin': base_url, 'Referer': base_url + '/'}
        try:
            response = self.session.get(
                ajax_url, params={'f': 'get_email_address'}, headers=headers, timeout=15)
            response.raise_for_status()
            data = response.json()
            if not data or 'email_addr' not in data:
                raise ValueError(
                    f"Initial request failed or invalid response format: {data}")
            return data['email_addr']
        except (requests.RequestException, json.JSONDecodeError, ValueError) as e:
            raise Exception(f"Guerrilla Mail v2 error: {e}") from e

    def _create_tempmail_lol_manual(self):
        username = ''.join(random.choices(
            string.ascii_lowercase + string.digits, k=12))
        domains = ["tempmail.lol", "tempr.email", "mailisku.com", "spam.care"]
        return f"{username}@{random.choice(domains)}"

    def _create_maildrop_email(self):
        username = ''.join(random.choices(
            string.ascii_lowercase + string.digits, k=10))
        return f"{username}@maildrop.cc"

    def _create_mailtm_email(self):
        try:
            domain_resp = self.session.get(
                "https://api.mail.tm/domains?page=1", headers={'Accept': 'application/json'}, timeout=10)
            domain_resp.raise_for_status()
            domains_data = domain_resp.json()
            if not domains_data or 'hydra:member' not in domains_data or not domains_data['hydra:member']:
                raise ValueError(
                    "Mail.tm: No domains found or invalid response")
            domain = random.choice(domains_data['hydra:member'])['domain']

            username = ''.join(random.choices(
                string.ascii_lowercase + string.digits, k=12))
            password = self.generate_password()
            payload = {"address": f"{username}@{domain}", "password": password}
            account_resp = self.session.post("https://api.mail.tm/accounts", headers={
                                             'Content-Type': 'application/json', 'Accept': 'application/json'}, json=payload, timeout=15)

            if account_resp.status_code == 201:
                return f"{username}@{domain}"
            else:
                try:
                    error_details = account_resp.json()
                except json.JSONDecodeError: error_details = account_resp.text
                raise requests.exceptions.HTTPError(
                    f"Account creation failed: {account_resp.status_code} - {error_details}", response=account_resp)

        except (requests.RequestException, json.JSONDecodeError, ValueError) as e:
            raise Exception(f"Mail.tm error: {e}") from e

    def _create_1secmail_email(self):
        try:
            response = requests.get(
                "https://www.1secmail.com/api/v1/?action=genRandomMailbox&count=1",
                headers={'User-Agent': self.api_user_agent}, timeout=10, proxies=None
            )
            response.raise_for_status()
            data = response.json()
            if isinstance(data, list) and data and isinstance(data[0], str) and '@' in data[0]:
                return data[0]
            else:
                raise ValueError(
                    f"1secmail unexpected response format: {data}")
        except (requests.RequestException, json.JSONDecodeError, ValueError) as e:
            raise Exception(f"1secmail error: {e}") from e

    def _create_generic_fallback_email(self):
        try:
            domains = ["mailinator.com", "yopmail.com",
                "inboxkitten.com", "tempmail.net"]
            username = ''.join(random.choices(
                string.ascii_lowercase + string.digits, k=12))
            return f"{username}@{random.choice(domains)}"
        except Exception as e:
            logger.error(f"Generic fallback generation failed: {e}")
            return f"very_fallback_{int(time.time())}@example.com"

    @staticmethod
    def generate_password(length=14):
        length = max(12, min(length, 20))
        chars = string.ascii_lowercase + string.ascii_uppercase + \
            string.digits + "!@#$%^&*()_+-=[]{}|;:,.<>?"
        while True:
            password = ''.join(random.choice(chars) for _ in range(length))
            if (any(c.islower() for c in password)
                    and any(c.isupper() for c in password)
                    and any(c.isdigit() for c in password)
                    and any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)):
                return password

# === Core Logic: Instagram Manager ===


class EnhancedInstagramManager:
    """
    Manages Instagram accounts, proxies, and actions with persistence and GUI linkage.
    """

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
        self.current_proxy_address = None; self.current_account = None
        self.session = requests.Session()

        # Utils
        self.user_agent_generator = UserAgent()
        self.current_user_agent = self.user_agent_generator.random
        self.email_creator = EnhancedEmailCreator()
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

    def _load_persistent_settings(self):
        config_path = Path(CONFIG_FILENAME)
        if not config_path.is_file():
            logger.info(
                f"'{CONFIG_FILENAME}' not found. Using default settings.")
            return
        logger.debug(
            f"Loading persistent settings from '{config_path.name}'...")
        try:
            with self._config_lock, open(config_path, 'r', encoding='utf-8') as f:
                loaded_config = json.load(f)
            # Update *only* the keys meant to be persistent (paths)
            keys_to_persist = ["chrome_binary_path",
                "chrome_driver_path", "geoip_db_path"]
            # Update non-path settings too if they exist in the config
            keys_to_update = [
                k for k in DEFAULT_SETTINGS.keys() if k in loaded_config]
            updated_count = 0
            for key in keys_to_update:
                if key in self.settings:  # Only update keys that exist in defaults
                     self.settings[key] = loaded_config[key]
                      updated_count += 1
            logger.info(
                f"Loaded {updated_count} settings from '{config_path.name}'.")
        except (json.JSONDecodeError, IOError) as e:
            logger.error(
                f"Error loading '{config_path.name}': {e}. Using defaults for affected settings.", exc_info=True)

    def save_persistent_settings(self):
        config_path = Path(CONFIG_FILENAME)
        logger.debug(f"Saving persistent settings to '{config_path.name}'...")
        # Save ALL current settings (including paths and numeric values)
        settings_to_save = self.settings.copy()
        try:
            with self._config_lock, open(config_path, 'w', encoding='utf-8') as f:
                json.dump(settings_to_save, f, indent=2, sort_keys=True)
            logger.info(
                f"Successfully saved {len(settings_to_save)} settings to '{config_path.name}'.")
        except (PermissionError, IOError) as e:
            logger.error(
                f"Permission/IO denied saving config file '{config_path.name}': {e}")
             if self.gui and hasattr(self.gui, 'root') and self.gui.root.winfo_exists():
                 messagebox.showerror(
                     "Config Save Error", f"Permission/IO error saving config to:\n{config_path.resolve()}\n{e}")
        except Exception as e:
            logger.error(
                f"Failed to save settings to '{config_path.name}': {e}", exc_info=True)
             if self.gui and hasattr(self.gui, 'root') and self.gui.root.winfo_exists():
                 messagebox.showerror("Config Save Error",
                                      f"Failed to save config file:\n{e}")

    def _validate_numeric_settings(self):
        """ Ensures numeric settings loaded from config are the correct type and within reasonable bounds. """
        # Define checks: {setting_key: (type, min_val, max_val)}
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
                # Attempt conversion
                if req_type is int:
                    # Allow float input for int conversion
                    converted_value = int(float(original_value))
                elif req_type is float:
                    converted_value = float(original_value)
                else:
                    continue  # Skip unknown types

                # Apply bounds
                validated_value = max(min_val, min(converted_value, max_val))

                if validated_value != original_value:  # Check if value was actually changed
                    if converted_value != original_value:  # Changed due to type conversion
                        logger.warning(
                            f"Setting '{key}': Corrected type from {type(original_value).__name__} to {req_type.__name__} ({original_value} -> {validated_value}).")
                    else:  # Changed due to bounds
                        logger.warning(
                            f"Setting '{key}': Clamped value {original_value} to range [{min_val}, {max_val}] -> {validated_value}.")
                    self.settings[key] = validated_value

            except (ValueError, TypeError, AttributeError) as e:
                default_val = DEFAULT_SETTINGS[key]
                 logger.error(
                     f"Setting '{key}': Invalid value '{original_value}' ({e}). Resetting to default: {default_val}.")
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
                self.geoip_reader.close(); self.geoip_reader = None
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
            self.proxies.clear(); logger.debug("Previous proxy list cleared.")
        thread = threading.Thread(target=self._load_and_verify_proxies_background, args=(
            gui_elements,), daemon=True, name="ProxyLoader")
        thread.start()

    def _load_and_verify_proxies_background(self, gui_elements=None):
        raw_proxies = []
        try:
            raw_proxies = self._fetch_raw_proxies()
            if not raw_proxies:
                logger.warning("Proxy Check: No raw proxies fetched.")
            to_verify_set = set(raw_proxies); to_verify_set.add("")
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
        status_order = {'verified': 0, 'checking': 1,
            'failed': 2}; status_rank = status_order.get(status, 3)
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
        update_gui_callback = None
        root_ref = None
        if gui_elements and 'root' in gui_elements and gui_elements['root'].winfo_exists():
            root_ref = gui_elements['root']

            def _update_progress_display_safe(p_count, total):
                try:
                    if not root_ref or not root_ref.winfo_exists():
                        return
                    pct = int((p_count / total) * 100) if total > 0 else 0
                    status_var = gui_elements.get('status_var')
                    if status_var and hasattr(status_var, 'set'):
                        try: status_var.set(f"Verifying {p_count}/{total} ({pct}%)...") except tk.TclError: pass
                    pb = gui_elements.get('progress_bar')
                    if pb and pb.winfo_exists():
                        try: pb.config(value=p_count, maximum=total); pb.grid() if not pb.winfo_ismapped() else None except tk.TclError: pass
                    gui_instance = gui_elements.get('gui_instance')
                    if gui_instance and (p_count % 20 == 0 or p_count == total) and hasattr(gui_instance, 'update_proxy_treeview') and callable(gui_instance.update_proxy_treeview):
                         try:
                             gui_instance.update_proxy_treeview() except tk.TclError: pass
                except Exception as gui_err: logger.error(f"GUI progress update internal error: {gui_err}", exc_info=True)
            update_gui_callback = _update_progress_display_safe
            root_ref.after(
                0, lambda p=0, t=total_proxies: update_gui_callback(p, t))

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads, thread_name_prefix='ProxyVerify') as executor:
            future_to_proxy_addr = {executor.submit(
                self._verify_proxy, addr): addr for addr in proxy_list}
            for future in concurrent.futures.as_completed(future_to_proxy_addr):
                processed_count += 1
                proxy_addr = future_to_proxy_addr[future]; proxy_dict_result = None
                try:
                    proxy_dict_result = future.result()
                    if isinstance(proxy_dict_result, dict) and 'address' in proxy_dict_result:
                        with self.proxies_lock:
                            existing_index = next((i for i, p in enumerate(
                                self.proxies) if p['address'] == proxy_dict_result['address']), -1)
                            if existing_index != -1:
                                self.proxies[existing_index] = proxy_dict_result
                            else: self.proxies.append(proxy_dict_result)
                            self.proxies.sort(key=self._proxy_sort_key)
                        if proxy_dict_result.get('status') == 'verified' and not first_found_signaled:
                            proxy_display = proxy_dict_result['address'] or "Direct Connection"
                            latency_val = proxy_dict_result.get('latency')
                            latency_str = f"Latency: {latency_val:.3f}s" if isinstance(
                                latency_val, float) else ""
                            logger.info(
                                f"First usable connection found: {proxy_display} {latency_str}. Signaling availability.")
                            self.first_proxy_available.set()
                            first_found_signaled = True
                    else:
                        logger.error(
                            f"Invalid result from _verify_proxy for {proxy_addr}: {proxy_dict_result}")
                        with self.proxies_lock:
                            failed_proxy = {'address': proxy_addr, 'status': 'failed',
                                'latency': None, 'country': None, 'last_checked': time.time()}
                            if not any(p['address'] == proxy_addr for p in self.proxies):
                                self.proxies.append(failed_proxy); self.proxies.sort(
                                    key=self._proxy_sort_key)
                except Exception as e:
                    logger.error(
                        f"Error processing verification result for {proxy_addr}: {e}", exc_info=logger.level == logging.DEBUG)
                    with self.proxies_lock:
                        failed_proxy = {'address': proxy_addr, 'status': 'failed',
                            'latency': None, 'country': None, 'last_checked': time.time()}
                        if not any(p['address'] == proxy_addr for p in self.proxies):
                            self.proxies.append(failed_proxy); self.proxies.sort(
                                key=self._proxy_sort_key)
                finally:
                    if update_gui_callback and root_ref and root_ref.winfo_exists():
                        root_ref.after(0, lambda p=processed_count,
                                       t=total_proxies: update_gui_callback(p, t))
        if update_gui_callback and root_ref and root_ref.winfo_exists():
            root_ref.after(10, lambda p=total_proxies,
                           t=total_proxies: update_gui_callback(p, t))
        logger.debug("Parallel proxy verification loop completed.")

    def _verify_proxy(self, proxy_address):
        test_url = self.platform_urls["login"]
        proxy_dict_req = None; ip_part = None; status = "checking"; latency = None; country = None; last_checked = time.time()
        result_dict = {'address': proxy_address, 'status': status,
            'latency': latency, 'country': country, 'last_checked': last_checked}
        start_time = time.monotonic()
        try:
            if proxy_address == "":
                proxy_display = "Direct Connection"; country = "Direct"; proxy_dict_req = None
            elif isinstance(proxy_address, str) and re.match(r"^\d{1,3}(\.\d{1,3}){3}:\d{1,5}$", proxy_address):
                proxy_display = proxy_address
                ip_part = proxy_address.split(':')[0]
                proxy_dict_req = {
                    "http": f"http://{proxy_address}", "https": f"http://{proxy_address}"}
            else:
                raise ValueError(f"Invalid proxy format: {proxy_address}")
            if ip_part and self.geoip_reader: country = self.get_proxy_country(
                ip_part)
            response = requests.get(test_url, proxies=proxy_dict_req, timeout=self.settings["proxy_timeout"], headers={
                                    'User-Agent': self.user_agent_generator.random}, allow_redirects=True, verify=False)
            latency = time.monotonic() - start_time
            if 200 <= response.status_code < 400:
                result_dict['status'] = 'verified'
                result_dict['latency'] = latency
                logger.debug(
                    f"[V] SUCCESS: {proxy_display} (Status: {response.status_code}, Latency: {latency:.3f}s, Country: {country or 'N/A'})")
            else:
                result_dict['status'] = 'failed'; logger.debug(
                    f"[X] FAIL: {proxy_display} - Bad Status Code: {response.status_code}")
        except ValueError as ve: result_dict['status'] = 'failed'; logger.debug(f"[X] FORMAT ERR: {proxy_display} - {ve}")
        except requests.exceptions.Timeout:
            result_dict['status'] = 'failed'
            latency_on_timeout = time.monotonic(
            ) - start_time; result_dict['latency'] = latency_on_timeout
            logger.debug(
                f"[X] FAIL: {proxy_display} - Timeout ({self.settings['proxy_timeout']}s, actual: {latency_on_timeout:.3f}s)")
        except (requests.exceptions.ProxyError, requests.exceptions.ConnectTimeout, requests.exceptions.SSLError, requests.exceptions.ConnectionError, MaxRetryError) as conn_err:
            result_dict['status'] = 'failed'
            logger.debug(
                f"[X] FAIL: {proxy_display} - Connection/Proxy Error: {type(conn_err).__name__}")
        except Exception as e:
            result_dict['status'] = 'failed'
            logger.warning(
                f"Unexpected error verifying {proxy_display}: {e}", exc_info=logger.level == logging.DEBUG)
        finally:
            result_dict['country'] = country
            result_dict['last_checked'] = time.time()
            return result_dict

    def get_random_proxy_address(self):
        with self.proxies_lock:
            verified_proxies = [
                p for p in self.proxies if p.get('status') == 'verified']
            if verified_proxies:
                selected_proxy_dict = random.choice(verified_proxies)
                addr = selected_proxy_dict['address']
                display_name = addr if addr else "Direct Connection"
                logger.debug(f"Selected random verified proxy: {display_name}")
                return addr
        if self.proxy_load_thread_active.is_set():
            logger.debug("No verified proxies available, waiting briefly...")
            signaled = self.first_proxy_available.wait(timeout=5.0)
            if signaled:
                logger.debug("Signal received, re-checking proxy list...")
                with self.proxies_lock:
                    verified_proxies = [
                        p for p in self.proxies if p.get('status') == 'verified']
                    if verified_proxies:
                        selected_proxy_dict = random.choice(verified_proxies)
                        addr = selected_proxy_dict['address']
                        display_name = addr if addr else "Direct Connection"
                        logger.debug(
                            f"Selected proxy after waiting: {display_name}")
                        return addr
                    else:
                        logger.warning(
                            "Proxy signal received, but verified list still empty.")
            else: logger.warning("Timed out waiting for first proxy signal.")
        logger.error("Could not get any working proxy address from list.")
        return None

    # --- Fetch Raw Proxies & Parsers ---

    def _fetch_raw_proxies(self):
        logger.debug("Fetching raw proxy lists...")
        headers = {'User-Agent': self.user_agent_generator.random,
            'Accept': 'text/plain,*/*'}
        proxy_sources = {
            'proxyscrape_http': {'url': 'https://api.proxyscrape.com/v3/free-proxy-list/get?request=displayproxies&protocol=http&proxy_format=ipport&format=text', 'parser': self._parse_plain_text},
            'geonode': {'url': 'https://proxylist.geonode.com/api/proxy-list?limit=150&page=1&sort_by=lastChecked&sort_type=desc&protocols=http%2Chttps', 'parser': self._parse_geonode},
            'free_proxy_list': {'url': 'https://free-proxy-list.net/', 'parser': self._parse_table_proxies_fpl},
        }
        all_proxies = set()
        fetch_session = requests.Session()
        retries = requests.adapters.Retry(
            total=2, backoff_factor=0.3, status_forcelist=[500, 502, 503, 504, 521])
        fetch_session.mount(
            'https://', requests.adapters.HTTPAdapter(max_retries=retries))
        fetch_session.headers.update(headers); timeout = 15
        ip_port_pattern = re.compile(
            r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}:\d{1,5}$")
        for source_name, source_info in proxy_sources.items():
            try:
                logger.debug(f"Fetching raw from {source_name}...")
                response = fetch_session.get(
                    source_info['url'], timeout=timeout, proxies=None, verify=False)
                response.raise_for_status()
                content = response.text
                parsed_proxies = source_info['parser'](content)
                valid_format_proxies = {
                    p for p in parsed_proxies if ip_port_pattern.match(p)}
                count = len(valid_format_proxies)
                if count > 0:
                    logger.debug(f"Got {count} valid proxies from {source_name}"); all_proxies.update(
                        valid_format_proxies)
                else: logger.debug(f"No valid proxies from {source_name}")
            except requests.exceptions.RequestException as e:
                level = logging.WARNING if isinstance(
                    e, (requests.exceptions.Timeout, requests.exceptions.ConnectionError)) else logging.ERROR
                 logger.log(
                     level, f"Network/HTTP error fetching raw from {source_name}: {e}")
            except Exception as e:
                logger.error(
                    f"Error processing source {source_name}: {e}", exc_info=logger.level == logging.DEBUG)
            time.sleep(random.uniform(0.2, 0.5))
        fetch_session.close()
        logger.info(
            f"Fetched {len(all_proxies)} total unique potential proxies.")
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

    # --- WebDriver Setup (FIXED capabilities) ---

    def _setup_driver_common(self, is_worker=False):
        """Common logic for setting up WebDriver options and service."""
        log_prefix = "Worker: " if is_worker else ""
        # Proxy and UA selection needs context (worker vs main) - handled by caller

        browser_type = self.settings.get("browser_type", "chrome").lower()
        headless_mode = self.settings.get(
            "headless", True) if not is_worker else True  # Workers default headless
        use_stealth = self.settings.get("enable_stealth", True)

        if browser_type != "chrome":
            logger.error(
                f"{log_prefix}Unsupported browser type: '{browser_type}'")
            return None, None, None  # Indicate failure

        options = ChromeOptions()
        options.add_argument("--disable-blink-features=AutomationControlled")
        options.add_argument('--no-sandbox')
        options.add_argument('--disable-dev-shm-usage')
        options.add_argument('--disable-gpu')
        options.add_argument('--log-level=3')  # Reduce browser console noise
        options.add_argument("--window-size=1280,800")  # Standard size
        # UA and Proxy set by caller
        options.add_experimental_option(
            "excludeSwitches", ["enable-automation", "enable-logging"])
        options.add_experimental_option('useAutomationExtension', False)
        options.add_argument("--disable-extensions")  # Disable extensions
        # Less critical popups?
        options.add_argument("--disable-popup-blocking")
        # Try standard profile?
        options.add_argument("--profile-directory=Default")

        if headless_mode:
            options.add_argument("--headless=new")  # Use new headless mode

        # **FIXED**: Set capabilities via options for Selenium 4+
        # Capture browser logs too?
        logging_prefs = {'performance': 'ALL', 'browser': 'ALL'}
        options.set_capability('goog:loggingPrefs', logging_prefs)
        logger.debug(
            f"{log_prefix}Enabled performance and browser logging via options capability.")

        # Handle Paths
        chrome_binary = self.settings.get("chrome_binary_path", "").strip()
        manual_driver_path = self.settings.get(
            "chrome_driver_path", "").strip()
        if chrome_binary and Path(chrome_binary).is_file():
            options.binary_location = chrome_binary
            logger.debug(
                f"{log_prefix}Using custom Chrome binary: {chrome_binary}")
        elif chrome_binary:
            logger.warning(
                f"{log_prefix}Custom Chrome binary path invalid: {chrome_binary}")

        service_args = ['--log-level=OFF']  # Reduce chromedriver console noise
        service = None
        driver_path_used = "N/A"

        if manual_driver_path and Path(manual_driver_path).is_file():
            logger.debug(
                f"{log_prefix}Using manually specified ChromeDriver: {manual_driver_path}")
            try:
                service = ChromeService(
                    executable_path=manual_driver_path, service_args=service_args)
                driver_path_used = manual_driver_path
            except Exception as e:
                logger.error(
                    f"{log_prefix}Failed to create service with manual driver path '{manual_driver_path}': {e}")
        else:
            if manual_driver_path:
                logger.warning(
                    f"{log_prefix}Manual ChromeDriver path invalid: '{manual_driver_path}'. Using WDM.")
            logger.debug(
                f"{log_prefix}Using WebDriver Manager for ChromeDriver...")
            try:
                os.environ['WDM_LOG_LEVEL'] = '0'
                os.environ['WDM_PRINT_FIRST_LINE'] = 'False'
                # Consider adding WDM caching options if needed
                driver_install_path = ChromeDriverManager().install()
                service = ChromeService(
                    executable_path=driver_install_path, service_args=service_args)
                driver_path_used = driver_install_path
                logger.debug(
                    f"{log_prefix}ChromeDriver path from WDM: {driver_install_path}")
            except Exception as wdm_error:
                logger.critical(
                    f"{log_prefix}WebDriver Manager failed: {wdm_error}", exc_info=True)
                return None, None, None  # WDM failure is critical

        if not service:
            logger.critical(
                f"{log_prefix}Failed to create WebDriver Service object.")
            return None, None, None

        return options, service, driver_path_used

    def _setup_driver(self):
        """Sets up the main Selenium WebDriver instance."""
        if self.driver:
            logger.warning(
                "Closing existing main WebDriver before creating new one.")
            self.close_driver()

        logger.debug("Setting up main WebDriver...")
        selected_proxy = self.get_random_proxy_address()
        if selected_proxy is None and not self.settings.get("use_direct_connection_fallback"):
            logger.error(
                "Main WebDriver setup failed: No usable proxy available and fallback disabled.")
             return None
        # If proxy is None, direct connection will be used (proxy_arg will be None)
        self.current_proxy_address = selected_proxy
        self.current_user_agent = self.user_agent_generator.random
        proxy_display = self.current_proxy_address if self.current_proxy_address else "Direct Connection"

        options, service, driver_path_used = self._setup_driver_common(
            is_worker=False)
        if options is None:
            return None  # Common setup failed

        # Add specific options for main driver
        options.add_argument(f"user-agent={self.current_user_agent}")
        proxy_arg = f"--proxy-server=http://{self.current_proxy_address}" if self.current_proxy_address else None
        if proxy_arg:
            options.add_argument(proxy_arg)

        headless_mode = self.settings.get("headless", True)
        logger.info(
            f"Setting up main Chrome WebDriver (Headless: {headless_mode}, Connection: {proxy_display})...")
        logger.debug(f"  User Agent: {self.current_user_agent}")

        driver_instance = None
        timeout_start = time.monotonic()
        try:
            logger.debug(
                f"Initializing main WebDriver instance using driver: {driver_path_used}")
            # **FIXED**: No desired_capabilities argument needed
            driver_instance = webdriver.Chrome(
                service=service, options=options)
            instantiation_duration = time.monotonic() - timeout_start
            logger.debug(
                f"Main WebDriver instance created in {instantiation_duration:.2f}s")

            if self.settings.get("enable_stealth", True):
                stealth_start = time.monotonic()
                 logger.debug("Applying Selenium Stealth to main driver...")
                 try:
                    stealth(driver_instance, languages=["en-US", "en"], vendor="Google Inc.", platform="Win32",
                            webgl_vendor="Intel Inc.", renderer="Intel Iris OpenGL Engine", fix_hairline=True)
                    logger.debug(
                        f"Stealth applied successfully in {time.monotonic() - stealth_start:.2f}s")
                 except Exception as stealth_err:
                    logger.warning(
                        f"Error applying Selenium Stealth: {stealth_err}")

            # Assign to main instance variable on success
            self.driver = driver_instance
            setup_duration = time.monotonic() - timeout_start
            logger.info(
                f"Main WebDriver setup successful. Total time: {setup_duration:.2f}s")
            return self.driver

        except SessionNotCreatedException as e:
            logger.error(f"WebDriver Session Creation Failed: {e}")
             if "version" in str(e).lower():
                 logger.error(
                     ">>> CRITICAL: ChromeDriver version MISMATCHES Chrome version! <<<")
             self.current_proxy_address = None; self.current_user_agent = None
             return None
        except WebDriverException as e:
            err_str = str(e).lower()
             if any(msg in err_str for msg in ["proxy", "connection refused", "net::err_", "timeout", "dns_probe", "unreachable"]):
                 logger.error(
                     f"Connection/Proxy FAILED during WebDriver setup for '{proxy_display}'. Error: {type(e).__name__}")
             else:
                 logger.error(
                     f"General WebDriver setup error: {e}", exc_info=logger.level == logging.DEBUG)
             if driver_instance: try: driver_instance.quit() except: pass
             self.current_proxy_address = None
             self.current_user_agent = None
             return None
        except Exception as e:
            logger.critical(
                f"Unexpected critical error during WebDriver setup: {e}", exc_info=True)
            if driver_instance:
                try: driver_instance.quit() except: pass
            self.current_proxy_address = None; self.current_user_agent = None
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
        worker_ua = self.user_agent_generator.random
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
            # **FIXED**: No desired_capabilities argument needed
            driver_instance = webdriver.Chrome(
                service=service, options=options)
            logger.debug(
                f"Worker WebDriver instance created in {time.monotonic() - timeout_start:.2f}s")

            if self.settings.get("enable_stealth", True):
                try:
                    stealth(driver_instance, languages=["en-US", "en"], vendor="Google Inc.", platform="Win32",
                            webgl_vendor="Intel Inc.", renderer="Intel Iris OpenGL Engine", fix_hairline=True)
                 except Exception as stealth_err:
                    logger.warning(
                        f"Worker stealth apply error: {stealth_err}")

            return driver_instance  # Return the isolated instance

        except Exception as e:
             logger.error(f"Worker WebDriver setup failed: {type(e).__name__} - {e}", exc_info=logger.level == logging.DEBUG)
             if driver_instance:
                 try: driver_instance.quit() except: pass
             return None

    # --- Account Handling ---
    def generate_password(self, length=14):
        return EnhancedEmailCreator.generate_password(length)

    def generate_username(self, max_attempts=25):
        logger.debug("Generating username...")
        prefixes = ["the", "real", "official", "its", "just", "mr", "mrs", "dr"]; nouns = ["photo", "pixel", "insta", "gram", "snapshot", "view", "scene", "travel", "art", "life"]; suffixes = ["official", "creative", "vibes", "world", "pics", "shots", "daily", "studio"]; separators = ["", ".", "_"]; numbers = [str(random.randint(10,999)), time.strftime("%y"), time.strftime("%m%d")]
        for attempt in range(max_attempts):
            try:
                parts = [random.choice(nouns)]
                if random.random() < 0.4:
                    parts.insert(0, random.choice(prefixes))
                if random.random() < 0.5: parts.append(random.choice(suffixes))
                if random.random() < 0.6:
                    parts.append(random.choice(numbers))
                sep = random.choice(separators); username = sep.join(random.sample(parts, len(parts)))[:28]
                username = re.sub(r'[^a-z0-9._]', '', username.lower())
                username = re.sub(r'[._]{2,}', '.', username).strip('._')
                if 3 <= len(username) <= 30 and not username.isdigit():
                    logger.debug(f"Generated username: '{username}' (Attempt {attempt+1})"); return username
            except Exception as e: logger.warning(f"Username generation attempt {attempt+1} error: {e}")
        fallback = f"user_{int(time.time()) % 10000}_{random.randint(100, 999)}"[:30]
        logger.warning(f"Username gen failed. Fallback: {fallback}"); return fallback

    def create_temporary_account(self, email=None, username=None, password=None):
        action_id = ''.join(random.choices(
            string.ascii_lowercase + string.digits, k=6))
        logger.info(f"AccCreate-{action_id}: Starting...")
        account_info = None
        local_driver = None
        proxy_used = "Unknown"
        final_status = "failed_init"
        try:
            local_driver = self._setup_driver()  # Uses main setup logic
            if not local_driver:
                # Raise the exception correctly
                raise WebDriverException(
                    "WebDriver setup failed for account creation.")

            # Correct assignment for proxy_used
            proxy_used = "Direct" if self.current_proxy_address is None else self.current_proxy_address

            creation_email = email or self.email_creator.create_temporary_email()
            logger.info(
                f"AccCreate-{action_id}: Using email: {creation_email}")
            if not creation_email:
                # Raise the exception correctly
                raise ValueError("Failed to generate email.")

            creation_username = username or self.generate_username()
            if not (3 <= len(creation_username) <= 30):
                raise ValueError(
                    f"Invalid username length: '{creation_username}'.")

            creation_password = password or self.generate_password()
            logger.info(
                f"AccCreate-{action_id}: Attempting signup for user: '{creation_username}'...")
            signup_successful = self.signup_with_selenium(creation_email,
                                                          creation_username,
                                                          creation_password,
                                                          driver_instance=local_driver)
            if not signup_successful:
                final_status = "failed_signup_stage"
                raise Exception(
                    f"Signup process via Selenium failed for '{creation_username}'.")

            self._random_delay(1, 3, local_driver)

            current_url = "ErrorFetchingURL"
            try:
                current_url = local_driver.current_url
                logger.debug(
                    f"AccCreate-{action_id}: URL after signup: {current_url}")
            except WebDriverException as e:  # Catch specific exception
                # Log the error but might continue if URL isn't critical or recovered
                logger.warning(
                    f"AccCreate-{action_id}: Could not get final URL after signup: {e}")
                # Keep current_url as "ErrorFetchingURL" to indicate failure to retrieve

            # Correctly indent the status checking block to be inside the main `try`
            if "ErrorFetchingURL" in current_url:
                final_status = "unknown_error"
            elif any(m in current_url for m in ["/challenge/", "/confirm/", "/sms/", "/contact_point/", "coig_restricted", "restrict"]):
                final_status = "verification_needed"
                logger.warning(
                    f"AccCreate-{action_id}: '{creation_username}' requires verification.")
            elif any(m in current_url for m in ["login", "suspended", "disabled", "emailsignup", "/error/", "/rejected/"]):
                final_status = "failed_creation"
                logger.error(
                    f"AccCreate-{action_id}: Creation failed/blocked for '{creation_username}'. URL: {current_url}")
                self._save_screenshot_safe(
                    f"creation_fail_{creation_username}", local_driver)
            elif "instagram.com" in current_url:
                final_status = "active"
                logger.info(
                    f"AccCreate-{action_id}: '{creation_username}' created successfully (pending popups).")
                self._handle_common_popups(
                    ["Not Now", "Cancel"], timeout=5, driver_instance=local_driver)
                self._handle_common_popups(
                    "Save Info", timeout=3, driver_instance=local_driver)
            else:
                final_status = "unknown_state"
                logger.error(
                    f"AccCreate-{action_id}: Unexpected state. URL: {current_url}")
                self._save_screenshot_safe(
                    f"creation_unknown_{creation_username}", local_driver)

            # Account saving logic should also be inside the main `try` block
            if final_status not in ["failed_creation", "failed_init", "unknown_error", "unknown_state", "failed_signup_stage"]:
                ua_string = "Unknown"
                try:
                    ua_string = local_driver.execute_script(
                        "return navigator.userAgent;")
                except Exception:  # Catch broader exception for safety
                    logger.warning(
                        f"AccCreate-{action_id}: Failed to get User Agent string.")
                    pass  # Continue without UA if it fails

                account_info = {
                    "username": creation_username,
                    "email": creation_email,
                    "password": creation_password,
                    "created_at": time.time(),
                    "status": final_status,
                    "reports_made": 0,
                    "last_report_time": 0,
                    "proxy_used": proxy_used,
                    "user_agent": ua_string
                }

                with self.account_lock:
                    if not any(acc['username'] == account_info['username'] for acc in self.accounts):
                        self.accounts.append(account_info)
                        logger.info(
                            f"AccCreate-{action_id}: Account '{creation_username}' added with status '{final_status}'.")
                    else:
                        logger.warning(
                            f"AccCreate-{action_id}: Account '{account_info['username']}' already exists, not re-adding.")

                self._save_account_to_csv(account_info)

        # Correct indentation for except and finally
        except (WebDriverException, ValueError, Exception) as e:
            logger.error(f"AccCreate-{action_id}: Process failed: {e}",
                         exc_info=logger.level == logging.DEBUG)
            # Ensure driver is passed for screenshot even on exception
            self._save_screenshot_safe(
                f"creation_exception_{username or 'random'}", local_driver)
            # Preserve more specific failure status if set before exception
            if final_status == "failed_init":
                final_status = f"failed_{type(e).__name__}"
        finally:
            if local_driver:
                logger.debug(
                    f"AccCreate-{action_id}: Closing creation driver.")
                try:
                    local_driver.quit()
                except Exception as qe:
                    logger.warning(f"Error closing creation driver: {qe}")

            # Use validated settings for delays
            delay_min = self.settings.get("account_creation_delay_min", 4.0)
            delay_max = self.settings.get("account_creation_delay_max", 10.0)
            # Ensure min <= max again just before use
            if delay_min > delay_max:
                delay_min = delay_max
            delay = random.uniform(delay_min, delay_max)
            logger.debug(
                f"AccCreate-{action_id}: Waiting {delay:.1f}s (Final Status: {final_status}).")
            time.sleep(delay)
            # Return account_info (will be None if creation failed before dict assembly)
            return account_info

    def signup_with_selenium(self, email, username, password, driver_instance):
        if not driver_instance:
            logger.error("Signup Failed: No WebDriver."); return False
        wait_timeout = self.settings.get("webdriver_wait_timeout", 15) + 5; wait = WebDriverWait(driver_instance, wait_timeout); signup_start_time = time.monotonic()
        logger.debug(f"Starting Selenium signup for '{username}'...")
        current_url = ""; try: current_url = driver_instance.current_url except: pass
        try:
            if "emailsignup" not in current_url:
                logger.debug(f"Navigating to signup: {self.platform_urls['signup']}"); driver_instance.get(self.platform_urls['signup']); self._random_delay(2.5, 4.5, driver_instance)
            try: consent_xpath = "//button[contains(., 'Allow all cookies') or contains(., 'Accept') or contains(., 'Allow essential and optional cookies')]"; consent_button = WebDriverWait(driver_instance, 5).until(EC.element_to_be_clickable((By.XPATH, consent_xpath))); self._js_click(consent_button, driver_instance); logger.info("Handled cookie consent."); self._random_delay(0.5, 1.5, driver_instance)
            except TimeoutException:
                logger.debug("No cookie consent banner found.");
            except Exception as e: logger.warning(f"Error clicking cookie consent: {e}")
            logger.debug("Filling signup form...")
            self._random_delay(0.5, 1.0, driver_instance)
            email_selectors = [(By.NAME, "emailOrPhone"), (By.XPATH, "//input[@aria-label='Mobile Number or Email']"),
                                (By.NAME, "emailOrPhoneNumber"), (By.XPATH, "//input[@aria-label='Phone number, username, or email']")]
            email_field = self._find_element_robust(driver_instance, email_selectors, wait, "Email/Phone")
            if not email_field:
                logger.error("SIGNUP FAILED: Email field not found."); return False; self._human_type(email_field, email, driver_instance)
            full_name = f"{random.choice(['Alex', 'Jamie', 'Chris', 'Sam'])} {random.choice(['Lee', 'Smith', 'Kim', 'Jones'])}"; name_selectors = [(By.NAME, "fullName"), (By.XPATH, "//input[@aria-label='Full Name']")]
            name_field = self._find_element_robust(driver_instance, name_selectors, wait, "Full Name")
            if not name_field:
                logger.error("SIGNUP FAILED: Name field not found."); return False; self._human_type(name_field, full_name, driver_instance)
            username_selectors = [(By.NAME, "username"), (By.XPATH, "//input[@aria-label='Username']")]
            username_field = self._find_element_robust(driver_instance, username_selectors, wait, "Username")
            if not username_field:
                logger.error("SIGNUP FAILED: Username field not found."); return False; self._human_type(username_field, username, driver_instance); self._random_delay(1.5, 2.5, driver_instance)
            password_selectors = [(By.NAME, "password"), (By.XPATH, "//input[@aria-label='Password']")]
            password_field = self._find_element_robust(driver_instance, password_selectors, wait, "Password")
            if not password_field:
                logger.error("SIGNUP FAILED: Password field not found."); return False; self._human_type(password_field, password, driver_instance); self._random_delay(0.5, 1.5, driver_instance)
            logger.debug("Clicking 'Sign up'..."); submit_xpath = "//button[.//div[contains(text(), 'Sign up')] or contains(., 'Sign up') or .//span[contains(text(), 'Sign up')] or @type='submit']"
            try:
                submit_button = wait.until(EC.element_to_be_clickable((By.XPATH, submit_xpath))); self._js_click(submit_button, driver_instance) or submit_button.click()
            except TimeoutException: logger.error("Signup Failed: 'Sign up' button not found/clickable."); self._save_screenshot_safe(f"signup_submit_fail_{username}", driver_instance); self._check_signup_page_errors(driver_instance, username); return False
            except Exception as e:
                logger.error(f"Error clicking Sign Up: {e}"); self._save_screenshot_safe(f"signup_submit_click_error_{username}", driver_instance); return False
            logger.info("'Sign up' clicked. Waiting..."); self._random_delay(7, 12, driver_instance)
            current_url = "Error"
            try: current_url = driver_instance.current_url; logger.debug(f"URL after submit: {current_url}") except WebDriverException as url_e: logger.warning(f"Error getting URL after submit: {url_e}"); return False
            if "/birthday/" in current_url:
                logger.info("Birthday prompt detected."); return self._handle_birthday_prompt(driver_instance=driver_instance)
            elif any(m in current_url for m in ["/challenge/", "/confirm/", "/sms/", "/contact_point/", "coig_restricted"]): logger.warning(f"Signup for '{username}' needs verification. URL: {current_url}"); return True
            elif "emailsignup" in current_url or "/accounts/signup/" in current_url:
                logger.error(f"Signup Failed: Still on signup page for '{username}'."); self._check_signup_page_errors(driver_instance, username); self._save_screenshot_safe(f"signup_stuck_on_page_{username}", driver_instance); return False
            elif any(m in current_url for m in ["suspended", "disabled", "rejected", "/error/"]): logger.error(f"Signup Failed: Blocked/rejected '{username}'. URL: {current_url}"); self._save_screenshot_safe(f"signup_blocked_{username}", driver_instance); return False
            elif "instagram.com" in current_url:
                logger.info(f"Signup successful for '{username}'. Landed: {current_url}"); self._handle_common_popups("Not Now", timeout=4, driver_instance=driver_instance); self._handle_common_popups("Save Info", timeout=3, driver_instance=driver_instance); return True
            else: logger.error(f"Signup Failed: Unexpected state for '{username}'. URL: {current_url}"); self._save_screenshot_safe(f"signup_unexpected_url_{username}", driver_instance); return False
        except (TimeoutException, NoSuchElementException, ElementNotInteractableException) as e:
            logger.error(f"Signup element interaction error: {type(e).__name__}", exc_info=logger.level == logging.DEBUG); self._save_screenshot_safe(f"signup_element_fail_{username}", driver_instance); self._check_signup_page_errors(driver_instance, username); return False
        except WebDriverException as e: logger.error(f"Signup WebDriverException: {e}", exc_info=True); self._save_screenshot_safe(f"signup_webdriver_exception_{username}", driver_instance); return False
        except Exception as e:
            logger.error(f"Signup unexpected error: {e}", exc_info=True); self._save_screenshot_safe(f"signup_unexpected_exception_{username}", driver_instance); return False
        finally: duration = time.monotonic() - signup_start_time; logger.debug(f"Signup process for '{username}' finished in {duration:.2f}s")

    def _check_signup_page_errors(self, driver_instance, username_attempt):
        if not driver_instance:
            return
        try:
            error_xpath = "//div[contains(@class, 'error')]//span | //p[contains(@class, 'error')] | //div[@role='alert']"
            error_elements = driver_instance.find_elements(By.XPATH, error_xpath); found_errors = False
            for el in error_elements:
                err_text = el.text.strip(); if err_text: logger.error(f"Signup page error for '{username_attempt}': '{err_text}'"); found_errors = True
            if not found_errors: logger.debug(f"No specific error elements on signup page for {username_attempt}.")
        except WebDriverException:
            logger.warning("Could not check signup page for errors.")
        except Exception as e: logger.warning(f"Error checking signup page errors: {e}")

    def _find_element_robust(self, driver, selectors, wait, element_name="Element"):
        last_exception = None; is_input = element_name in ["Email/Phone", "Full Name", "Username", "Password"]
        for i, (by, value) in enumerate(selectors):
            try:
                condition = EC.element_to_be_clickable((by, value)) if is_input else EC.visibility_of_element_located((by, value))
                wait_type = "clickability" if is_input else "visibility"
                element = wait.until(condition)
                logger.debug(f"Found {element_name} via {wait_type} on {by}='{value}'"); return element
            except (TimeoutException, NoSuchElementException, ElementNotInteractableException, StaleElementReferenceException) as e:
                last_exception = e; logger.debug(f"Failed {element_name} with {wait_type} on {by}='{value}' (Attempt {i+1}/{len(selectors)}). Err: {type(e).__name__}")
            except WebDriverException as e: logger.error(f"WDException finding {element_name}: {e}"); last_exception = e; break
        logger.error(f"{element_name} NOT found via ANY selector. Last err: {type(last_exception).__name__}")
        self._save_screenshot_safe(f"find_fail_{element_name.replace('/','_').replace(' ','_')}", driver); return None

    def _save_screenshot_safe(self, prefix, driver_instance=None):
        if self.settings.get("save_screenshots"):
            self._save_screenshot(prefix, driver_instance)

    def _human_type(self, element, text, driver_instance):
        try:
            try:
                element.click()
            except ElementClickInterceptedException: logger.warning(f"Click intercepted typing, trying JS click."); self._js_click(element, driver_instance)
            self._random_delay(0.05, 0.15)
            element.clear(); self._random_delay(0.1, 0.2)
            for char in text:
                element.send_keys(char); self._random_delay(0.03, 0.12)
            self._random_delay(0.1, 0.3)
        except (StaleElementReferenceException, ElementNotInteractableException) as e:
            logger.warning(f"Human typing failed ({type(e).__name__}), trying JS value set.")
            try:
                driver_instance.execute_script("arguments[0].value = arguments[1]; arguments[0].dispatchEvent(new Event('input', { bubbles: true }));", element, text) if element and element.is_enabled() else logger.error("Element invalid for JS set.")
            except Exception as js_e: logger.error(f"JS value set failed: {js_e}")
        except Exception as e:
            logger.error(f"Human typing error: {e}", exc_info=logger.level == logging.DEBUG)

    def _random_delay(self, min_sec=None, max_sec=None, driver_instance=None):
        min_d = min_sec if min_sec is not None else self.settings["random_delay_min"]
        max_d = max_sec if max_sec is not None else self.settings["random_delay_max"]; delay = max(0.1, random.uniform(min_d, max_d)); time.sleep(delay)

    def _js_click(self, element, driver_instance):
        if not element or not driver_instance:
            return False
        try: driver_instance.execute_script("arguments[0].scrollIntoViewIfNeeded(true);", element); self._random_delay(0.1, 0.25); driver_instance.execute_script("arguments[0].click();", element); logger.debug("JS click ok."); return True
        except (WebDriverException, StaleElementReferenceException) as e:
            logger.warning(f"JS click failed: {type(e).__name__} - {str(e)[:100]}"); return False
        except Exception as e: logger.warning(f"JS click failed unexpectedly: {e}"); return False

    def _save_screenshot(self, prefix="screenshot", driver_instance=None):
        driver = driver_instance or self.driver
        if not driver or not self.settings.get("save_screenshots"):
            return
        try:
            SCREENSHOT_DIR.mkdir(exist_ok=True)
            safe_prefix = re.sub(r'[^\w\-]+', '_', prefix); timestamp = time.strftime('%Y%m%d_%H%M%S'); rand = random.randint(100,999); filename = SCREENSHOT_DIR / f"{safe_prefix}_{timestamp}_{rand}.png"
            if driver.save_screenshot(str(filename)):
                logger.info(f"Screenshot: {filename.name}")
            else: logger.warning(f"Screenshot save returned False for: {filename.name}")
        except WebDriverException as e:
            err_msg=str(e).lower();
            if any(term in err_msg for term in ["session deleted", "no such window", "invalid session id"]): logger.error(f"Cannot save screenshot '{prefix}': WD session closed."); self.close_driver()
            else:
                logger.error(f"WDException saving screenshot '{prefix}': {e}")
        except Exception as e: logger.error(f"Failed saving screenshot '{prefix}': {e}", exc_info=logger.level == logging.DEBUG)

    def _handle_birthday_prompt(self, timeout=10, driver_instance=None):
        driver = driver_instance or self.driver
        if not driver: return False; logger.debug("Handling birthday..."); wait = WebDriverWait(driver, timeout)
        try:
            month_xpath = "//select[@title='Month:' or starts-with(@aria-label,'Month')]"
            day_xpath = "//select[@title='Day:' or starts-with(@aria-label,'Day')]"; year_xpath = "//select[@title='Year:' or starts-with(@aria-label,'Year')]"; next_xpath = "//button[normalize-space()='Next' or .//div[normalize-space()='Next'] or .//span[normalize-space()='Next']]"
            month_dp = wait.until(EC.visibility_of_element_located((By.XPATH, month_xpath)))
            day_dp = wait.until(EC.visibility_of_element_located((By.XPATH, day_xpath))); year_dp = wait.until(EC.visibility_of_element_located((By.XPATH, year_xpath)))
            year = random.randint(1988, 2005)
            month = random.randint(1, 12); day = random.randint(1, 28)
            Select(month_dp).select_by_value(str(month))
            self._random_delay(0.2, 0.5, driver); Select(day_dp).select_by_value(str(day)); self._random_delay(0.2, 0.5, driver); Select(year_dp).select_by_value(str(year)); self._random_delay(0.3, 0.7, driver)
            next_btn = wait.until(EC.element_to_be_clickable((By.XPATH, next_xpath)))
            self._js_click(next_btn, driver); logger.info(f"Submitted birthday: {month}/{day}/{year}"); self._random_delay(4, 7, driver); return True
        except (TimeoutException, NoSuchElementException) as e:
            logger.error(f"Birthday elements error: {type(e).__name__}"); self._save_screenshot_safe("birthday_prompt_fail", driver); return False
        except Exception as e: logger.error(f"Birthday prompt error: {e}", exc_info=logger.level == logging.DEBUG); self._save_screenshot_safe("birthday_prompt_exception", driver); return False

    def _handle_common_popups(self, button_text_keywords, timeout=5, driver_instance=None):
        driver = driver_instance or self.driver
        if not driver: return False
        if isinstance(button_text_keywords, str):
            keywords = [button_text_keywords.lower()]
        elif isinstance(button_text_keywords, list): keywords = [str(k).lower() for k in button_text_keywords if k]
        else:
            logger.warning(f"Invalid keywords for popup: {type(button_text_keywords)}"); return False
        if not keywords: logger.warning("No valid keywords for popup handling."); return False
        logger.debug(
            f"Checking popup for buttons: {keywords} (Timeout: {timeout}s)")
        try:
            kw_cond = " or ".join(
                [f"contains(translate(normalize-space(.), 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), '{kw}')" for kw in keywords])
            xpath = (
                f"(//div[@role='dialog' or @role='alertdialog'] | //body/div[count(./*) < 5])" f"//button[({kw_cond}) and not(@disabled)]" f" | " f"(//div[@role='dialog' or @role='alertdialog'] | //body/div[count(./*) < 5])" f"//*[@role='button'][({kw_cond}) and not(@aria-disabled='true')]")
            popup_button = WebDriverWait(driver, timeout).until(
                EC.element_to_be_clickable((By.XPATH, xpath)))
            btn_text = "[Text Error]"
            try: btn_text = popup_button.text.strip() or popup_button.get_attribute('aria-label') or "[Label Error]" except: pass
            if self._js_click(popup_button, driver):
                logger.info(f"Clicked popup button: '{btn_text}' (Matched: {keywords})"); self._random_delay(0.8, 1.8, driver); return True
            else: logger.warning(f"Found popup button '{btn_text}' but JS click failed."); return False
        except (TimeoutException, NoSuchElementException, StaleElementReferenceException):
            logger.debug(f"Popup matching '{keywords}' not found/stale within {timeout}s."); return False
        except WebDriverException as e: level = logging.DEBUG if logger.level == logging.DEBUG else logging.WARNING; logger.log(level, f"WDException handling popup '{keywords}': {type(e).__name__}"); return False
        except Exception as e:
            logger.warning(f"Unexpected error handling popup '{keywords}': {e}", exc_info=logger.level==logging.DEBUG); return False

    def _save_account_to_csv(self, account_dict):
        if not account_dict or not account_dict.get('username'):
            logger.error("Attempted save invalid account data."); return
        file_path = Path(ACCOUNT_CSV_FILENAME); fieldnames = ["username", "email", "password", "status", "created_at", "reports_made", "last_report_time", "proxy_used", "user_agent"]; username_to_save = account_dict['username']
        logger.debug(f"Saving/Updating '{username_to_save}' in CSV '{file_path.name}'...")
        with self._csv_lock:
            try:
                accounts_data = []
                file_exists = file_path.is_file(); updated = False
                if file_exists:
                    try:
                        with open(file_path, "r", newline="", encoding='utf-8') as infile:
                            reader = csv.DictReader(infile)
                            if not reader.fieldnames or not all(f in reader.fieldnames for f in ["username", "password"]):
                                logger.error(f"CSV '{file_path.name}' invalid header. Will overwrite."); file_exists = False
                            else: accounts_data = [row for row in reader if any(row.values())]
                    except (FileNotFoundError, PermissionError):
                        logger.error(f"Cannot read existing CSV '{file_path.name}'."); file_exists = False
                    except Exception as read_err: logger.error(f"Error reading CSV '{file_path.name}': {read_err}. Will overwrite.", exc_info=True); file_exists = False
                row_data = account_dict.copy()
                for key in ["created_at", "last_report_time"]:
                    ts = row_data.get(key)
                    row_data[key] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts)) if isinstance(ts, (int, float)) and ts > 0 else ""
                account_found_index = next((i for i, acc in enumerate(
                    accounts_data) if acc.get('username') == username_to_save), -1)
                if account_found_index != -1:
                    for key, value in row_data.items():
                        accounts_data[account_found_index][key] = value # Update all fields
                    updated = True; logger.debug(f"Updating entry for '{username_to_save}'.")
                else:
                    new_row = {field: row_data.get(field, "") for field in fieldnames}; accounts_data.append(new_row); logger.debug(f"Adding new entry for '{username_to_save}'.")
                try:
                    with open(file_path, "w", newline="", encoding='utf-8') as outfile:
                        writer = csv.DictWriter(outfile, fieldnames=fieldnames, extrasaction='ignore', restval='')
                        writer.writeheader(); writer.writerows(accounts_data)
                    logger.info(
                        f"Successfully {'updated' if updated else 'added'} '{username_to_save}' in '{file_path.name}'.")
                except (PermissionError, csv.Error, IOError) as write_e:
                    logger.critical(f"CSV SAVE FAILED for '{username_to_save}' to '{file_path}': {write_e}")
            except Exception as outer_e: logger.error(f"Outer CSV save error for '{username_to_save}': {outer_e}", exc_info=True)

    def load_accounts_from_csv(self, filename=ACCOUNT_CSV_FILENAME):
        file_path = Path(filename)
        logger.info(f"Loading accounts from: {file_path.name}")
        if not file_path.is_file():
            logger.warning(f"Account file '{filename}' not found."); self.accounts = []; return
        loaded_accounts = []; loaded_usernames = set(); required_fields = ["username", "password"]
        try:
            with self._csv_lock, open(file_path, "r", newline="", encoding='utf-8') as file:
                reader = csv.DictReader(file)
                if not reader.fieldnames or not all(f in reader.fieldnames for f in required_fields):
                    logger.error(f"CSV '{filename}' missing headers. Load aborted."); self.accounts = []; return
                for i, row in enumerate(reader):
                    line_num = i + 2
                    if not any(row.values()): continue
                    username = row.get("username", "").strip()
                    password = row.get("password", "").strip()
                    if not username or not password:
                        logger.warning(f"Skipping row {line_num}: Missing user/pass."); continue
                    if username in loaded_usernames: logger.warning(f"Skipping duplicate user '{username}' at row {line_num}."); continue
                    email = row.get("email", "").strip()
                    status = (row.get("status", "").strip().lower() or "unknown")

                    def parse_ts(ts_str, name):
                        if not ts_str:
                            return 0.0
                        try: return time.mktime(time.strptime(ts_str, "%Y-%m-%d %H:%M:%S"))
                        except (ValueError, TypeError, OSError):
                            logger.warning(f"Row {line_num}: Invalid {name} '{ts_str}'."); return 0.0
                    created_ts = parse_ts(row.get("created_at", "").strip(), "created_at"); last_report_ts = parse_ts(row.get("last_report_time", "").strip(), "last_report_time")
                    reports_made = 0; reports_str = row.get("reports_made", "0").strip()
                    if reports_str:
                        try: reports_made = max(0, int(reports_str)) except ValueError: logger.warning(f"Row {line_num}: Invalid reports_made '{reports_str}'.")
                    account = {"username": username, "password": password, "email": email, "status": status, "created_at": created_ts, "reports_made": reports_made, "last_report_time": last_report_ts, "proxy_used": row.get("proxy_used", "").strip(), "user_agent": row.get("user_agent", "").strip()}
                    loaded_accounts.append(account)
                    loaded_usernames.add(username)
            with self.account_lock:
                self.accounts = loaded_accounts; logger.info(f"Loaded {len(self.accounts)} unique accounts from '{filename}'.")
        except (PermissionError, csv.Error, IOError) as e: logger.critical(f"CSV LOAD FAILED '{file_path}': {e}"); self.accounts = []
        except Exception as e:
            logger.error(f"Failed loading accounts from '{filename}': {e}", exc_info=True); self.accounts = []

    # --- Login Method ---

    def login(self, account_to_login, driver_instance_override=None, update_main_driver=True):
        """Logs into an Instagram account. Can use override driver and optionally update self.driver."""
        if not account_to_login or not account_to_login.get('username'):
            logger.error("Login Failed: Invalid account data."); return False
        username = account_to_login['username']; password = account_to_login['password']
        log_prefix_base = f"Login-{username[:10]}"
        logger.info(f"[{log_prefix_base}]: Attempting login...")
        driver_to_use = driver_instance_override  # Use override if provided
        is_isolated = driver_instance_override is not None
        if is_isolated:
            update_main_driver = False; log_prefix_base += "-Iso"
        # Check if already logged in (only applies if using main driver)
        if not is_isolated and self.driver and self.current_account and self.current_account.get('username') == username:
            try:
                WebDriverWait(self.driver, 3).until(EC.presence_of_element_located((By.XPATH, "//nav"))); logger.info(f"[{log_prefix_base}]: Session active. Skipping."); return True
            except: logger.warning(f"[{log_prefix_base}]: Session inactive. Proceeding."); self.close_driver()
        elif not is_isolated and self.driver:  # Close existing main driver if different user
            prev_user = self.current_account.get('username', '?') if self.current_account else '?'
            logger.info(f"[{log_prefix_base}]: Closing existing session for '{prev_user}'."); self.close_driver()

        login_success = False
        max_attempts = self.settings.get("max_login_attempts", 2)
        local_driver_for_login = None  # Only used if NOT providing an override driver

        for attempt in range(max_attempts):
            log_prefix = f"{log_prefix_base}-Att-{attempt+1}"
            logger.info(f"[{log_prefix}]: Starting attempt...")
            # Get driver for this attempt
            if driver_to_use:
                driver_instance = driver_to_use # Use the override provided (for first attempt only if override used)
            else: # Need to manage local driver lifecycle
                 if local_driver_for_login:
                     try: local_driver_for_login.quit() except: pass; local_driver_for_login = None; self.current_proxy_address = None
                 local_driver_for_login = self._setup_driver() # Setup main driver if not isolated
                 if not local_driver_for_login:
                     logger.warning(f"[{log_prefix}]: WebDriver setup failed. Retrying..."); if attempt < max_attempts - 1: self._random_delay(5, 10); continue
                 driver_instance = local_driver_for_login

            if not driver_instance:
                continue # Skip attempt if driver setup failed

            try:
                wait_timeout = self.settings.get("webdriver_wait_timeout", 15) + 10
                wait = WebDriverWait(driver_instance, wait_timeout)
                login_url = self.platform_urls['login']
                logger.debug(f"[{log_prefix}]: Navigating to {login_url}"); driver_instance.get(login_url); self._random_delay(1.5, 3.5, driver_instance)
                self._handle_common_popups(
                    ["Accept", "Allow"], timeout=5, driver_instance=driver_instance)
                logger.debug(f"[{log_prefix}]: Filling form...")
                user_selectors = [(By.NAME, "username"), (By.XPATH, "//input[@aria-label='Phone number, username, or email']")]; pass_selectors = [(By.NAME, "password"), (By.XPATH, "//input[@aria-label='Password']")]
                user_field = self._find_element_robust(driver_instance, user_selectors, wait, "Login Username")
                if not user_field: continue
                pass_field = self._find_element_robust(driver_instance, pass_selectors, wait, "Login Password")
                if not pass_field: continue
                self._human_type(user_field, username, driver_instance)
                self._human_type(pass_field, password, driver_instance); self._random_delay(0.5, 1.5, driver_instance)
                logger.debug(f"[{log_prefix}]: Clicking button...")
                login_xpath = "//button[@type='submit'][.//div[contains(text(),'Log in')] or contains(., 'Log in') or contains(.,'Log In')]"; login_btn = self._find_element_robust(driver_instance, [(By.XPATH, login_xpath)], wait, "Login Button"); if not login_btn: continue
                self._js_click(login_btn, driver_instance)
                logger.info(f"[{log_prefix}]: Login clicked. Waiting...")
                outcome_timeout = 30
                conditions = [ EC.url_contains("?__coig_login"), EC.url_matches(r"https://www\.instagram\.com/(?:$|\?.*$)"), EC.presence_of_element_located((By.XPATH, "//nav")), EC.url_contains("/challenge/"), EC.url_contains("/suspended/"), EC.url_contains("/disabled/"), EC.url_contains("/onetap/"), EC.url_contains("/login/"), EC.presence_of_element_located((By.ID, "slfErrorAlert")), EC.presence_of_element_located((By.XPATH, "//*[contains(text(), 'password was incorrect')]")), EC.presence_of_element_located((By.XPATH, "//*[contains(text(), 'find your account')]")), EC.presence_of_element_located((By.XPATH, "//*[contains(text(), 'Turn on Notifications')]")) ]
                try:
                    WebDriverWait(driver_instance, outcome_timeout).until(EC.any_of(*conditions)); logger.debug(f"[{log_prefix}]: Outcome condition met."); self._random_delay(1.5, 3.0, driver_instance)
                except TimeoutException: logger.error(f"[{log_prefix}]: Login outcome timed out."); self._save_screenshot_safe(f"login_timeout_{username}", driver_instance); continue
                current_url = "Error"
                page_source_lower = ""; try: current_url = driver_instance.current_url; page_source_lower = driver_instance.page_source.lower() except WebDriverException: pass; logger.debug(f"[{log_prefix}]: Analyzing outcome. URL: {current_url}")
                if ("password was incorrect" in page_source_lower or "find your account" in page_source_lower or driver_instance.find_elements(By.ID, "slfErrorAlert")):
                    logger.error(f"[{log_prefix}]: Login Failed: Incorrect creds."); account_to_login["status"] = "login_failed"; break
                elif "/challenge/" in current_url: logger.error(f"[{log_prefix}]: Login Failed: Challenge."); account_to_login["status"] = "challenge"; break
                elif any(b in current_url for b in ["/suspended/", "/disabled/", "account_disabled"]):
                    logger.error(f"[{log_prefix}]: Login Failed: Banned/Disabled."); account_to_login["status"] = "banned"; break
                elif "/onetap/" in current_url or "turn_on_notifications" in current_url: logger.info(f"[{log_prefix}]: Intermediate page. Dismissing..."); dismissed = self._handle_common_popups(["Not Now", "Cancel"], timeout=5, driver_instance=driver_instance); if dismissed: self._random_delay(2, 4, driver_instance); try: current_url = driver_instance.current_url except: pass else: logger.warning(f"[{log_prefix}]: Failed dismiss intermediate."); continue
                if ("instagram.com" in current_url and not any(f in current_url for f in ["/login", "/challenge/", "/suspended/", "/disabled/", "/error/"])):
                    try:
                        WebDriverWait(driver_instance, 5).until(EC.presence_of_element_located((By.XPATH, "//nav | //div[@role='navigation']"))); logger.info(f"[{log_prefix}]: Login SUCCESS."); login_success = True; account_to_login["status"] = "active"
                        if update_main_driver: self.driver = driver_instance; self.current_account = account_to_login; local_driver_for_login = None # Hand over driver if updating main
                        self._handle_common_popups(["Not Now", "Cancel"], timeout=6, driver_instance=driver_instance)
                        self._handle_common_popups("Save Info", timeout=4, driver_instance=driver_instance); break
                    except:
                        logger.error(f"[{log_prefix}]: URL good but UI missing. Partial login?"); self._save_screenshot_safe(f"login_partial_{username}", driver_instance); continue
                else: logger.error(f"[{log_prefix}]: Unexpected state. URL: {current_url}"); self._save_screenshot_safe(f"login_unexpected_{username}", driver_instance); continue
            except WebDriverException as e:
                logger.error(f"[{log_prefix}]: WebDriverException: {e}", exc_info=logger.level == logging.DEBUG); self._save_screenshot_safe(f"login_wd_exception_{username}", driver_instance); if any(f in str(e).lower() for f in ["proxy", "refused", "net::err_", "timeout"]): logger.error(f"[{log_prefix}]: Failure likely network/proxy."); break # Don't retry network fails on same proxy?
            except Exception as e: logger.error(f"[{log_prefix}]: Unexpected error: {e}", exc_info=True); self._save_screenshot_safe(f"login_exception_{username}", driver_instance);
            finally:
                if is_isolated and not login_success: # If override driver failed, log it but don't quit it here (caller should manage)
                     logger.warning(f"[{log_prefix}]: Isolated login attempt failed. Caller should handle driver.")
                      driver_to_use = None  # Stop using override if it fails once
                 elif local_driver_for_login and not login_success:  # Quit locally managed driver if it failed
                     logger.debug(f"[{log_prefix}]: Closing driver for unsuccessful attempt."); try: local_driver_for_login.quit() except: pass; local_driver_for_login = None; self.current_proxy_address=None
            if attempt < max_attempts - 1 and not login_success:
                self._random_delay(2, 5)

        if not login_success:
            final_status = account_to_login.get('status', 'unknown_failure'); logger.error(f"All {max_attempts} login attempts FAILED for '{username}'. Final status: {final_status}"); if update_main_driver: self.current_account = None; self.driver = None; # Clear main state if main login failed
        else: logger.debug(f"Login sequence completed successfully for '{username}'.");
        self._save_account_to_csv(account_to_login)
        return login_success # Return driver only if isolated? No, return success boolean.

    # --- Report & Mass Report ---

    def report_account(self, target_username, reason="spam", driver_instance=None, reporting_account=None):
        driver = driver_instance or self.driver
        account = reporting_account or self.current_account
        if not driver:
            logger.error("Report Failed: No WebDriver."); return False
        if not account or 'username' not in account: logger.error("Report Failed: Invalid reporting account."); return False
        if not target_username or not isinstance(target_username, str) or not target_username.strip():
            logger.error("Report Failed: Invalid target."); return False
        target_username = target_username.strip(); current_acc_username = account.get('username', 'N/A'); log_prefix = f"Report-{current_acc_username[:10]}-to-{target_username[:10]}"; logger.info(f"[{log_prefix}]: Reporting '{target_username}' as '{reason}'")
        now = time.time()
        reports_made_today = account.get("reports_made", 0); last_report_time = account.get("last_report_time", 0); max_reports = self.settings.get("max_reports_per_day", 15); min_interval = self.settings.get("report_interval_seconds", 1800)
        if (now - last_report_time) > (86400 * 1.05):
            logger.info(f"[{log_prefix}]: Daily report count reset.") if reports_made_today > 0 else None; reports_made_today = 0; account["reports_made"] = 0
        if reports_made_today >= max_reports: logger.warning(f"[{log_prefix}]: Skipped - Daily limit ({max_reports}) reached."); account["_worker_rate_limited"] = True if reporting_account else False; return False # Flag for worker
        time_since_last = now - last_report_time
        if time_since_last < min_interval and last_report_time != 0:
            wait_needed = min_interval - time_since_last; logger.info(f"[{log_prefix}]: Skipped - Cooldown active. {wait_needed:.0f}s left."); account["_worker_rate_limited"] = True if reporting_account else False; return False
        account.pop("_worker_rate_limited", None) # Clear flag if checks pass
        wait_timeout = self.settings.get("webdriver_wait_timeout", 15) + 5
        wait = WebDriverWait(driver, wait_timeout); short_wait = WebDriverWait(driver, 10); profile_url = f"{self.platform_urls['base']}{urllib.parse.quote(target_username)}/"
        try:
            logger.debug(f"[{log_prefix}]: Navigating to {profile_url}")
            driver.get(profile_url); self._random_delay(2.5, 5, driver)
            try:
                not_found_xpath = "//*[contains(text(), \"Sorry, this page isn't available\") or contains(text(), \"Page Not Found\") or contains(text(), \"couldn't find this account\") or contains(h2,'Something Went Wrong')]"; WebDriverWait(driver, 4).until(EC.presence_of_element_located((By.XPATH, not_found_xpath))); logger.error(f"[{log_prefix}]: FAILED - Target '{target_username}' not found."); self._save_screenshot_safe(f"report_target_nf_{target_username}", driver); return "target_not_found"
            except TimeoutException: logger.debug(f"[{log_prefix}]: Target profile accessible.")
            except WebDriverException as wd_err:
                logger.error(f"[{log_prefix}]: WD error checking profile availability: {wd_err}"); return False
            logger.debug(f"[{log_prefix}]: Clicking options menu..."); opts_xpath = "//header//button[descendant::*[local-name()='svg' and @aria-label='Options']] | //header//button[.//span[@aria-label='Options']] | //div[h1]/following-sibling::button[.//span[@aria-label='Options']] | //h2/following-sibling::button[.//span[@aria-label='Options']] | //button[@aria-label='User options' or @aria-label='Options']";
            options_btn = self._find_element_robust(driver, [(By.XPATH, opts_xpath)], wait, "Profile Options Button")
            if not options_btn:
                logger.error(f"[{log_prefix}]: FAILED - Options button not found."); self._save_screenshot_safe(f"report_opts_fail_{target_username}", driver); return False
            self._js_click(options_btn, driver); self._random_delay(0.8, 1.8, driver)
            logger.debug(f"[{log_prefix}]: Clicking 'Report' option...")
            report_xpath = "//div[@role='dialog' or @role='menu']//button[normalize-space()='Report' or normalize-space()='Report...']"
            report_opt_button = self._find_element_robust(driver, [(By.XPATH, report_xpath)], short_wait, "Report Option")
            if not report_opt_button:
                logger.error(f"[{log_prefix}]: FAILED - 'Report' option not found."); self._save_screenshot_safe(f"report_menu_fail_{target_username}", driver); return False
            self._js_click(report_opt_button, driver); self._random_delay(1.5, 3, driver)
            logger.debug(f"[{log_prefix}]: Handling reason flow for '{reason}'")
            report_successful = self._handle_report_reason_flow(driver, reason, wait, short_wait, log_prefix)
            if report_successful:
                with self.account_lock:  # Ensure safe update even if called sequentially for now
                    current_reports = account.get("reports_made", 0); account["reports_made"] = current_reports + 1; account["last_report_time"] = now
                    logger.info(
                        f"[{log_prefix}]: Report successful. Count for '{current_acc_username}': {account['reports_made']}.")
                if account is self.current_account:
                    self._save_account_to_csv(account) # Save if it's the main account
                # Caller (e.g., worker) is responsible for saving passed accounts
                return True
            else:
                logger.error(f"[{log_prefix}]: Report failed during reason flow."); return False
        except WebDriverException as e: logger.error(f"[{log_prefix}]: WDException during report: {e}", exc_info=logger.level==logging.DEBUG); if any(t in str(e).lower() for t in ["session deleted","no such window","invalid session"]): self.close_driver(); return False
        except Exception as e:
            logger.error(f"[{log_prefix}]: Unexpected report error: {e}", exc_info=True); self._save_screenshot_safe(f"report_unexpected_{target_username}", driver); return False

    def _handle_report_reason_flow(self, driver, reason_str, wait, short_wait, log_prefix):
        reason_lower = reason_str.lower().strip()
        reason_map = {"spam": "spam", "scam": "scam or fraud", "hate": "hate speech", "bullying": "bullying or harassment", "nudity": "nudity or sexual", "violence": "violence or dangerous", "intellectual property": "intellectual property", "sale": "sale of illegal or regulated", "self-injury": "suicide or self-injury", "false information": "false information", "impersonation": "pretending to be", "underage": "under the age of 13", "something else": "something else"}; selected_reason_text = "Something Else"; primary_reason_keyword = None
        if reason_lower == "spam":
            primary_reason_keyword = reason_map["spam"]; selected_reason_text = "Spam"
        else:
            for key, keyword in reason_map.items():
                 if reason_lower == key.lower():
                     primary_reason_keyword = keyword; selected_reason_text = keyword.capitalize(); break
            if not primary_reason_keyword:
                for key, keyword in reason_map.items():
                     if key in reason_lower and len(key) > 4:
                         primary_reason_keyword = keyword; selected_reason_text = keyword.capitalize(); logger.debug(f"[{log_prefix}]: Partial match: '{reason_lower}' -> '{keyword}'."); break
        if not primary_reason_keyword: primary_reason_keyword = reason_map["something else"]; selected_reason_text = "Something Else"; logger.warning(f"[{log_prefix}]: Reason '{reason_lower}' unmapped. Using '{primary_reason_keyword}'.")
        logger.debug(f"[{log_prefix}]: Stage 1: Selecting '{selected_reason_text}'")
        stage1_xpath = f"//div[@role='dialog' or @role='alertdialog']//*[self::button or @role='button' or @role='radio' or @role='link' or ancestor::label[@role='radio']][contains(translate(normalize-space(.), 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), '{primary_reason_keyword}')][not(@disabled) and not(@aria-disabled='true')]"; stage1_choice = None
        try:
            stage1_choice = self._find_element_robust(
                driver, [(By.XPATH, stage1_xpath)], short_wait, f"Stage 1 ({selected_reason_text})")
            if not stage1_choice:
                 fallback_keyword = reason_map["something else"]; logger.warning(f"[{log_prefix}]: Stage 1 specific failed. Trying '{fallback_keyword}'."); fallback_xpath = f"//div[@role='dialog' or @role='alertdialog']//*[self::button or @role='button' or @role='radio' or @role='link' or ancestor::label[@role='radio']][contains(translate(normalize-space(.), 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), '{fallback_keyword}')][not(@disabled) and not(@aria-disabled='true')]"; stage1_choice = self._find_element_robust(driver, [(By.XPATH, fallback_xpath)], short_wait, f"Stage 1 Fallback")
            if not stage1_choice:
                logger.error(f"[{log_prefix}]: FAILED Stage 1 - Cannot find reason/fallback."); self._save_screenshot_safe("report_stage1_fail", driver); return False
            self._js_click(stage1_choice, driver); logger.info(f"[{log_prefix}]: Clicked Stage 1 element for '{selected_reason_text}' (or fallback)."); self._random_delay(1.5, 3, driver)
        except Exception as e1:
            logger.error(f"[{log_prefix}]: Error in Stage 1 click: {e1}"); return False
        max_stages = 5; submission_confirmed = False; stages_processed = 0;
        for stage_num in range(2, max_stages + 2):
            logger.debug(f"[{log_prefix}]: Processing report stage {stage_num}..."); action_taken = False; stages_processed += 1; confirmation_xpath = "//*[contains(text(), 'Thanks for reporting') or contains(text(), 'Report sent') or contains(text(), 'Report submitted') or contains(text(),'We received your report')]"
            try:
                WebDriverWait(driver, 0.5).until(EC.presence_of_element_located((By.XPATH, confirmation_xpath))); logger.info(f"[{log_prefix}]: CONFIRMED by text stage {stage_num}."); submission_confirmed = True; self._handle_common_popups(["Close", "Done"], timeout=2, driver_instance=driver); break
            except TimeoutException: pass
            final_keywords = ["submit report", "submit", "done", "send report", "report account"]; final_xpath = f"//div[@role='dialog' or @role='alertdialog']//button[not(@disabled) and not(@aria-disabled='true') and (" + " or ".join([f"contains(translate(normalize-space(.), 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), '{kw}')" for kw in final_keywords]) + ")]"
            try:
                final_button = WebDriverWait(driver, 0.5).until(EC.element_to_be_clickable((By.XPATH, final_xpath))); btn_text = final_button.text.strip() or "[Submit]"; logger.info(f"[{log_prefix}]: Found final button '{btn_text}' stage {stage_num}. Clicking..."); self._js_click(final_button, driver); action_taken = True; self._random_delay(2.0, 4.0, driver)
                try:
                    WebDriverWait(driver, 3).until(EC.presence_of_element_located((By.XPATH, confirmation_xpath))); logger.info(f"[{log_prefix}]: CONFIRMED by text after clicking '{btn_text}'."); except TimeoutException: logger.warning(f"[{log_prefix}]: Clicked final '{btn_text}', no confirmation text. Assuming success.");
                submission_confirmed = True; self._handle_common_popups(["Close", "Done"], timeout=2, driver_instance=driver); break
            except TimeoutException:
                logger.debug(f"[{log_prefix}]: No final button stage {stage_num}.")
            except Exception as e_final: logger.warning(f"[{log_prefix}]: Error clicking final button: {e_final}")
            if not action_taken:
                next_xpath = "//div[@role='dialog' or @role='alertdialog']//button[normalize-space()='Next' and not(@disabled) and not(@aria-disabled='true')]"
                try:
                    next_button = WebDriverWait(driver, 0.5).until(EC.element_to_be_clickable((By.XPATH, next_xpath))); logger.info(f"[{log_prefix}]: Found 'Next' stage {stage_num}. Clicking..."); self._js_click(next_button, driver); action_taken = True; self._random_delay(1.5, 3, driver)
                except TimeoutException: logger.debug(f"[{log_prefix}]: No 'Next' button stage {stage_num}.")
                except Exception as e_next:
                    logger.warning(f"[{log_prefix}]: Error clicking 'Next': {e_next}")
            if not action_taken:
                sub_opt_xpath = f"//div[@role='dialog' or @role='alertdialog']//label[@role='radio'][not(ancestor::*[contains(@style,'display: none')])] | //div[@role='dialog']//input[@type='radio'][not(@disabled)][not(ancestor::*[contains(@style,'display: none')])] | //div[@role='dialog']//div[@role='button' or @role='menuitemradio'][not(ancestor::*[contains(@style,'display: none')])]"
                 try:
                    sub_opts = WebDriverWait(driver, 1).until(EC.presence_of_all_elements_located((By.XPATH, sub_opt_xpath)))
                    clickable_opts = [el for el in sub_opts if el.is_displayed()]
                    if clickable_opts:
                        opt_to_click = clickable_opts[0]; opt_text = opt_to_click.text.strip() or opt_to_click.get_attribute('aria-label') or "[SubOpt]"; logger.info(f"[{log_prefix}]: Found sub-options stage {stage_num}. Clicking first: '{opt_text[:50]}...'"); self._js_click(opt_to_click, driver); action_taken = True; self._random_delay(1.0, 2.5, driver)
                    else: logger.debug(f"[{log_prefix}]: Sub-option elements present but not clickable stage {stage_num}.")
                 except TimeoutException:
                     logger.debug(f"[{log_prefix}]: No sub-options stage {stage_num}.")
                 except Exception as e_sub: logger.warning(f"[{log_prefix}]: Error handling sub-options: {e_sub}")
            if not action_taken:
                 logger.warning(f"[{log_prefix}]: No action in stage {stage_num}. Checking dialog status...")
                 dialog_marker_xpath = "//div[@role='dialog' or @role='alertdialog']//h1[contains(text(),'Report')]"
                 try:
                     WebDriverWait(driver, 0.5).until_not(EC.presence_of_element_located((By.XPATH, dialog_marker_xpath))); logger.info(f"[{log_prefix}]: Dialog marker gone stage {stage_num}. Assuming closure."); submission_confirmed = True; break
                 except TimeoutException: logger.error(f"[{log_prefix}]: Dialog marker remained stage {stage_num}. Flow STUCK."); self._save_screenshot_safe(f"report_stuck_stage_{stage_num}", driver); return False
                 except (NoSuchElementException, StaleElementReferenceException):
                     logger.info(f"[{log_prefix}]: Dialog marker gone (stale/no longer exists) stage {stage_num}. Assuming closure."); submission_confirmed = True; break
                 except WebDriverException as wd_stale: logger.warning(f"[{log_prefix}]: WD error check stale: {wd_stale}. Assuming closure."); submission_confirmed = True; break
            if action_taken and stage_num < max_stages + 1:
                self._random_delay(0.5, 1.0)
        if submission_confirmed: logger.info(f"[{log_prefix}]: Report reason flow completed."); return True
        else:
            logger.error(f"[{log_prefix}]: Report flow FAILED after {stages_processed} stages."); self._save_screenshot_safe("report_flow_fail_final", driver); return False

    def _mass_report_concurrent_logic(self, target, reason, accounts_to_use, max_workers, num_reports_per_account=1):
        results = {"success": 0, "failed_login": 0, "skipped_or_failed_report": 0, "target_not_found": 0, "worker_exception": 0,
            "rate_limited": 0, "total": len(accounts_to_use) * num_reports_per_account, "target": target, "reason": reason, "details": []}
        actual_workers = max(1, min(max_workers, len(accounts_to_use)))
        logger.info(
            f"Mass Report Mgr: Starting {results['total']} reports for '{target}' using {actual_workers} workers across {len(accounts_to_use)} accounts...")
        tasks = []
        for acc in accounts_to_use:
             for i in range(num_reports_per_account):
                 tasks.append((acc, target, reason, i + 1))
        random.shuffle(tasks) # Randomize order slightly
        with concurrent.futures.ThreadPoolExecutor(max_workers=actual_workers, thread_name_prefix='MassReportWorker') as executor:
            future_map = {executor.submit(
                self._mass_report_worker, task[0], task[1], task[2], task[3]): task[0]['username'] for task in tasks}
            processed_count = 0
            for future in concurrent.futures.as_completed(future_map):
                processed_count += 1
                user = future_map[future]; log_prefix = f"MassMgr-{user[:10]}"
                try:
                    job_result = future.result()
                    results["details"].append(job_result); outcome = job_result.get("outcome", "unknown")
                    if outcome == "success":
                        results["success"] += 1
                    elif outcome.startswith("failed_login"): results["failed_login"] += 1 # Only count login fail once per account? Hard with multi-reports. Count each fail.
                    elif outcome == "skipped_or_failed_report":
                        results["skipped_or_failed_report"] += 1
                    elif outcome == "target_not_found": results["target_not_found"] += 1
                    elif outcome == "rate_limited":
                        results["rate_limited"] += 1
                    elif "exception" in outcome or "unknown" in outcome: results["worker_exception"] += 1
                    else:
                        logger.warning(f"[{log_prefix}]: Unexpected worker outcome '{outcome}'."); results["worker_exception"] += 1
                    logger.debug(f"[{log_prefix}]: Worker job ({job_result.get('report_num', '?')}) for '{user}' outcome: {outcome}")
                except Exception as exc:
                    logger.error(f"[{log_prefix}]: CRITICAL error retrieving result for '{user}': {exc}"); results["worker_exception"] += 1; results["details"].append({"username": user, "outcome": "future_exception", "error_details": str(exc)});
                finally:
                    if hasattr(self, 'gui') and self.gui and hasattr(self.gui,'root') and self.gui.root.winfo_exists():
                         try:
                             self.gui.root.after(0, lambda p=processed_count, t=results['total']: self.gui.update_status(f"Mass Report Progress: {p}/{t} jobs done...", "info"));
                         if processed_count % 10 == 0 or processed_count == results['total']: self.gui.root.after(10, self.gui.update_account_listbox) # Update list less often
                         except Exception as gui_err:
                             logger.warning(f"GUI update error during mass report progress: {gui_err}")
        logger.info(f"Mass Report Concurrency FINISHED for '{target}'. Results: {results['success']}/{results['total']} OK, {results['failed_login']} LoginFail, {results['rate_limited']} RateLimit, {results['skipped_or_failed_report']} Skip/Fail, {results['target_not_found']} NoTgt, {results['worker_exception']} Err.")
        if hasattr(self, 'gui') and self.gui and hasattr(self.gui,'root') and self.gui.root.winfo_exists():
             final_msg = f"Mass Rpt Done '{target}'. OK:{results['success']}, LFail:{results['failed_login']}, RateL:{results['rate_limited']}, Skip:{results['skipped_or_failed_report']}, Err:{results['worker_exception']}"
             try:
                 self.gui.root.after(0, lambda msg=final_msg: self.gui.update_status(msg, "info")); self.gui.root.after(50, self.gui.update_account_listbox)
             except: pass
        return results

    def _mass_report_worker(self, account, target_username, reason, report_num):
        username = account.get("username", "Unknown")
        log_prefix = f"Worker-{username[:10]}-R{report_num}"; worker_driver = None; login_success = False; final_outcome = "unknown"; err_details = None
        try:
            logger.debug(f"[{log_prefix}]: Starting worker..."); worker_driver = self._setup_driver_for_worker()
            if not worker_driver:
                final_outcome = "failed_login_driver_setup"; raise Exception("Worker driver setup failed.")
            login_success = self._login_with_selenium_isolated(account, worker_driver, log_prefix); # Tries to log in using isolated driver
            if not login_success:
                final_outcome = account.get("status", "failed_login"); raise Exception(f"Worker login failed ({final_outcome}).") # Use status set by isolated login
            logger.debug(f"[{log_prefix}]: Login success. Proceeding to report {report_num}...");
            # Pass isolated driver and account dict to report method
            report_result = self.report_account(
                target_username, reason, worker_driver, account)
            if report_result is True:
                final_outcome = "success"; logger.info(f"[{log_prefix}]: Report successful.")
            elif report_result == "target_not_found": final_outcome = "target_not_found"; logger.warning(f"[{log_prefix}]: Target not found.")
            elif account.get("_worker_rate_limited"):
                final_outcome = "rate_limited"; logger.warning(f"[{log_prefix}]: Rate limited."); account.pop("_worker_rate_limited", None) # Clean up flag
            else: final_outcome = "skipped_or_failed_report"; logger.error(f"[{log_prefix}]: Report action failed/skipped.")
        except Exception as e:
            logger.error(f"[{log_prefix}]: Worker exception: {e}", exc_info=logger.level == logging.DEBUG); err_details = f"{type(e).__name__}: {str(e)[:150]}"; final_outcome = final_outcome if final_outcome != "unknown" else "worker_exception"; # Preserve specific login fail status
        finally:
            if worker_driver:
                logger.debug(f"[{log_prefix}]: Closing worker driver."); try: worker_driver.quit() except Exception as qe: logger.warning(f"[{log_prefix}]: Error closing worker driver: {qe}")
            self._save_account_to_csv(account) # Save updated account state (report count, last time)
            logger.debug(
                f"[{log_prefix}]: Worker finished. Final Outcome: {final_outcome}")
        return {"username": username, "outcome": final_outcome, "error_details": err_details, "report_num": report_num}

    def _login_with_selenium_isolated(self, account_to_login, driver_instance, log_prefix):
        if not driver_instance or not account_to_login:
            return False; username = account_to_login['username']; password = account_to_login['password']
        logger.debug(f"[{log_prefix}]: Isolated login for {username}...");
        try:
            wait = WebDriverWait(driver_instance, self.settings.get("webdriver_wait_timeout", 15) + 10)
            driver_instance.get(self.platform_urls['login']); self._random_delay(1.5, 3.5); self._handle_common_popups(["Accept", "Allow"], timeout=5, driver_instance=driver_instance)
            user_selectors = [(By.NAME, "username"), (By.XPATH,
                               "//input[@aria-label='Phone number, username, or email']")]
            user_field = self._find_element_robust(driver_instance, user_selectors, wait, f"IsoLoginUser")
            if not user_field: return False
            pass_selectors = [(By.NAME, "password"), (By.XPATH, "//input[@aria-label='Password']")]
            pass_field = self._find_element_robust(driver_instance, pass_selectors, wait, f"IsoLoginPass"); if not pass_field: return False
            self._human_type(user_field, username, driver_instance)
            self._human_type(pass_field, password, driver_instance); self._random_delay(0.5, 1.5)
            login_xpath = "//button[@type='submit'][.//div[contains(text(),'Log in')] or contains(., 'Log in')]"
            login_btn = self._find_element_robust(driver_instance, [(By.XPATH, login_xpath)], wait, f"IsoLoginBtn"); if not login_btn: return False
            self._js_click(login_btn, driver_instance); logger.debug(f"[{log_prefix}]: IsoLogin clicked. Waiting..."); outcome_timeout = 30
            conditions = [EC.url_contains("?__coig_login"), EC.url_matches(r"https://www\.instagram\.com/(?:$|\?.*$)"), EC.presence_of_element_located((By.XPATH, "//nav")), EC.url_contains("/challenge/"), EC.url_contains("/suspended/"), EC.url_contains("/disabled/"), EC.url_contains("/onetap/"), EC.url_contains("/login/"), EC.presence_of_element_located((By.ID, "slfErrorAlert")), EC.presence_of_element_located((By.XPATH, "//*[contains(text(), 'password was incorrect')]")), EC.presence_of_element_located((By.XPATH, "//*[contains(text(), 'find your account')]")), EC.presence_of_element_located((By.XPATH, "//*[contains(text(), 'Turn on Notifications')]")) ]
            try:
                WebDriverWait(driver_instance, outcome_timeout).until(EC.any_of(*conditions)); self._random_delay(1.5, 3.0)
            except TimeoutException: logger.error(f"[{log_prefix}]: Iso login outcome timeout."); self._save_screenshot_safe(f"iso_login_timeout_{username}", driver_instance); account_to_login["status"] = "login_timeout"; return False
            current_url = driver_instance.current_url
            page_source_lower = driver_instance.page_source.lower()
            if ("password was incorrect" in page_source_lower or "find your account" in page_source_lower or ("/login/" in current_url and driver_instance.find_elements(By.ID, "slfErrorAlert"))):
                logger.error(f"[{log_prefix}]: Iso Login Fail: Creds."); account_to_login["status"] = "login_failed"; return False
            elif "/challenge/" in current_url: logger.error(f"[{log_prefix}]: Iso Login Fail: Challenge."); account_to_login["status"] = "challenge"; return False
            elif any(b in current_url for b in ["/suspended/", "/disabled/"]):
                logger.error(f"[{log_prefix}]: Iso Login Fail: Banned."); account_to_login["status"] = "banned"; return False
            elif "/onetap/" in current_url or "turn_on_notifications" in current_url: logger.info(f"[{log_prefix}]: Iso intermediate page. Dismiss..."); if not self._handle_common_popups(["Not Now", "Cancel"], timeout=5, driver_instance=driver_instance): logger.warning(f"[{log_prefix}] Failed dismiss intermediate."); return False; current_url = driver_instance.current_url # Recheck URL
            if ("instagram.com" in current_url and not any(f in current_url for f in ["/login", "/challenge/", "/suspended/", "/disabled/"])):
                try:
                    WebDriverWait(driver_instance, 5).until(EC.presence_of_element_located((By.XPATH, "//nav | //div[@role='navigation']"))); logger.info(f"[{log_prefix}]: Iso login success."); account_to_login["status"] = "active"; self._handle_common_popups(["Not Now", "Cancel"], timeout=6, driver_instance=driver_instance); self._handle_common_popups("Save Info", timeout=4, driver_instance=driver_instance); return True
                except: logger.error(f"[{log_prefix}]: Iso URL good but UI bad."); return False
            else:
                logger.error(f"[{log_prefix}]: Iso login unexpected state. URL: {current_url}"); return False
        except WebDriverException as e: logger.error(f"[{log_prefix}]: WDException in Iso login: {e}", exc_info=logger.level==logging.DEBUG); self._save_screenshot_safe(f"iso_login_wd_err_{username}", driver_instance); return False
        except Exception as e:
            logger.error(f"[{log_prefix}]: Unexpected error in Iso login: {e}", exc_info=True); self._save_screenshot_safe(f"iso_login_exc_{username}", driver_instance); return False

    # --- Data Extraction ---

    def _analyze_network_logs(self, logs):
        graphql_responses = []
        graphql_url_part = "/api/graphql"; relevant_methods = ["Network.responseReceived", "Network.dataReceived", "Network.loadingFinished"]; response_data_map = {}; finished_requests = {}
        try:
            for entry in logs:
                if not isinstance(entry, dict) or "message" not in entry:
                    continue
                try: message_data = json.loads(entry["message"]); log = message_data.get("message", {})
                except (json.JSONDecodeError, TypeError):
                    continue
                method = log.get("method"); params = log.get("params")
                if not params or method not in relevant_methods:
                    continue
                request_id = params.get("requestId"); if not request_id: continue
                if method == "Network.responseReceived":
                    response = params.get("response", {})
                    url = response.get("url", "")
                    if graphql_url_part in url:
                        finished_requests[request_id] = {"url": url, "headers": response.get("headers", {}), "status": response.get("status"), "mimeType": response.get("mimeType")}; response_data_map[request_id] = []
                elif method == "Network.dataReceived":
                    if request_id in response_data_map and not response_data_map[request_id]:
                        response_data_map[request_id].append(True) # Mark data received
                elif method == "Network.loadingFinished":
                    if request_id in finished_requests and request_id in response_data_map:
                        request_info = finished_requests[request_id]
                        if graphql_url_part in request_info.get("url", "") and response_data_map[request_id]:
                            body = None
                            decoded_body = None
                            try:
                                body_info = self.driver.execute_cdp_cmd('Network.getResponseBody', {'requestId': request_id})
                                body = body_info.get('body'); base64_encoded = body_info.get('base64Encoded', False)
                                if body:
                                     logger.debug(f"NetLog: Got body {request_id} (Base64: {base64_encoded})")
                                     decoded_body = base64.b64decode(body).decode('utf-8', 'ignore') if base64_encoded else body
                                     if decoded_body:
                                        try:
                                            json_data = json.loads(decoded_body)
                                             if isinstance(json_data, dict) and 'data' in json_data:
                                                 graphql_responses.append({"url": request_info.get("url"), "status": request_info.get("status"), "requestId": request_id, "data": json_data}); logger.debug(f"NetLog: Parsed GraphQL JSON {request_id}")
                                             elif isinstance(json_data, dict) and json_data.get('status') == 'fail': logger.warning(f"NetLog: GraphQL req {request_id} failed: {json_data.get('message', '?')}")
                                             else:
                                                 logger.debug(f"NetLog: Resp {request_id} JSON but not expected format.")
                                        except json.JSONDecodeError: logger.debug(f"NetLog: Fail decode JSON {request_id}. Body: {decoded_body[:100]}...")
                                        except Exception as parse_e:
                                            logger.warning(f"NetLog: Err processing JSON {request_id}: {parse_e}")
                                else: logger.debug(f"NetLog: getResponseBody empty body {request_id}")
                            except WebDriverException as cdp_e:
                                logger.debug(f"NetLog: CDP getResponseBody failed {request_id}: {cdp_e}") if "No resource with given identifier found" not in str(cdp_e) else None
                            except Exception as body_e: logger.warning(f"NetLog: Err get/process body {request_id}: {body_e}")
                        finished_requests.pop(request_id, None)
                        response_data_map.pop(request_id, None)
        except Exception as e:
            logger.error(f"Error processing performance logs: {e}", exc_info=True)
        logger.info(f"Analyzed network logs. Found {len(graphql_responses)} valid GraphQL responses.")
        return graphql_responses

    def extract_user_data(self, username):
        if not self.driver or not self.current_account:
            logger.error("Extract Failed: Login required."); return {"username": username, "extraction_status": "Login Required", "data": None}
        if not username or not isinstance(username, str) or not username.strip(): logger.error("Extract Failed: Invalid target."); return {"username": None, "extraction_status": "Missing Username", "data": None}
        target_username = username.strip()
        logger.info(f"Extracting data for '{target_username}'"); profile_url = f"{self.platform_urls['base']}{urllib.parse.quote(target_username)}/"; wait = WebDriverWait(self.driver, self.settings.get("webdriver_wait_timeout", 15)); start_time = time.monotonic()
        user_data = {"username": target_username, "extraction_timestamp": time.time(), "extraction_status": "pending", "profile_url": profile_url, "user_id": None, "full_name": None, "profile_pic_url": None, "is_private": None,
                                                                                    "is_verified": False, "follower_count": None, "following_count": None, "media_count": None, "biography": None, "external_url": None, "category_name": None, "recent_posts": [], "network_responses": []}
        try:
            try:
                self.driver.get_log('performance'); logger.debug("Cleared previous perf logs.") except: logger.warning("Could not clear perf logs.")
            logger.debug(f"Navigating to profile: {profile_url}"); self.driver.get(profile_url); self._random_delay(3, 5, self.driver)
            try:
                error_xpath = "//*[contains(text(), \"Sorry, this page isn't available\") or contains(text(), \"Page Not Found\") or contains(text(), \"couldn't find this account\") or contains(h2,'Something Went Wrong') or contains(text(),'Please wait a few minutes')]"; err_el = WebDriverWait(self.driver, 3).until(EC.presence_of_element_located((By.XPATH, error_xpath)))
                page_text = err_el.text.lower(); status = "Rate Limited" if "wait a few minutes" in page_text else "Profile not found"; logger.warning(f"Extraction stopped for '{target_username}': {status}."); user_data["extraction_status"] = status; return user_data
            except TimeoutException:
                logger.debug(f"Profile '{target_username}' accessible.")
            except WebDriverException as e: logger.warning(f"WD error checking profile availability: {e}")
            try:
                private_xpath = "//h2[contains(text(), 'This Account is Private') or contains(text(),'account is private')]"; WebDriverWait(self.driver, 1).until(EC.visibility_of_element_located((By.XPATH, private_xpath))); user_data["is_private"] = True; logger.info(f"'{target_username}' is Private.")
            except TimeoutException: user_data["is_private"] = False; logger.debug(f"'{target_username}' assumed Public.")
            except WebDriverException as e:
                logger.warning(f"WD error checking private status: {e}"); user_data["is_private"] = None
            def get_txt(driver, xpaths):
                for xp in xpaths:
                    try: return driver.find_element(By.XPATH, xp).text.strip() except: continue; return None
            def get_attr(driver, xpaths, attr):
                 for xp in xpaths:
                     try: return driver.find_element(By.XPATH, xp).get_attribute(attr) except: continue; return None
            def exists(driver, xpath):
                 try:
                     WebDriverWait(driver, 0.2).until(EC.presence_of_element_located((By.XPATH, xpath))); return True except: return False
            logger.debug("Scraping basic HTML info...");
            try:
                user_data["full_name"] = get_txt(self.driver, ["//header//h1", "//span[contains(@class,'FullName')]", "//section//h1"]); user_data["is_verified"] = exists(self.driver, "//header//*[local-name()='svg'][@aria-label='Verified']"); user_data["profile_pic_url"] = get_attr(self.driver, ["//header//img[contains(@alt, 'profile picture')]", "//div[contains(@class,'profile')]/img"], 'src'); bio_xps = ["//header//h1/following-sibling::span[1]", "//header//div/span[normalize-space()]", "//div[@data-testid='UserBio']"]; user_data["biography"] = get_txt(self.driver, bio_xps); url_xps = ["//header//a[@rel and contains(@href,'http')]", "//a[@data-testid='UserUrl']"]; user_data["external_url"] = get_attr(self.driver, url_xps, 'href')
            except Exception as html_err: logger.warning(f"Minor HTML scrape error: {html_err}", exc_info=logger.level == logging.DEBUG)
            logger.debug("Scraping HTML stats..."); stats_block = ""
            try:
                stats_xps = ["//header//ul", "//div[contains(@class,'Stats')]//span"];
                 for xp in stats_xps: try: stats_block = WebDriverWait(self.driver, 1).until(EC.visibility_of_element_located((By.XPATH, xp))).text; if stats_block: break except: continue
            except Exception as stats_err:
                logger.warning(f"Cannot find stats container via HTML: {stats_err}")
            def parse_ct(txt, kw_pat):
                 match = re.search(rf"([\d.,]+\s*[km]?)\s*{kw_pat}", txt, re.I)
                 if not match: return None; num_s = match.group(1).lower().replace(',', '').replace(' ', '').strip(); mult = 1_000_000 if 'm' in num_s else (1_000 if 'k' in num_s else 1); num_s = num_s.replace('m','').replace('k',''); try: return int(float(num_s)*mult) except: return None
            if stats_block:
                user_data["media_count"]=parse_ct(stats_block, r"posts?"); user_data["follower_count"]=parse_ct(stats_block, r"followers?"); user_data["following_count"]=parse_ct(stats_block, r"following"); logger.debug(f"HTML Stats: P={user_data['media_count']}, Flw={user_data['follower_count']}, Flg={user_data['following_count']}")
            else: logger.warning("Stats block not found via HTML.")
            if user_data["is_private"] is False:
                logger.debug("Scraping HTML posts..."); max_html_posts=6;
                try: post_link_xpath="//main//a[contains(@href, '/p/') or contains(@href, '/reel/')]"; post_els = WebDriverWait(self.driver, 3).until(EC.presence_of_all_elements_located((By.XPATH, post_link_xpath))); extracted=set();
                    for el in post_els:
                        if len(user_data["recent_posts"]) >= max_html_posts:
                            break
                        try: url = el.get_attribute('href'); match = re.search(r"/(?:p|reel)/([\w-]+)", url);
                             if match:
                                 code=match.group(1); if code not in extracted: thumb=get_attr(el, [".//img"], 'src'); user_data["recent_posts"].append({"code":code, "url":url, "thumbnail_url":thumb}); extracted.add(code)
                        except: continue; logger.debug(f"HTML Posts Scraped: {len(user_data['recent_posts'])}.")
                except TimeoutException:
                    logger.warning("Post grid/links timeout.")
                except Exception as post_err: logger.warning(f"HTML post scrape error: {post_err}")
            logger.debug("Retrieving & analyzing performance logs...")
            try:
                logs = self.driver.get_log('performance')
                if logs:
                    logger.info(f"Retrieved {len(logs)} perf log entries."); net_data = self._analyze_network_logs(logs); user_data["network_responses"] = net_data; user_info_resp = next((r['data'] for r in net_data if r.get('data',{}).get('data',{}).get('user')), None)
                    if user_info_resp and 'user' in user_info_resp.get('data', {}):
                        api_data = user_info_resp['data']['user']; logger.info(f"Found API user info ID: {api_data.get('id')}")
                        user_data.update({"user_id": api_data.get('id'), "full_name": api_data.get('full_name') or user_data["full_name"], "profile_pic_url": api_data.get('profile_pic_url_hd') or api_data.get('profile_pic_url') or user_data["profile_pic_url"], "is_private": api_data.get('is_private'), "is_verified": api_data.get('is_verified'), "biography": api_data.get('biography'), "external_url": api_data.get('external_url'), "category_name": api_data.get('category_name') });
                        m = api_data.get('edge_owner_to_timeline_media', {}).get('count'); f1 = api_data.get('edge_followed_by', {}).get('count'); f2 = api_data.get('edge_follow', {}).get('count')
                        if m is not None:
                            user_data["media_count"]=m;
                        if f1 is not None: user_data["follower_count"]=f1;
                        if f2 is not None:
                            user_data["following_count"]=f2;
                        media_edges = api_data.get('edge_owner_to_timeline_media', {}).get('edges', []); net_posts = []
                        if media_edges:
                            for edge in media_edges:
                                node=edge.get('node',{}); if node.get('shortcode'): net_posts.append({"code":node['shortcode'], "url":f"https://www.instagram.com/p/{node['shortcode']}/", "thumbnail_url":node.get('thumbnail_src'), "is_video":node.get('is_video',False), "likes":node.get('edge_liked_by',{}).get('count'), "comments":node.get('edge_media_to_comment',{}).get('count'), "timestamp":node.get('taken_at_timestamp')})
                            if net_posts: logger.debug(f"Merging {len(net_posts)} API posts."); user_data["recent_posts"] = net_posts # Prioritize API posts
                    else:
                        logger.warning("User info struct not found in network responses.")
                else: logger.warning("Performance log empty/failed.")
            except WebDriverException as log_e:
                logger.error(f"Failed get/process logs: {log_e}.")
            except Exception as e: logger.error(f"Unexpected log analysis error: {e}", exc_info=True)
            if user_data["extraction_status"] == "pending":
                status_det = "Public" if user_data["is_private"] is False else ("Private" if user_data["is_private"] is True else "Privacy?"); net_info = f"+ {len(user_data['network_responses'])} API Resp" if user_data["network_responses"] else "(No API)"; html_info = f"({('Partial' if any(v is None for k,v in user_data.items() if k in ['full_name','follower_count']) else 'Full')} HTML)"; user_data["extraction_status"] = f"Completed [{status_det}] {html_info} {net_info}"
            duration = time.monotonic() - start_time; logger.info(f"Extract finish for '{target_username}' ({user_data['extraction_status']}) in {duration:.2f}s"); return user_data
        except WebDriverException as e:
            logger.error(f"Extract WDException for '{target_username}': {e}", exc_info=logger.level==logging.DEBUG); if "session deleted" in str(e).lower(): self.close_driver(); user_data["extraction_status"] = "WebDriver Error"; return user_data
        except Exception as e: logger.error(f"Extract unexpected error for '{target_username}': {e}", exc_info=True); self._save_screenshot_safe(f"extract_fail_{target_username}"); user_data["extraction_status"] = "Unexpected Error"; return user_data

    def close_driver(self):
        """Closes the main WebDriver instance if it exists."""
        if self.driver:
            user = self.current_account.get('username', 'None') if self.current_account else 'None'
            logger.debug(f"Closing main WebDriver (Proxy: {self.current_proxy_address}, User: {user})...")
            try:
                self.driver.quit()
            except Exception as e: logger.error(f"Error during driver quit: {e}")
            finally:
                self.driver = None; self.current_account = None; self.current_proxy_address = None

# === GUI Class ===


class EnhancedInstagramManagerGUI:
    BG_COLOR = "#2E2E2E"; FG_COLOR = "#EAEAEA"; ACCENT_COLOR = "#C13584"; SECONDARY_COLOR = "#5851DB"; WIDGET_BG = "#3C3C3C"; WIDGET_FG = "#FFFFFF"; ERROR_COLOR = "#FF6B6B"; SUCCESS_COLOR = "#6BCB77"; LOG_TEXT_BG = "#252525"; LISTBOX_SELECT_BG = ACCENT_COLOR; TREEVIEW_HEAD_BG = SECONDARY_COLOR; PROGRESS_BAR_COLOR = SECONDARY_COLOR; LOG_COLOR_DEBUG = "grey60"; LOG_COLOR_INFO = FG_COLOR; LOG_COLOR_WARNING = "orange"; LOG_COLOR_ERROR = ERROR_COLOR; LOG_COLOR_CRITICAL = "#FF2020"

    def __init__(self, root, manager_instance):
        if not isinstance(root, tk.Tk):
            raise TypeError("GUI root must be tk.Tk")
        if not isinstance(manager_instance, EnhancedInstagramManager): raise TypeError("Requires EnhancedInstagramManager instance.")
        self.root = root
        self.manager = manager_instance; self.manager.gui = self
        self.log_queue = queue.Queue()
        log_level = logging.DEBUG if self.manager.settings.get(
            "debug_mode") else logging.INFO
        setup_global_logging(level=log_level, queue_ref=self.log_queue)
        logger.info("Initializing GUI...")
        self._configure_root_window()
        self._configure_styles()
        self.main_frame = ttk.Frame(self.root, padding="10")
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        self.tab_control = ttk.Notebook(self.main_frame, style="TNotebook")
        self.account_tab = ttk.Frame(self.tab_control, padding="10")
        self.proxy_tab = ttk.Frame(self.tab_control, padding="10"); self.report_tab = ttk.Frame(self.tab_control, padding="10"); self.data_tab = ttk.Frame(self.tab_control, padding="10"); self.settings_log_tab = ttk.Frame(self.tab_control, padding="10")
        self.tab_control.add(self.account_tab, text=" Accounts ")
        self.tab_control.add(self.proxy_tab, text=" Proxies "); self.tab_control.add(self.report_tab, text=" Reporting "); self.tab_control.add(self.data_tab, text=" Data Extraction "); self.tab_control.add(self.settings_log_tab, text=" Settings & Log ")
        self.tab_control.pack(fill=tk.BOTH, expand=True, pady=5)
        self.status_var = tk.StringVar(value="Initializing...")
        self.status_bar = ttk.Label(self.root, textvariable=self.status_var, style="Status.TLabel", relief=tk.SUNKEN, anchor=tk.W, padding=(5, 2)); self.status_bar.pack(side=tk.BOTTOM, fill=tk.X, pady=(5,0))
        self._action_buttons = []
        self._last_extracted_data = None; self._mass_report_active = threading.Event()
        self._init_setting_vars()
        self.setup_account_tab()
        self.setup_proxy_tab(); self.setup_report_tab(); self.setup_data_tab(); self.setup_settings_log_tab()
        self.update_account_listbox()
        self.update_proxy_treeview(); self.enable_actions(False)
        self.root.after(500, self.check_proxy_readiness)
        self.root.after(100, self.update_log_display); self.root.protocol("WM_DELETE_WINDOW", self.on_close); self.setup_error_handling()
        logger.info(
            f"GUI Initialized. (Startup: {time.monotonic() - START_TIME:.2f}s)")

    def _init_setting_vars(self):
        """ Initialize tk variables for settings before GUI elements are created. """
        self.settings_vars = {
            "debug_mode": tk.BooleanVar(value=self.manager.settings.get("debug_mode", False)),
            "headless": tk.BooleanVar(value=self.manager.settings.get("headless", True)),
            "enable_stealth": tk.BooleanVar(value=self.manager.settings.get("enable_stealth", True)),
            "save_screenshots": tk.BooleanVar(value=self.manager.settings.get("save_screenshots", False)),
            "use_direct_connection_fallback": tk.BooleanVar(value=self.manager.settings.get("use_direct_connection_fallback", True)),
            "geoip_db_path": tk.StringVar(value=self.manager.settings.get("geoip_db_path", "")),
            "chrome_driver_path": tk.StringVar(value=self.manager.settings.get("chrome_driver_path", "")),
            "chrome_binary_path": tk.StringVar(value=self.manager.settings.get("chrome_binary_path", "")),
            "random_delay_min": tk.DoubleVar(value=self.manager.settings.get("random_delay_min", 0.8)),
            "random_delay_max": tk.DoubleVar(value=self.manager.settings.get("random_delay_max", 2.5)),
            "account_creation_delay_min": tk.DoubleVar(value=self.manager.settings.get("account_creation_delay_min", 4.0)),
            "account_creation_delay_max": tk.DoubleVar(value=self.manager.settings.get("account_creation_delay_max", 10.0)),
            "report_interval_seconds": tk.IntVar(value=self.manager.settings.get("report_interval_seconds", 1800)),
            "webdriver_wait_timeout": tk.IntVar(value=self.manager.settings.get("webdriver_wait_timeout", 15)),
            "proxy_timeout": tk.IntVar(value=self.manager.settings.get("proxy_timeout", 7)),
            "max_login_attempts": tk.IntVar(value=self.manager.settings.get("max_login_attempts", 2)),
            "max_reports_per_day": tk.IntVar(value=self.manager.settings.get("max_reports_per_day", 15)),
            "proxy_test_threads": tk.IntVar(value=self.manager.settings.get("proxy_test_threads", 30)),
            "max_mass_report_workers": tk.IntVar(value=self.manager.settings.get("max_mass_report_workers", 5)),
        }

    def _configure_root_window(self):
        self.root.title(f"Enhanced Instagram Manager v2.8.2 - The Works ✨"); default_width, default_height = 1200, 850; min_width, min_height = 1000, 700
        try:
            screen_width = self.root.winfo_screenwidth(); screen_height = self.root.winfo_screenheight(); x_pos = max(0, (screen_width//2)-(default_width//2)); y_pos = max(0, (screen_height//2)-(default_height//2)); self.root.geometry(f"{default_width}x{default_height}+{x_pos}+{y_pos}")
        except: self.root.geometry(f"{default_width}x{default_height}")
        self.root.minsize(min_width, min_height)
        self.root.configure(bg=self.BG_COLOR)

    def _configure_styles(self):
        self.style = ttk.Style(); try: self.style.theme_use('clam') except tk.TclError: logger.warning("Clam theme N/A.")
        self.style.configure(".", background=self.BG_COLOR, foreground=self.FG_COLOR, fieldbackground=self.WIDGET_BG, insertcolor=self.WIDGET_FG, font=("Segoe UI", 9))
        self.style.map(".", background=[('disabled', self.BG_COLOR)], foreground=[('disabled', 'grey50')])
        self.style.configure("TFrame", background=self.BG_COLOR)
        self.style.configure("TLabel", background=self.BG_COLOR, foreground=self.FG_COLOR); self.style.configure("Header.TLabel", foreground=self.ACCENT_COLOR, font=("Segoe UI", 14, "bold")); self.style.configure("Status.TLabel", foreground=self.SECONDARY_COLOR, font=("Segoe UI", 9), background="#333333"); self.style.configure("Error.TLabel", foreground=self.ERROR_COLOR, font=("Segoe UI", 9, "bold")); self.style.configure("Success.TLabel", foreground=self.SUCCESS_COLOR, font=("Segoe UI", 9))
        self.style.configure("TButton", background=self.ACCENT_COLOR, foreground=self.WIDGET_FG, font=("Segoe UI", 10, "bold"), borderwidth=1, padding=(10, 6))
        self.style.map("TButton", background=[('active', self.SECONDARY_COLOR), ('disabled', '#555555')], foreground=[('disabled', '#AAAAAA')], relief=[('pressed', tk.SUNKEN), ('!pressed', tk.RAISED)])
        self.style.configure("TNotebook", background=self.BG_COLOR, borderwidth=0)
        self.style.configure("TNotebook.Tab", background=self.WIDGET_BG, foreground="grey85", font=("Segoe UI", 10), padding=[12, 6], borderwidth=0); self.style.map("TNotebook.Tab", background=[("selected", self.SECONDARY_COLOR)], foreground=[("selected", self.WIDGET_FG)], font=[("selected", ("Segoe UI", 10, "bold"))], expand=[("selected", [1, 1, 1, 0])])
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
        self.root.option_add('*TCombobox*Listbox.foreground', self.WIDGET_FG); self.root.option_add('*TCombobox*Listbox.selectBackground', self.SECONDARY_COLOR); self.root.option_add('*TCombobox*Listbox.selectForeground', self.WIDGET_FG); self.root.option_add('*TCombobox*Listbox.font', ("Segoe UI", 9))
        self.style.configure("Treeview", background=self.WIDGET_BG, foreground=self.WIDGET_FG, fieldbackground=self.WIDGET_BG, borderwidth=1, relief=tk.FLAT, rowheight=22)
        self.style.configure("Treeview.Heading", background=self.TREEVIEW_HEAD_BG, foreground=self.WIDGET_FG, font=("Segoe UI", 9, "bold"), relief=tk.FLAT, padding=(5, 5)); self.style.map("Treeview.Heading", background=[('active', self.ACCENT_COLOR)]); self.style.map("Treeview", background=[('selected', self.LISTBOX_SELECT_BG)], foreground=[('selected', self.WIDGET_FG)])
        self.style.configure("Vertical.TScrollbar", background=self.WIDGET_BG, troughcolor=self.BG_COLOR, borderwidth=0, arrowcolor=self.FG_COLOR)
        self.style.configure("Horizontal.TScrollbar", background=self.WIDGET_BG, troughcolor=self.BG_COLOR, borderwidth=0, arrowcolor=self.FG_COLOR); self.style.map("TScrollbar", background=[('active', self.SECONDARY_COLOR)])
        self.style.configure("Horizontal.TProgressbar", troughcolor=self.WIDGET_BG,
                             background=self.PROGRESS_BAR_COLOR, borderwidth=1, thickness=15)

    def setup_account_tab(self):
        logger.debug("Setting up Account tab...")
        main_acc_frame = ttk.Frame(self.account_tab)
        main_acc_frame.pack(fill=tk.BOTH, expand=True); main_acc_frame.rowconfigure(0, weight=1); main_acc_frame.columnconfigure(0, weight=1)
        list_frame = ttk.LabelFrame(main_acc_frame, text=" Saved Accounts ", style="TLabelframe")
        list_frame.grid(row=0, column=0, padx=5, pady=5, sticky="nsew"); list_scrollbar = ttk.Scrollbar(list_frame, orient="vertical", style="Vertical.TScrollbar"); list_scrollbar.pack(side=tk.RIGHT, fill=tk.Y); self.account_listbox = tk.Listbox(list_frame, bg=self.WIDGET_BG, fg=self.WIDGET_FG, selectbackground=self.LISTBOX_SELECT_BG, selectforeground=self.WIDGET_FG, font=("Segoe UI", 10), relief=tk.FLAT, highlightthickness=0, borderwidth=1, yscrollcommand=list_scrollbar.set); self.account_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True); list_scrollbar.config(command=self.account_listbox.yview); self.account_listbox.bind('<<ListboxSelect>>', self.on_account_select)
        manual_frame = ttk.LabelFrame(main_acc_frame, text=" Manual Login ", style="TLabelframe")
        manual_frame.grid(row=1, column=0, padx=5, pady=(10, 5), sticky="ew"); manual_frame.columnconfigure(1, weight=1); ttk.Label(manual_frame, text="Username:").grid(row=0, column=0, padx=5, pady=5, sticky="w"); self.manual_user_entry = ttk.Entry(manual_frame, width=30); self.manual_user_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew"); ttk.Label(manual_frame, text="Password:").grid(row=1, column=0, padx=5, pady=5, sticky="w"); self.manual_pass_entry = ttk.Entry(manual_frame, width=30, show="*"); self.manual_pass_entry.grid(row=1, column=1, padx=5, pady=5, sticky="ew"); self.manual_login_btn = ttk.Button(manual_frame, text="Login with These Credentials", command=self.manual_login, style="TButton"); self.manual_login_btn.grid(row=0, column=2, rowspan=2, padx=10, pady=5, sticky="ns")
        button_frame = ttk.Frame(main_acc_frame)
        button_frame.grid(row=2, column=0, padx=5, pady=(5, 0), sticky="ew"); button_frame.columnconfigure(0, weight=1); button_frame.columnconfigure(1, weight=1); self.create_account_btn = ttk.Button(button_frame, text="Create New Account", command=self.create_account, style="TButton"); self.create_account_btn.grid(row=0, column=0, padx=5, pady=5, sticky="ew"); self.login_btn = ttk.Button(button_frame, text="Login Selected Account", command=self.login_selected_account, style="TButton", state=tk.DISABLED); self.login_btn.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
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
        paned_window = ttk.PanedWindow(self.settings_log_tab, orient=tk.VERTICAL); paned_window.pack(fill=tk.BOTH, expand=True)
        settings_scroll_frame = ttk.Frame(paned_window)
        settings_canvas = tk.Canvas(settings_scroll_frame, bg=self.BG_COLOR, highlightthickness=0); settings_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True); settings_scrollbar = ttk.Scrollbar(settings_scroll_frame, orient="vertical", command=settings_canvas.yview, style="Vertical.TScrollbar"); settings_scrollbar.pack(side=tk.RIGHT, fill=tk.Y); settings_canvas.configure(yscrollcommand=settings_scrollbar.set); settings_inner_frame = ttk.Frame(settings_canvas, padding=10); settings_canvas.create_window((0,0), window=settings_inner_frame, anchor="nw"); settings_inner_frame.bind("<Configure>", lambda e: settings_canvas.configure(scrollregion=settings_canvas.bbox("all")))
        col_widths = [150, 80, 150, 80]
        num_cols = len(col_widths); current_row = 0
        ttk.Label(settings_inner_frame, text="Behavior", style="TLabelframe.Label").grid(row=current_row, column=0, columnspan=num_cols, sticky="w", pady=(0,5))
        current_row += 1
        ttk.Checkbutton(settings_inner_frame, text="Debug Mode", variable=self.settings_vars["debug_mode"], command=self.toggle_debug_mode, style="TCheckbutton").grid(
            row=current_row, column=0, columnspan=2, sticky="w", padx=5, pady=2)
        ttk.Checkbutton(settings_inner_frame, text="Run Headless", variable=self.settings_vars["headless"], command=self.update_manager_bool_setting(
            "headless"), style="TCheckbutton").grid(row=current_row+1, column=0, columnspan=2, sticky="w", padx=5, pady=2)
        ttk.Checkbutton(settings_inner_frame, text="Enable Stealth", variable=self.settings_vars["enable_stealth"], command=self.update_manager_bool_setting(
            "enable_stealth"), style="TCheckbutton").grid(row=current_row, column=2, columnspan=2, sticky="w", padx=5, pady=2)
        ttk.Checkbutton(settings_inner_frame, text="Save Screenshots", variable=self.settings_vars["save_screenshots"], command=self.update_manager_bool_setting("save_screenshots"), style="TCheckbutton").grid(row=current_row+1, column=2, columnspan=2, sticky="w", padx=5, pady=2)
        current_row += 2
        ttk.Checkbutton(settings_inner_frame, text="Use Direct Conn Fallback", variable=self.settings_vars["use_direct_connection_fallback"], command=self.update_manager_bool_setting("use_direct_connection_fallback"), style="TCheckbutton").grid(row=current_row, column=0, columnspan=2, sticky="w", padx=5, pady=2)
        current_row += 1
        ttk.Separator(settings_inner_frame, orient=tk.HORIZONTAL).grid(row=current_row, column=0, columnspan=num_cols, sticky='ew', pady=8)
        current_row += 1
        ttk.Label(settings_inner_frame, text="Timing (seconds)", style="TLabelframe.Label").grid(row=current_row, column=0, columnspan=num_cols, sticky="w", pady=(0,5))
        current_row += 1
        self._create_spinbox_setting(settings_inner_frame, current_row, 0,
                                     "Webdriver Wait Timeout:", self.settings_vars["webdriver_wait_timeout"], 5, 120)
        self._create_spinbox_setting(settings_inner_frame, current_row, 2, "Proxy Connect Timeout:", self.settings_vars["proxy_timeout"], 1, 60)
        current_row += 1
        self._create_spinbox_setting(settings_inner_frame, current_row, 0, "Min Action Delay:",
                                     self.settings_vars["random_delay_min"], 0.1, 60.0, is_float=True)
        self._create_spinbox_setting(settings_inner_frame, current_row, 2, "Max Action Delay:", self.settings_vars["random_delay_max"], 0.2, 120.0, is_float=True)
        current_row += 1
        self._create_spinbox_setting(settings_inner_frame, current_row, 0, "Min Acc Creation Delay:",
                                     self.settings_vars["account_creation_delay_min"], 1.0, 300.0, is_float=True)
        self._create_spinbox_setting(settings_inner_frame, current_row, 2, "Max Acc Creation Delay:", self.settings_vars["account_creation_delay_max"], 2.0, 600.0, is_float=True)
        current_row += 1
        self._create_spinbox_setting(settings_inner_frame, current_row, 0, "Report Interval:", self.settings_vars["report_interval_seconds"], 60, 86400)
        current_row += 1
        ttk.Separator(settings_inner_frame, orient=tk.HORIZONTAL).grid(row=current_row, column=0, columnspan=num_cols, sticky='ew', pady=8)
        current_row += 1
        ttk.Label(settings_inner_frame, text="Limits & Workers", style="TLabelframe.Label").grid(row=current_row, column=0, columnspan=num_cols, sticky="w", pady=(0,5))
        current_row += 1
        self._create_spinbox_setting(settings_inner_frame, current_row, 0,
                                     "Max Login Attempts:", self.settings_vars["max_login_attempts"], 1, 10)
        self._create_spinbox_setting(settings_inner_frame, current_row, 2, "Max Reports / Day / Acc:", self.settings_vars["max_reports_per_day"], 1, 1000)
        current_row += 1
        self._create_spinbox_setting(settings_inner_frame, current_row, 0,
                                     "Proxy Test Threads:", self.settings_vars["proxy_test_threads"], 1, 100)
        self._create_spinbox_setting(settings_inner_frame, current_row, 2, "Mass Report Workers:", self.settings_vars["max_mass_report_workers"], 1, 50)
        current_row += 1
        ttk.Separator(settings_inner_frame, orient=tk.HORIZONTAL).grid(row=current_row, column=0, columnspan=num_cols, sticky='ew', pady=8)
        current_row += 1
        ttk.Label(settings_inner_frame, text="Paths", style="TLabelframe.Label").grid(row=current_row, column=0, columnspan=num_cols, sticky="w", pady=(0,5))
        current_row += 1
        ttk.Label(settings_inner_frame, text="GeoIP DB:").grid(row=current_row, column=0, sticky="w", padx=5, pady=3)
        ttk.Entry(settings_inner_frame, textvariable=self.settings_vars["geoip_db_path"], width=45).grid(row=current_row, column=1, columnspan=2, sticky="ew", padx=5, pady=3); ttk.Button(settings_inner_frame, text="Browse...", command=lambda v=self.settings_vars["geoip_db_path"], t="GeoLite2 DB", ft=[("MMDB files", "*.mmdb")]: self.browse_file(v, t, ft)).grid(row=current_row, column=3, sticky="e", padx=5, pady=3); current_row += 1
        ttk.Label(settings_inner_frame, text="ChromeDriver (Opt):").grid(row=current_row, column=0, sticky="w", padx=5, pady=3)
        ttk.Entry(settings_inner_frame, textvariable=self.settings_vars["chrome_driver_path"], width=45).grid(row=current_row, column=1, columnspan=2, sticky="ew", padx=5, pady=3); ttk.Button(settings_inner_frame, text="Browse...", command=lambda v=self.settings_vars["chrome_driver_path"], t="ChromeDriver", ft=[("Executables", "*.exe"), ("All", "*.*")]: self.browse_file(v, t, ft)).grid(row=current_row, column=3, sticky="e", padx=5, pady=3); current_row += 1
        ttk.Label(settings_inner_frame, text="Chrome Binary (Opt):").grid(row=current_row, column=0, sticky="w", padx=5, pady=3)
        ttk.Entry(settings_inner_frame, textvariable=self.settings_vars["chrome_binary_path"], width=45).grid(row=current_row, column=1, columnspan=2, sticky="ew", padx=5, pady=3); ttk.Button(settings_inner_frame, text="Browse...", command=lambda v=self.settings_vars["chrome_binary_path"], t="Chrome", ft=[("Executables", "*.exe"), ("Apps", "*.app"), ("All", "*.*")]: self.browse_file(v, t, ft)).grid(row=current_row, column=3, sticky="e", padx=5, pady=3); current_row += 1
        self.save_settings_btn = ttk.Button(settings_inner_frame, text="💾 Save All Settings", command=self.save_gui_settings, style="TButton")
        self.save_settings_btn.grid(row=current_row, column=0, columnspan=num_cols, pady=15); current_row += 1
        paned_window.add(settings_scroll_frame)
        log_outer_frame = ttk.Frame(paned_window, padding=(5,0))
        log_frame = ttk.LabelFrame(log_outer_frame, text=" Application Log ", style="TLabelframe"); log_frame.pack(fill=tk.BOTH, expand=True)
        self.log_text = scrolledtext.ScrolledText(log_frame, bg=self.LOG_TEXT_BG, fg=self.FG_COLOR, insertbackground=self.FG_COLOR, wrap=tk.WORD, font=("Consolas", 9), relief=tk.FLAT, highlightthickness=0, borderwidth=1, state=tk.DISABLED)
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.log_text.tag_config("log_debug", foreground=self.LOG_COLOR_DEBUG)
        self.log_text.tag_config("log_info", foreground=self.LOG_COLOR_INFO); self.log_text.tag_config("log_warning", foreground=self.LOG_COLOR_WARNING); self.log_text.tag_config("log_error", foreground=self.LOG_COLOR_ERROR); self.log_text.tag_config("log_critical", foreground=self.LOG_COLOR_CRITICAL, font=("Consolas", 9, "bold"))
        paned_window.add(log_outer_frame)
        self.root.update_idletasks()
        pane_height = paned_window.winfo_height(); paned_window.sashpos(0, int(pane_height * 0.55))

    def _create_spinbox_setting(self, parent, grid_row, grid_col_start, label_text, tk_var, min_val, max_val, is_float=False):
        """ Helper to create a Label + Spinbox pair for numeric settings. """
        ttk.Label(parent, text=label_text).grid(row=grid_row, column=grid_col_start, sticky="w", padx=(5, 2), pady=3)
        increment = 0.1 if is_float else 1
        format_str = '%.1f' if is_float else '%0.f'
        # Extract setting key from label_text
        setting_key = label_text.lower().replace(" ", "_").replace(":", "").replace("/", "_").replace("_opt", "").replace("__","_")
        # Remove potentially problematic suffixes like _day_acc or _acc
        setting_key = setting_key.replace("_day_acc", "").replace("_acc","").replace("_threads", "_threads")
        # Fix specific keys if derivation is wrong
        if "webdriver_wait" in setting_key:
            setting_key = "webdriver_wait_timeout"
        elif "proxy_connect" in setting_key: setting_key = "proxy_timeout"
        elif "min_action" in setting_key:
            setting_key = "random_delay_min"
        elif "max_action" in setting_key: setting_key = "random_delay_max"
        elif "min_account_creation" in setting_key:
            setting_key = "account_creation_delay_min"
        elif "max_account_creation" in setting_key: setting_key = "account_creation_delay_max"
        elif "report_interval" in setting_key:
            setting_key = "report_interval_seconds"
        elif "login_attempts" in setting_key: setting_key = "max_login_attempts"
        elif "reports_day" in setting_key:
            setting_key = "max_reports_per_day"
        elif "proxy_test" in setting_key: setting_key = "proxy_test_threads"
        elif "mass_report" in setting_key:
            setting_key = "max_mass_report_workers"

        # logger.debug(f"Creating Spinbox for derived key: {setting_key} (from Label: '{label_text}')") # Debug derived key

        spin = ttk.Spinbox(
            parent, from_=min_val, to=max_val, increment=increment,
            textvariable=tk_var, width=8, style="TSpinbox", format=format_str,
            command=lambda k=setting_key: self.update_manager_numeric_setting(k)  # Use derived key
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
        if not self.root.winfo_exists():
            return
        selected_indices = self.account_listbox.curselection(); cur_val = self.account_listbox.get(selected_indices[0]) if selected_indices else None; self.account_listbox.delete(0, tk.END); new_selection_idx = None
        with self.manager.account_lock:
            sorted_accounts = sorted(
                self.manager.accounts, key=lambda x: x.get('username', '').lower())
            for idx, acc in enumerate(sorted_accounts):
                disp = f"{acc.get('username', '?')} - {acc.get('status','?').capitalize()} (R: {acc.get('reports_made',0)})"
                self.account_listbox.insert(tk.END, disp)
                if cur_val and disp == cur_val:
                    new_selection_idx = idx
        if new_selection_idx is not None: try: self.account_listbox.selection_set(new_selection_idx); self.account_listbox.activate(new_selection_idx); self.account_listbox.see(new_selection_idx) except: pass # Ignore error if index becomes invalid
        self.update_login_button_state()

    def on_account_select(self, event=None): self.update_login_button_state()

    def update_login_button_state(self):
        if not self.root.winfo_exists() or not hasattr(self, 'login_btn'):
            return
        try: self.login_btn.config(state=tk.NORMAL if self.account_listbox.curselection() else tk.DISABLED)
        except:
            pass # Ignore TclError

    def update_proxy_treeview(self):
        if not self.root.winfo_exists() or not hasattr(self, 'proxy_tree'):
            return
        selected_id = self.proxy_tree.selection()
        for item in self.proxy_tree.get_children():
            try: self.proxy_tree.delete(item) except: pass
        with self.manager.proxies_lock:
            sorted_proxies = sorted(
                self.manager.proxies, key=self.manager._proxy_sort_key)
            for proxy in sorted_proxies:
                addr = proxy.get('address','')
                disp_addr = addr if addr else 'Direct'; status = proxy.get('status','?').capitalize()
                latency = f"{proxy.get('latency'):.3f}" if isinstance(proxy.get('latency'),float) else "N/A"; country = proxy.get('country') or 'N/A'
                last_chk = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(proxy.get('last_checked', 0))) if proxy.get('last_checked') else "Never"
                item_id = addr if addr else "DIRECT"
                try: self.proxy_tree.insert("", tk.END, iid=item_id, values=(disp_addr, status, latency, country, last_chk)) except tk.TclError: pass
        if selected_id and self.proxy_tree.exists(selected_id[0]):
            try: self.proxy_tree.selection_set(selected_id[0]); self.proxy_tree.focus(selected_id[0]); self.proxy_tree.see(selected_id[0]) except: pass

    def update_proxy_gui_final(self):
        if not self.root.winfo_exists():
            return; self.update_proxy_treeview()
        if hasattr(self, 'proxy_progress') and self.proxy_progress.winfo_ismapped(): self.proxy_progress.grid_remove();
        self.refresh_proxies_btn.config(state=tk.NORMAL)
        with self.manager.proxies_lock:
            has_verified = any(p.get('status') == 'verified' for p in self.manager.proxies); count = len([p for p in self.manager.proxies if p.get('status')=='verified']);
        msg, level = (f"Proxy check complete. {count} verified.", "success") if has_verified else ("Proxy check complete. None verified.", "error"); self.update_status(msg, level); self.enable_actions(has_verified);

    def enable_actions(self, enabled=True):
        if not self.root.winfo_exists():
            return; target_state = tk.NORMAL if enabled else tk.DISABLED
        for btn in self._action_buttons:
            if hasattr(btn, 'winfo_exists') and btn.winfo_exists() and isinstance(btn, ttk.Button):
                try: btn.config(state=target_state) except: pass
        if hasattr(self, 'login_btn') and self.login_btn.winfo_exists(): try: self.login_btn.config(state=tk.NORMAL if enabled and self.account_listbox.curselection() else tk.DISABLED) except: pass
        if hasattr(self, '_mass_report_active') and self._mass_report_active.is_set():  # Disable specific buttons if mass report is active
            btns_to_disable = [getattr(self, name, None) for name in [
                                       "single_report_btn", "mass_report_btn", "extract_data_btn", "create_account_btn", "manual_login_btn"]]
            for btn in btns_to_disable:
                if btn and hasattr(btn, 'winfo_exists') and btn.winfo_exists(): try: btn.config(state=tk.DISABLED) except: pass

    def check_proxy_readiness(self):
        if not self.root.winfo_exists():
            return; is_ready = False
        if self.manager.first_proxy_available.is_set(): with self.manager.proxies_lock: is_ready = any(p.get('status') == 'verified' for p in self.manager.proxies)
        if is_ready:
            logger.info("Proxies ready. Enabling actions."); self.enable_actions(True); self.update_status("Ready.", "info")
        elif self.manager.proxy_load_thread_active.is_set(): self.update_status("Verifying proxies...", "info"); self.root.after(3000, self.check_proxy_readiness)
        else:
            logger.warning("Initial proxies not ready."); self.enable_actions(False); self.update_status("No working connections. Refresh proxies.", "error")

    def update_log_display(self):
        if not self.root.winfo_exists():
            return; max_lines = 100; processed = 0;
        try:
            while not self.log_queue.empty() and processed < max_lines:
                try:
                    level, msg = self.log_queue.get_nowait(); tag = GUI_LOG_TAGS.get(level, "log_info"); self.log_text.config(state=tk.NORMAL); self.log_text.insert(tk.END, msg + "\n", tag); self.log_text.config(state=tk.DISABLED); processed += 1
                except queue.Empty: break
            if processed > 0:
                self.log_text.see(tk.END)
        except Exception as e: print(f"Log display error: {e}") # Use print as logger might be involved
        self.root.after(200, self.update_log_display)

    def on_close(self):
        logger.info("User requested exit.")
        if messagebox.askokcancel("Quit", "Quit application?"):
            logger.info("Exit confirmed.")
            self._mass_report_active.set()  # Signal background threads (if they check)
            if self.manager:
                 if self.manager.driver:
                     logger.info("Closing WebDriver..."); self.manager.close_driver()
                 self.save_gui_settings(show_success=False) # Save settings on exit without popup
            self.root.destroy()
            logger.info("App shutdown.")
        else:
            logger.info("Exit cancelled.")

    def setup_error_handling(self):
        def handle_err(exc_type, exc_val, exc_tb):
            err_lines = traceback.format_exception(exc_type, exc_val, exc_tb)
            error_message = f"Unhandled GUI Error:\n{''.join(err_lines)}"; logger.critical(error_message); messagebox.showerror("Unhandled GUI Error", "Unexpected error. Check log.")
        self.root.report_callback_exception = handle_err
        logger.debug("Global Tkinter error handler set.")

    # --- Action Methods ---
    def create_account(self):
        logger.info("GUI: Create Account clicked.")
        self.update_status("Creating new account...", "info"); self.enable_actions(False)

        def task():
            info = None
            try:
                info = self.manager.create_temporary_account();
                if info: msg=f"Created: {info.get('username')} (Status: {info.get('status','?')})"; lvl="success" if info.get('status')=='active' else "warning"; self.root.after(0, self.update_status, msg, lvl); self.root.after(0, self.update_account_listbox)
                else:
                    self.root.after(0, self.update_status, "Account creation failed.", "error")
            except Exception as e: logger.error(f"Creation thread error: {e}", exc_info=True); self.root.after(0, self.update_status, "Creation error. See log.", "error")
            finally:
                self.root.after(100, lambda: self.enable_actions(True))
        threading.Thread(target=task, daemon=True, name="AccCreateThread").start()

    def manual_login(self):
        username = self.manual_user_entry.get().strip(); password = self.manual_pass_entry.get()
        if not username or not password:
            messagebox.showerror("Input Error", "Enter username and password."); return
        logger.info(f"GUI: Manual Login attempt: {username}"); self.update_status(f"Manual login as {username}...", "info"); self.enable_actions(False)
        manual_account = {"username": username,
            "password": password, "status": "manual"}

        def task():
            success = False
            try:
                success = self.manager.login(manual_account); msg = f"Manual login {('ok' if success else 'fail')} for {username}."; lvl = "success" if success else "error"; self.root.after(0, self.update_status, msg, lvl);
                 if success: logger.info(f"Manual login ok {username}.")
                 else:
                     self.manual_pass_entry.delete(0, tk.END)
            except Exception as e: logger.error(f"Manual login thread error: {e}", exc_info=True); self.root.after(0, self.update_status, f"Manual login error {username}. Log.", "error"); self.manual_pass_entry.delete(0, tk.END);
            finally:
                self.root.after(100, lambda: self.enable_actions(True))
        threading.Thread(target=task, daemon=True, name=f"ManualLogin-{username[:10]}").start()

    def login_selected_account(self):
        indices = self.account_listbox.curselection()
        if not indices:
            messagebox.showwarning("No Selection", "Select account first."); return
        try:
            listbox_text = self.account_listbox.get(indices[0]); match = re.match(r"^([\w.]+) -", listbox_text)
            if not match:
                logger.error(f"Cannot parse user from: '{listbox_text}'"); self.update_status("Error selecting.", "error"); return
            username = match.group(1)
            with self.manager.account_lock:
                account = next((acc for acc in self.manager.accounts if acc.get('username') == username), None)
            if not account: logger.error(f"User '{username}' not in manager list."); self.update_status("Error finding account.", "error"); return
            logger.info(f"GUI: Login clicked for: {account['username']}")
            self.update_status(f"Logging in as {account['username']}...", "info"); self.enable_actions(False)

            def task():
                success = False
                try:
                    success = self.manager.login(account); msg = f"Login {('ok' if success else 'fail')} for {account['username']}."; lvl = "success" if success else "error"; self.root.after(0, self.update_status, msg, lvl); self.root.after(0, self.update_account_listbox)
                except Exception as e: logger.error(f"Login thread error: {e}", exc_info=True); self.root.after(0, self.update_status, f"Login error {account['username']}. Log.", "error")
                finally:
                    self.root.after(100, lambda: self.enable_actions(True))
            threading.Thread(target=task, daemon=True, name=f"LoginThread-{account['username'][:10]}").start()
        except Exception as e:
            logger.error(f"Login prep error: {e}", exc_info=True); self.update_status("Error initiating login.", "error")

    def refresh_proxies(self):
        logger.info("GUI: Refresh Proxies clicked."); self.update_status("Refreshing proxies...", "info"); self.refresh_proxies_btn.config(state=tk.DISABLED)
        if hasattr(self, 'proxy_progress'):
            self.proxy_progress.config(value=0); self.proxy_progress.grid(row=0, column=0, padx=5, pady=5, sticky="ew") if not self.proxy_progress.winfo_ismapped() else None;
        self.enable_actions(False); gui_elements={'root':self.root,'gui_instance':self,'status_var':self.status_var,'progress_bar':getattr(self,'proxy_progress',None)}; self.manager.start_background_proxy_load(gui_elements=gui_elements)

    def single_report(self):
        target = self.target_entry.get().strip(); reason = self.report_reason_var.get()
        if not target:
            messagebox.showerror("Input Error", "Enter target username."); return
        if not self.manager.driver or not self.manager.current_account: messagebox.showerror("Login Required", "Must be logged in."); return
        user = self.manager.current_account['username']
        logger.info(f"GUI: Single Report '{target}' as '{reason}' by '{user}'"); self.update_status(f"Reporting '{target}' as '{reason}'...", "info"); self.enable_actions(False)

        def task():
            res = None
            try:
                res = self.manager.report_account(target, reason); # Uses main driver/account
                 if res is True: msg=f"Reported '{target}'."; lvl="success"; self.root.after(0, self.update_account_listbox)
                 elif res == "target_not_found":
                     msg=f"Report Fail: Target '{target}' not found."; lvl="error"
                 else: msg=f"Report failed/skipped '{target}'. Logs?"; lvl="error"
                 self.root.after(0, self.update_status, msg, lvl)
            except Exception as e:
                logger.error(f"Single report thread error: {e}", exc_info=True); self.root.after(0, self.update_status, f"Error reporting '{target}'. Log.", "error")
            finally: self.root.after(100, lambda: self.enable_actions(True))
        threading.Thread(target=task, daemon=True,
                         name=f"SingleReport-{target[:10]}").start()

    def mass_report(self):
        target = self.target_entry.get().strip(); reason = self.report_reason_var.get()
        if not target:
            messagebox.showerror("Input Error", "Enter target username."); return
        try: num_accounts_to_use = min(self.mass_report_accounts_var.get(), len(self.manager.accounts)); num_accounts_to_use = max(1, num_accounts_to_use)
        except:
            num_accounts_to_use = len(self.manager.accounts) # Fallback
        try: num_workers = self.settings_vars["max_mass_report_workers"].get()
        except:
            num_workers = self.manager.settings.get("max_mass_report_workers", 5) # Fallback
        with self.manager.account_lock: suitable_statuses={'active','unknown','verification_needed'}; all_accounts=[acc for acc in self.manager.accounts if acc.get('status','unknown') in suitable_statuses]; accounts_to_use=random.sample(all_accounts, min(num_accounts_to_use, len(all_accounts))) if len(all_accounts)>0 else []
        if not accounts_to_use:
            messagebox.showwarning("No Accounts", "No suitable accounts found."); return
        num_selected = len(accounts_to_use);
        if not messagebox.askyesno("Confirm Mass Report", f"Report '{target}' as '{reason}' using {num_selected} account(s) with up to {num_workers} workers?"):
            logger.info("Mass report cancelled."); return
        logger.info(f"GUI: Starting Mass Report. Target: '{target}', Reason: '{reason}', Accounts: {num_selected}, Workers: {num_workers}"); self.update_status(f"Mass reporting '{target}' ({num_selected} accounts)...", "info"); self._mass_report_active.set(); self.enable_actions(False)

        def task():
            try:
                self.manager._mass_report_concurrent_logic(target, reason, accounts_to_use, num_workers)
            except Exception as e: logger.error(f"Mass report mgr thread error: {e}", exc_info=True); self.root.after(0, self.update_status, "Mass report error. Log.", "error")
            finally:
                self._mass_report_active.clear(); self.root.after(200, lambda: self.enable_actions(True)); self.root.after(250, self.update_account_listbox)
        threading.Thread(target=task, daemon=True, name="MassReportManager").start()

    def extract_data(self):
        target = self.data_target_entry.get().strip()
        if not target:
            messagebox.showerror("Input Error", "Enter target username."); return
        if not self.manager.driver or not self.manager.current_account: messagebox.showerror("Login Required", "Must be logged in."); return
        user = self.manager.current_account['username']; logger.info(f"GUI: Extract Data '{target}' by '{user}'"); self.update_status(f"Extracting data for '{target}'...", "info"); self.enable_actions(False); self.save_data_btn.config(state=tk.DISABLED)
        self.data_results_text.config(state=tk.NORMAL)
        self.data_results_text.delete('1.0', tk.END); self.data_results_text.insert('1.0', f"Extracting data for {target}...\nPlease wait."); self.data_results_text.config(state=tk.DISABLED); self._last_extracted_data = None

        def task():
            data = None
            try:
                data = self.manager.extract_user_data(target); self._last_extracted_data = data; display_text = f"--- Extraction for {target} ---\nStatus: {data.get('extraction_status', '?')}\nTimestamp: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(data.get('extraction_timestamp', 0)))}\n{'-'*50}\n"; data_to_print = {k: v for k, v in data.items() if k not in ['network_responses', 'extraction_timestamp']};
                 try: display_text += json.dumps(data_to_print, indent=2, ensure_ascii=False)
                 except Exception as json_err:
                     display_text += f"\nError formatting: {json_err}\nRaw:\n{data_to_print}";
                 net_resp_count = len(data.get('network_responses', []));
                 if net_resp_count > 0:
                     display_text += f"\n\n{'-'*50}\nNetwork Analysis: Found {net_resp_count} relevant API responses (details logged).";
                 else: display_text += f"\n\n{'-'*50}\nNetwork Analysis: No relevant API responses found/captured.";
                 def update_gui(txt): self.data_results_text.config(state=tk.NORMAL); self.data_results_text.delete('1.0', tk.END); self.data_results_text.insert('1.0', txt); self.data_results_text.config(state=tk.DISABLED)
                 self.root.after(0, update_gui, display_text); status_level = "success" if "Completed" in data.get('extraction_status', '') else "warning"; self.root.after(0, self.update_status, f"Extract complete for '{target}'. Status: {data.get('extraction_status','?')}", status_level); self.save_data_btn.config(state=tk.NORMAL if data else tk.DISABLED)
            except Exception as e:
                logger.error(f"Extract thread error: {e}", exc_info=True); self.root.after(0, self.update_status, f"Error extracting '{target}'. Log.", "error"); self.save_data_btn.config(state=tk.DISABLED);
            finally: self.root.after(100, lambda: self.enable_actions(True))
        threading.Thread(target=task, daemon=True,
                         name=f"ExtractData-{target[:10]}").start()

    def save_extracted_data(self):
        if not self._last_extracted_data:
            messagebox.showwarning("No Data", "No data extracted yet."); return
        username = self._last_extracted_data.get("username", "unknown"); default_filename = f"{username}_data_{time.strftime('%Y%m%d_%H%M%S')}.json";
        filepath = filedialog.asksaveasfilename(title="Save Extracted Data", initialfile=default_filename, defaultextension=".json", filetypes=[
                                                ("JSON files", "*.json"), ("All", "*.*")])
        if not filepath:
            logger.debug("Save extracted data cancelled."); return
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(self._last_extracted_data, f, indent=2, ensure_ascii=False);
            logger.info(f"Saved extracted data for '{username}' to {filepath}"); self.update_status(f"Data saved to {Path(filepath).name}", "success")
        except Exception as e:
            logger.error(f"Failed saving extracted data: {e}", exc_info=True); messagebox.showerror("Save Error", f"Could not save data:\n{e}");
 
    # --- Settings Tab Actions ---
    def update_manager_bool_setting(self, setting_key):
        return lambda: self._update_setting(setting_key, self.settings_vars[setting_key].get())

    def update_manager_numeric_setting(self, setting_key):
         if setting_key in self.settings_vars:
             self._update_setting(setting_key, self.settings_vars[setting_key].get())
         else: logger.error(f"Unknown numeric setting key: {setting_key}")

    def _update_setting(self, key, value):
        if key in self.manager.settings:
             current_val = self.manager.settings[key]
              if type(current_val) != type(value) and not (isinstance(current_val,(int,float)) and isinstance(value,(int,float))):
                  logger.debug(f"Setting '{key}' type change: {type(current_val).__name__} -> {type(value).__name__}")
              self.manager.settings[key] = value
              logger.info(f"Setting '{key}' updated to: {value}"); self.update_status(f"Setting '{key}' updated.", "info")
         else:
             logger.error(f"Update non-existent setting: {key}")

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
                 try: tk_var.set(self.manager.settings[key]) except: pass
        self.manager.load_geoip_database(); self.manager.save_persistent_settings();
        if show_success:
            messagebox.showinfo("Settings Saved", "Settings saved & validated.");
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
    logger.info(f"Version: 2.5.1"); 
    logger.info(f"Python: {sys.version.split()[0]}, Platform: {sys.platform}"); 
    logger.info(f"PID: {os.getpid()}, CWD: {Path.cwd()}")
    try:
        LOG_DIR.mkdir(exist_ok=True); 
        SCREENSHOT_DIR.mkdir(exist_ok=True)
    except Exception as dir_err: 
        logger.error(f"Cannot create dirs: {dir_err}")
    try:
        manager = EnhancedInstagramManager()
        root = tk.Tk()
        root.withdraw()
        if sys.platform == "win32":
            try:
                ctypes.windll.shcore.SetProcessDpiAwareness(2); logger.info("DPI awareness set (Per-Monitor v2).")
            except (AttributeError, OSError): 
                try: ctypes.windll.user32.SetProcessDPIAware(); 
            logger.info("DPI awareness set (System Aware).") 
                except Exception as e: 
            logger.warning(f"SetProcessDPIAware failed: {e}")
                except Exception as e:
            logger.warning(f"DPI awareness check failed: {e}")
        app = EnhancedInstagramManagerGUI(root, manager)
        root.deiconify()
        root.mainloop()
        logger.info("GUI main loop exited.")
    except tk.TclError as e:
        logger.critical(f"Fatal Tkinter error: {e}", exc_info=True); 
        print(f"\nFATAL TKINTER ERROR: {e}", file=sys.stderr); 
        sys.exit(1)
    except ImportError as e: 
        logger.critical(f"Fatal Import Error: {e}", 
                        exc_info=True); 
        print(f"\nFATAL IMPORT ERROR: {e}", file=sys.stderr); 
        sys.exit(1)
    except Exception as e:
        logger.critical(f"Critical application error: {e}", 
                        exc_info=True); 
        print(f"\nFATAL APP ERROR: {e}", 
              file=sys.stderr); 
        log_path=LOG_DIR.resolve()/LOG_FILENAME; 
        print(f"Check log: '{log_path}'.", file=sys.stderr); 
        if 'manager' in locals() and manager and manager.driver: 
            print("Closing WebDriver due to error..."); 
            manager.close_driver(); 
            sys.exit(1)
    finally: print("\n" + "="*25 + " Application Exited " + "="*25)


if __name__ == "__main__":
    main()

# --- END OF FILE v2.8.2 ---