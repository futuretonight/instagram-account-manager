import requests # Added for making HTTP requests
import random # Added for generating random usernames
import time # Added for time-based operations
import logging # Added for logging
import json # Added for parsing JSON responses
import os # Added for file operations
import string # Added for generating random usernames
import re # Added for parsing proxies from HTML
import csv # Added for saving accounts to CSV
import threading # Added for loading proxies in background
import queue # Added for logging with GUI
import tkinter as tk
import hashlib # Added for hashing passwords
from tkinter import ttk, scrolledtext, messagebox
import concurrent.futures
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, NoSuchElementException
from fake_useragent import UserAgent

# Custom logging handler that works with GUI
class QueueHandler(logging.Handler):
    def __init__(self, log_queue):
        super().__init__()
        self.log_queue = log_queue
        
    def emit(self, record):
        self.log_queue.put(self.format(record))

class InstagramAccountManager:
    def __init__(self, log_queue=None):
        """Initialize the Instagram account manager."""
        self.proxies = []
        self.accounts = []
        self.current_proxy = None
        self.current_account = None
        self.driver = None
        self.user_agent = UserAgent()
        self.session = requests.Session()
        self.log_queue = log_queue
        
        # Configure logging
        self.setup_logging()
        
        # Default settings
        self.settings = {
            "max_accounts": 50,
            "max_reports_per_day": 10,
            "report_interval_seconds": 3600,
            "retry_attempts": 3,
            "backoff_factor": 2,
            "proxy_timeout": 5,
            "proxy_test_threads": 10,
            "use_direct_connection_fallback": True,
            "viewport_width": 1920,
            "viewport_height": 1080,
            "rotate_useragent": True,
            "random_delay_min": 1,
            "random_delay_max": 3
        }
        
        # URLs for Instagram
        self.platform_urls = {
            "base": "https://www.instagram.com/",
            "login": "https://www.instagram.com/accounts/login/",
            "report": "https://help.instagram.com/contact/1652567838289083",
            "api": "https://graph.instagram.com/v22.0/"
        }
        
        # Load proxies
        self.logger.info("Starting Instagram Account Manager")
        threading.Thread(target=self.load_proxies_from_internet, daemon=True).start()
    
    def setup_logging(self):
        """Set up logging to both file and queue (for GUI)."""
        self.logger = logging.getLogger("InstagramManager")
        self.logger.setLevel(logging.INFO)
        
        # File handler
        file_handler = logging.FileHandler("instagram_manager.log")
        file_handler.setLevel(logging.INFO)
        file_format = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(file_format)
        self.logger.addHandler(file_handler)
        
        # Queue handler (for GUI)
        if self.log_queue:
            queue_handler = QueueHandler(self.log_queue)
            queue_handler.setLevel(logging.INFO)
            queue_handler.setFormatter(file_format)
            self.logger.addHandler(queue_handler)
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(file_format)
        self.logger.addHandler(console_handler)
    
    def load_proxies_from_internet(self):
        """Load proxies from various internet sources."""
        self.logger.info("Loading proxies from internet sources")
        
        # Define headers to avoid scraping detection
        headers = {
            'User-Agent': self.user_agent.random,
            'Accept': 'text/html,application/xhtml+xml,application/xml',
            'Accept-Language': 'en-US,en;q=0.9',
            'Connection': 'keep-alive',
        }
        
        # Define proxy sources with their parsers
        proxy_sources = {
            'proxyscrape': {
                'url': 'https://api.proxyscrape.com/v2/?request=getproxies&protocol=http&timeout=10000&country=all&ssl=all&anonymity=all',
                'parser': self._parse_plain_text
            },
            'ssl_proxies': {
                'url': 'https://www.sslproxies.org/',
                'parser': self._parse_ssl_proxies
            },
            'free_proxy_list': {
                'url': 'https://free-proxy-list.net/',
                'parser': self._parse_ssl_proxies
            },
            'geonode': {
                'url': 'https://proxylist.geonode.com/api/proxy-list?limit=50&page=1&sort_by=lastChecked&sort_type=desc',
                'parser': self._parse_geonode
            }
        }
        
        all_proxies = []
        
        # Try each source
        for source_name, source_info in proxy_sources.items():
            try:
                self.logger.info(f"Fetching proxies from {source_name}")
                response = requests.get(source_info['url'], headers=headers, timeout=15)
                if response.status_code == 200:
                    parsed_proxies = source_info['parser'](response.text)
                    self.logger.info(f"Found {len(parsed_proxies)} proxies from {source_name}")
                    all_proxies.extend(parsed_proxies)
                else:
                    self.logger.warning(f"Failed to fetch from {source_name} - Status code: {response.status_code}")
            except Exception as e:
                self.logger.error(f"Error fetching from {source_name}: {e}")
        
        # Remove duplicates
        all_proxies = list(set(all_proxies))
        self.logger.info(f"Total of {len(all_proxies)} unique proxies collected")
        
        if not all_proxies:
            self.logger.warning("No proxies found from any sources. Adding fallback proxies.")
            # Add some popular public proxies as fallback
            fallback_proxies = [
                "51.159.24.172:3167",
                "157.230.32.15:43343",
                "95.216.194.46:1081",
                "167.71.5.83:8080",
                "178.62.193.217:3128"
            ]
            all_proxies = fallback_proxies
        
        # Verify proxies in parallel for efficiency
        self.proxies = self._verify_proxies_parallel(all_proxies)
        
        if not self.proxies and self.settings.get("use_direct_connection_fallback", True):
            self.logger.warning("No working proxies found. Using direct connection as fallback.")
            self.proxies = [""]  # Empty string for direct connection
            
        self.logger.info(f"Verified {len(self.proxies)} working proxies")
    
    def _parse_plain_text(self, text_content):
        """Parse proxies from plain text content."""
        proxies = []
        lines = text_content.strip().split('\n')
        for line in lines:
            if ':' in line and line.strip():
                proxies.append(line.strip())
        return proxies
    
    def _parse_ssl_proxies(self, html_content):
        """Parse proxies from sslproxies.org and similar sites."""
        proxies = []
        pattern = r'<tr><td>([\d\.]+)</td><td>(\d+)</td>'
        matches = re.findall(pattern, html_content)
        for ip, port in matches:
            proxies.append(f"{ip}:{port}")
        return proxies
    
    def _parse_geonode(self, json_content):
        """Parse proxies from geonode API."""
        proxies = []
        try:
            data = json.loads(json_content)
            for proxy in data.get('data', []):
                ip = proxy.get('ip')
                port = proxy.get('port')
                if ip and port:
                    proxies.append(f"{ip}:{port}")
        except:
            pass
        return proxies
    
    def _verify_proxy(self, proxy):
        """Verify a single proxy and return it if working."""
        if not proxy:  # Empty proxy is direct connection
            return ""
        try:
            test_url = "https://httpbin.org/ip"
            timeout = self.settings.get("proxy_timeout", 5)
            proxy_dict = {"http": f"http://{proxy}", "https": f"http://{proxy}"}
            response = requests.get(
                test_url,
                proxies=proxy_dict,
                timeout=timeout
            )
            if response.status_code == 200:
                return proxy
        except:
            pass
        return None
    
    def _verify_proxies_parallel(self, proxy_list):
        """Verify proxies in parallel for better performance."""
        verified_proxies = []
        max_threads = self.settings.get("proxy_test_threads", 10)
        self.logger.info(f"Verifying proxies in parallel with {max_threads} threads")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
            # Map each proxy to its verification result
            future_to_proxy = {executor.submit(self._verify_proxy, proxy): proxy for proxy in proxy_list}
            for future in concurrent.futures.as_completed(future_to_proxy):
                result = future.result()
                if result is not None:
                    verified_proxies.append(result)
                    if len(verified_proxies) >= 10:  # Stop after finding enough working proxies
                        for f in future_to_proxy:
                            f.cancel()
                        break
        
        return verified_proxies
    
    def _get_random_proxy(self):
        """Get a random proxy from the available pool."""
        if not self.proxies:
            self.logger.warning("No proxies available, using direct connection")
            return ""
        return random.choice(self.proxies)
    
    def _setup_driver(self):
        """Set up the Selenium WebDriver with enhanced anti-detection."""
        if self.driver:
            try:
                self.driver.quit()
            except:
                pass
        
        # Use webdriver_manager for automatic ChromeDriver management
        from webdriver_manager.chrome import ChromeDriverManager
        from selenium.webdriver.chrome.service import Service
        
        options = webdriver.ChromeOptions()
        
        # Updated options to handle deprecated endpoints
        options.add_argument('--disable-blink-features=AutomationControlled')
        options.add_argument('--disable-infobars')
        options.add_argument('--no-sandbox')
        options.add_argument('--disable-dev-shm-usage')
        options.add_argument('--log-level=3')  # Suppress console logging
        
        # Remove deprecated experimental options
        options.add_experimental_option('detach', False)
        options.add_experimental_option('excludeSwitches', ['enable-automation', 'enable-logging'])
        
        # Enhanced privacy and stealth settings
        options.add_argument('--disable-web-security')
        options.add_argument('--disable-features=IsolateOrigins,site-per-process')
        options.add_argument('--disable-site-isolation-trials')
        options.add_argument('--disable-notifications')
        options.add_argument('--disable-popup-blocking')
        options.add_argument('--disable-gpu')
        options.add_argument('--disable-extensions')
        
        # Viewport and user agent settings
        width = self.settings["viewport_width"]
        height = self.settings["viewport_height"]
        options.add_argument(f'--window-size={width},{height}')
        
        # Randomized user agent
        if self.settings["rotate_useragent"]:
            user_agent = self.user_agent.random
            options.add_argument(f'user-agent={user_agent}')
        
        # Proxy configuration
        self.current_proxy = self._get_random_proxy()
        if self.current_proxy:
            options.add_argument(f'--proxy-server={self.current_proxy}')
        
        try:
            # Use webdriver_manager to handle ChromeDriver installation
            service = Service(ChromeDriverManager().install())
            service.log_path = 'NUL'  # Suppress WebDriver logging on Windows
            
            # Create WebDriver instance
            self.driver = webdriver.Chrome(service=service, options=options)
            
            # CDP commands for additional stealth
            self.driver.execute_cdp_cmd('Network.setUserAgentOverride', {
                "userAgent": user_agent,
                "platform": "Windows",
                "acceptLanguage": "en-US,en;q=0.9"
            })
            
            # Enhanced stealth JavaScript
            self.driver.execute_script("""
                // Overwrite navigator properties
                Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
                Object.defineProperty(navigator, 'languages', {get: () => ['en-US', 'en']});
                Object.defineProperty(navigator, 'plugins', {get: () => [1, 2, 3, 4, 5]});
                Object.defineProperty(navigator, 'permissions', {get: () => {query: () => Promise.resolve({state: 'granted'})}});
                
                // Add Chrome runtime
                window.chrome = {
                    runtime: {},
                    loadTimes: function() {},
                    csi: function() {},
                    app: {}
                };
                
                // Modify permissions
                const originalQuery = window.navigator.permissions.query;
                window.navigator.permissions.query = (parameters) => (
                    parameters.name === 'notifications' ?
                    Promise.resolve({state: Notification.permission}) :
                    originalQuery(parameters)
                );
            """)
            
            # Set page load timeout and random delay
            self.driver.set_page_load_timeout(30)
            time.sleep(random.uniform(
                self.settings["random_delay_min"],
                self.settings["random_delay_max"]
            ))
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to initialize WebDriver: {e}")
            return False
    
    def create_temporary_account(self, email=None, username=None, password=None):
        """Create a temporary Instagram account with improved generation logic."""
        
        def generate_password():
            """Generate a secure random password."""
            length = random.randint(12, 16)
            chars = string.ascii_letters + string.digits + "!@#$%^&*"
            return ''.join(random.choice(chars) for _ in range(length))
            
        def generate_email():
            """Generate a random email address."""
            domains = ["gmail.com", "yahoo.com", "outlook.com", "hotmail.com"]
            username = ''.join(random.choices(string.ascii_lowercase + string.digits, k=10))
            domain = random.choice(domains)
            return f"{username}@{domain}"

        def check_username_availability(username):
            """Check if the generated username is available on Instagram."""
            try:
                url = f"https://www.instagram.com/{username}/"
                headers = {'User-Agent': self.user_agent.random}
                response = requests.get(url, headers=headers, timeout=10)
                return response.status_code == 404
            except Exception as e:
                self.logger.warning(f"Failed to check username availability: {e}")
                return False

        def generate_username():
            """Generate a unique username with availability check."""
            patterns = [
                lambda: f"user_{random.randint(1000000, 9999999)}",
                lambda: f"{random.choice(['photo', 'insta', 'gram'])}_{random.randint(10000, 99999)}",
                lambda: f"{random.choice(['social', 'digital', 'web'])}{random.randint(1000, 9999)}"
            ]
            
            max_attempts = 5
            attempts = 0
            
            while attempts < max_attempts:
                username = random.choice(patterns)()
                if check_username_availability(username):
                    self.logger.info(f"Found available username: {username}")
                    return username
                attempts += 1
                time.sleep(1)
            
            return f"user_{int(time.time())}"

        def signup_with_selenium(email, username, password):
            """Attempt to create account using Selenium automation."""
            try:
                if not self.driver:
                    self._setup_driver()
                
                self.driver.get("https://www.instagram.com/accounts/emailsignup/")
                time.sleep(random.uniform(3, 5))
                
                # Fill the form with delays to appear human
                email_field = WebDriverWait(self.driver, 10).until(
                    EC.presence_of_element_located((By.NAME, "emailOrPhone"))
                )
                for char in email:
                    email_field.send_keys(char)
                    time.sleep(random.uniform(0.1, 0.3))
                
                name_field = WebDriverWait(self.driver, 10).until(
                    EC.presence_of_element_located((By.NAME, "fullName"))
                )
                full_name = f"User {random.randint(100, 999)}"
                for char in full_name:
                    name_field.send_keys(char)
                    time.sleep(random.uniform(0.1, 0.3))
                
                username_field = WebDriverWait(self.driver, 10).until(
                    EC.presence_of_element_located((By.NAME, "username"))
                )
                for char in username:
                    username_field.send_keys(char)
                    time.sleep(random.uniform(0.1, 0.3))
                
                password_field = WebDriverWait(self.driver, 10).until(
                    EC.presence_of_element_located((By.NAME, "password"))
                )
                for char in password:
                    password_field.send_keys(char)
                    time.sleep(random.uniform(0.1, 0.3))
                
                # Submit form
                submit_button = WebDriverWait(self.driver, 10).until(
                    EC.element_to_be_clickable((By.XPATH, "//button[text()='Sign up']"))
                )
                submit_button.click()
                
                # Wait and check for success
                time.sleep(5)
                if "signup" not in self.driver.current_url:
                    self.logger.info(f"Successfully created account: {username}")
                    return True
                else:
                    self.logger.warning("Failed to create account - possible CAPTCHA")
                    return False
                    
            except Exception as e:
                self.logger.error(f"Error during signup: {e}")
                return False

        try:
            # Generate or use provided credentials
            if not email:
                email = generate_email()
            if not username:
                username = generate_username()
            if not password:
                password = generate_password()
            
            # Attempt to create account using Selenium
            success = signup_with_selenium(email, username, password)
            
            account = {
                "email": email,
                "username": username,
                "password": password,
                "created_at": time.time(),
                "reports_made": 0,
                "last_report_time": 0,
                "signup_success": success
            }
            
            # Log account creation with censored password
            censored_password = password[:2] + '*' * (len(password) - 4) + password[-2:]
            self.logger.info(f"Created account: {username} ({email}) with password: {censored_password}")
            
            # Save account to CSV
            self._save_account_to_csv(account)
            
            self.accounts.append(account)
            return account
            
        except Exception as e:
            self.logger.error(f"Failed to create account: {e}")
            raise
    
    def _save_account_to_csv(self, account):
        """Save account details to a CSV file."""
        filename = "generated_accounts.csv"
        file_exists = os.path.exists(filename)
        
        try:
            with open(filename, "a", newline="") as file:
                writer = csv.DictWriter(file, fieldnames=["username", "email", "password", "created_at"])
                if not file_exists:
                    writer.writeheader()
                writer.writerow({
                    "username": account["username"],
                    "email": account["email"],
                    "password": account["password"],
                    "created_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(account["created_at"]))
                })
        except Exception as e:
            self.logger.error(f"Failed to save account to CSV: {e}")
    
    def login(self, account=None):
        """Log in to Instagram using the specified account."""
        if not account:
            if not self.accounts:
                account = self.create_temporary_account()
            else:
                account = random.choice(self.accounts)
        
        self.current_account = account
        max_retries = self.settings.get("retry_attempts", 3)
        retry_count = 0
        
        while retry_count < max_retries:
            try:
                # Ensure driver is properly initialized
                if self.driver:
                    try:
                        self.driver.quit()
                    except:
                        pass
                    self.driver = None
                
                self._setup_driver()
                
                if not self.driver:
                    self.logger.error("Failed to initialize WebDriver")
                    retry_count += 1
                    continue
                    
                # Access login page with retry logic
                try:
                    self.driver.get(self.platform_urls["login"])
                    WebDriverWait(self.driver, 15).until(
                        lambda driver: "login" in driver.current_url.lower()
                    )
                except:
                    self.logger.warning("Failed to load login page, retrying...")
                    self.driver.refresh()
                    time.sleep(random.uniform(3, 5))
                
                # Verify page loaded properly
                if "login" not in self.driver.current_url.lower():
                    raise Exception("Login page did not load properly")
                
                # Enter credentials with explicit waits
                username_field = WebDriverWait(self.driver, 15).until(
                    EC.presence_of_element_located((By.NAME, "username"))
                )
                username_field.clear()
                for char in account["username"]:
                    username_field.send_keys(char)
                    time.sleep(random.uniform(0.05, 0.15))
                
                password_field = WebDriverWait(self.driver, 10).until(
                    EC.presence_of_element_located((By.NAME, "password"))
                )
                password_field.clear()
                for char in account["password"]:
                    password_field.send_keys(char)
                    time.sleep(random.uniform(0.05, 0.15))
                
                # Submit form
                submit_button = WebDriverWait(self.driver, 10).until(
                    EC.element_to_be_clickable((By.CSS_SELECTOR, "button[type='submit']"))
                )
                submit_button.click()
                
                # Wait for successful login
                try:
                    WebDriverWait(self.driver, 20).until(
                        EC.presence_of_element_located((By.CSS_SELECTOR, "main"))
                    )
                    self.logger.info(f"Successfully logged in as {account['username']}")
                    return True
                except:
                    if "challenge" in self.driver.current_url:
                        self.logger.error("Security challenge detected")
                        raise Exception("Security challenge detected")
                    else:
                        raise Exception("Login verification failed")
                        
            except Exception as e:
                self.logger.error(f"Login attempt {retry_count + 1} failed: {str(e)}")
                retry_count += 1
                
                if self.driver:
                    try:
                        self.driver.quit()
                    except:
                        pass
                    self.driver = None
                    
                # Add exponential backoff between retries
                if retry_count < max_retries:
                    wait_time = self.settings["backoff_factor"] ** retry_count
                    self.logger.info(f"Waiting {wait_time} seconds before retry...")
                    time.sleep(wait_time)
                    
                # Try with a different proxy on retry
                self.current_proxy = self._get_random_proxy()
        
        self.logger.error(f"Failed to login after {max_retries} attempts")
        return False
    
    def report_account(self, target_username, reason):
        """Report an account for violating platform guidelines."""
        if not self.driver:
            if not self.login():
                self.logger.error("Cannot report account: Login failed")
                return False
        
        # Check if we can make another report
        if self.current_account["reports_made"] >= self.settings["max_reports_per_day"]:
            self.logger.warning("Daily report limit reached for this account")
            return False
        
        # Check if we need to wait before making another report
        time_since_last_report = time.time() - self.current_account["last_report_time"]
        if time_since_last_report < self.settings["report_interval_seconds"]:
            wait_time = self.settings["report_interval_seconds"] - time_since_last_report
            self.logger.info(f"Waiting {wait_time:.0f} seconds before making another report")
            time.sleep(wait_time)
        
        try:
            # Navigate to target profile
            self.driver.get(f"{self.platform_urls['base']}{target_username}")
            time.sleep(random.uniform(2, 5))
            
            # Click on report button (implementation depends on platform)
            try:
                menu_button = WebDriverWait(self.driver, 10).until(
                    EC.element_to_be_clickable((By.CSS_SELECTOR, "button[aria-label='More options']"))
                )
                menu_button.click()
                
                report_option = WebDriverWait(self.driver, 10).until(
                    EC.element_to_be_clickable((By.XPATH, "//button[contains(text(), 'Report')]"))
                )
                report_option.click()
                
                # Select reason
                reason_option = WebDriverWait(self.driver, 10).until(
                    EC.element_to_be_clickable((By.XPATH, f"//button[contains(text(), '{reason}')]"))
                )
                reason_option.click()
                
                # Submit report
                submit_button = WebDriverWait(self.driver, 10).until(
                    EC.element_to_be_clickable((By.XPATH, "//button[contains(text(), 'Submit report')]"))
                )
                submit_button.click()
                
                # Update account reporting stats
                self.current_account["reports_made"] += 1
                self.current_account["last_report_time"] = time.time()
                self.logger.info(f"Successfully reported account {target_username} for {reason}")
                return True
            except Exception as e:
                # Try alternative method for newer Instagram UI
                try:
                    # Try finding the three dots menu by different selectors
                    selectors = [
                        "//div[contains(@aria-label, 'More options')]",
                        "//button[contains(@aria-label, 'More')]",
                        "//span[contains(@aria-label, 'More options')]"
                    ]
                    
                    for selector in selectors:
                        try:
                            menu_button = WebDriverWait(self.driver, 5).until(
                                EC.element_to_be_clickable((By.XPATH, selector))
                            )
                            menu_button.click()
                            break
                        except:
                            continue
                    
                    # Look for report option in the menu
                    report_selectors = [
                        "//button[contains(text(), 'Report')]",
                        "//span[contains(text(), 'Report')]",
                        "//div[contains(text(), 'Report')]"
                    ]
                    
                    for selector in report_selectors:
                        try:
                            report_option = WebDriverWait(self.driver, 5).until(
                                EC.element_to_be_clickable((By.XPATH, selector))
                            )
                            report_option.click()
                            break
                        except:
                            continue
                    
                    # Follow through the reporting flow
                    # This will vary based on Instagram's current UI
                    # We'll try to be flexible with selectors
                    
                    # Update account reporting stats
                    self.current_account["reports_made"] += 1
                    self.current_account["last_report_time"] = time.time()
                    self.logger.info(f"Successfully reported account {target_username} using alternative method")
                    return True
                except Exception as e2:
                    self.logger.error(f"Error reporting account using alternative method: {e2}")
                    return False
        except Exception as e:
            self.logger.error(f"Error reporting account {target_username}: {e}")
            return False
    
    def extract_user_data(self, username):
# day 2 code
        """
        Extract user data through Instagram API calls.
        For bug bounty/security research demonstration purposes.
        """
        self.logger.info(f"Attempting to extract data for user: {username}")
        if not self.driver:
            if not self.login():
                self.logger.error("Cannot extract data: Login failed")
                return None
        
        user_data = {
            "username": username,
            "email": None,
            "phone": None,
            "user_id": None,
            "full_name": None,
            "profile_pic": None,
            "is_private": None,
            "additional_data": {}
        }
        
        try:
            # Navigate to user profile
            self.driver.get(f"{self.platform_urls['base']}{username}")
            time.sleep(random.uniform(2, 3))
            
            # Extract all cookies and get authentication tokens
            cookies = self.driver.get_cookies()
            cookie_dict = {cookie['name']: cookie['value'] for cookie in cookies}
            cookie_string = "; ".join([f"{name}={value}" for name, value in cookie_dict.items()])
            
            # Get the CSRF token from the cookies
            csrf_token = cookie_dict.get('csrftoken', '')
            
            # Get user ID from page source or alternative methods
            page_source = self.driver.page_source
            
            # Method 1: Using regex pattern
            user_id_match = re.search(r'"profilePage_([0-9]+)"', page_source)
            if user_id_match:
                user_data["user_id"] = user_id_match.group(1)
                self.logger.info(f"Found user ID: {user_data['user_id']}")
            
            # Method 2: Using JavaScript execution (more reliable)
            if not user_data["user_id"]:
                try:
                    js_result = self.driver.execute_script(
                        "return window._sharedData.entry_data.ProfilePage[0].graphql.user.id"
                    )
                    if js_result:
                        user_data["user_id"] = js_result
                        self.logger.info(f"Found user ID via JS: {user_data['user_id']}")
                except:
                    self.logger.warning("Failed to extract user ID via JavaScript")
            
            # Method 3: Using fetch user data from Instagram's API
            if not user_data["user_id"]:
                try:
                    api_headers = {
                        "User-Agent": self.user_agent.random,
                        "Cookie": cookie_string,
                        "X-IG-App-ID": "936619743392459",
                        "X-CSRFToken": csrf_token,
                        "Accept": "*/*",
                        "Accept-Language": "en-US,en;q=0.9",
                        "Referer": f"https://www.instagram.com/{username}/"
                    }
                    
                    response = requests.get(
                        f"https://www.instagram.com/{username}/?__a=1&__d=dis",
                        headers=api_headers,
                        timeout=10
                    )
                    
                    if response.status_code == 200:
                        try:
                            user_json = response.json()
                            if 'graphql' in user_json and 'user' in user_json['graphql']:
                                user_data["user_id"] = user_json['graphql']['user']['id']
                                self.logger.info(f"Found user ID via API: {user_data['user_id']}")
                        except:
                            self.logger.warning("Failed to parse JSON response from API")
                    else:
                        self.logger.warning(f"API request failed with status code: {response.status_code}")
                except:
                    self.logger.warning("Failed to make API request for user ID")
            
            # Set up headers for API requests with the tokens we've collected
            api_headers = {
                "User-Agent": self.user_agent.random,
                "Cookie": cookie_string,
                "X-IG-App-ID": "936619743392459",
                "X-CSRFToken": csrf_token,
                "Accept": "*/*",
                "Accept-Language": "en-US,en;q=0.9",
                "Origin": "https://www.instagram.com",
                "Referer": f"https://www.instagram.com/{username}/"
            }
            
            # Step 2: Use the API to get user info if we have a user ID
            if user_data["user_id"]:
                # Get user info from the Instagram API
                api_url = f"https://i.instagram.com/api/v1/users/{user_data['user_id']}/info/"
                
                try:
                    proxy_dict = None
                    if self.current_proxy and self.current_proxy != "":
                        proxy_dict = {"http": f"http://{self.current_proxy}", "https": f"http://{self.current_proxy}"}
                    
                    response = requests.get(
                        api_url,
                        headers=api_headers,
                        proxies=proxy_dict,
                        timeout=10
                    )
                    
                    if response.status_code == 200:
                        user_info = response.json()
                        user = user_info.get("user", {})
                        
                        # Extract basic information
                        user_data["full_name"] = user.get("full_name")
                        user_data["profile_pic"] = user.get("profile_pic_url")
                        user_data["is_private"] = user.get("is_private")
                        
                        # Store additional data for research
                        user_data["additional_data"] = {
                            "follower_count": user.get("follower_count"),
                            "following_count": user.get("following_count"),
                            "media_count": user.get("media_count"),
                            "biography": user.get("biography"),
                            "external_url": user.get("external_url")
                        }
                        
                        self.logger.info(f"Successfully extracted basic user data for {username}")
                    else:
                        self.logger.warning(f"User info API request failed with status code: {response.status_code}")
                except Exception as e:
                    self.logger.error(f"Error accessing user info API: {e}")
                
                # Step 3: Get contact info (for bug bounty research purposes)
                try:
                    contact_api_url = f"https://i.instagram.com/api/v1/users/{user_data['user_id']}/contact_info/"
                    
                    response = requests.get(
                        contact_api_url,
                        headers=api_headers,
                        proxies=proxy_dict,
                        timeout=10
                    )
                    
                    if response.status_code == 200:
                        contact_info = response.json()
                        
                        # Extract email and phone (masked/partial for ethical research)
                        user_data["email"] = contact_info.get("user", {}).get("email")
                        user_data["phone"] = contact_info.get("user", {}).get("phone_number")
                        
                        self.logger.info(f"Successfully extracted contact information for {username}")
                    else:
                        self.logger.warning(f"Contact API request failed with status code: {response.status_code}")
                except Exception as e:
                    self.logger.error(f"Error accessing contact API: {e}")
            
            return user_data
        except Exception as e:
            self.logger.error(f"Error extracting user data: {e}")
            return user_data  # Return partial data if we have any
    
    def close(self):
        """Clean up resources before shutting down."""
        if self.driver:
            try:
                self.driver.quit()
            except:
                pass
        self.logger.info("Resources cleaned up")

    def create_temporary_email(self):
        """Create a temporary email using temp-mail.org API."""
        max_attempts = 3
        for attempt in range(max_attempts):
            try:
                response = requests.get(
                    "https://api.temp-mail.org/request/new/domain/list", 
                    timeout=10
                )
                domains = response.json()
                domain = random.choice(domains)
                username = ''.join(random.choices(string.ascii_lowercase + string.digits, k=10))
                email = f"{username}@{domain}"
                
                self.temp_email = {
                    "address": email,
                    "hash": hashlib.md5(email.encode()).hexdigest()
                }
                
                return email
            except Exception as e:
                self.logger.error(f"Failed to create temporary email (attempt {attempt + 1}/{max_attempts}): {e}")
                time.sleep(2)
        
        # Fallback to 1secmail if temp-mail fails
        try:
            response = requests.get(
                "https://www.1secmail.com/api/v1/?action=genRandomMailbox&count=1",
                timeout=10
            )
            email = response.json()[0]
            self.temp_email = {
                "address": email,
                "domain": email.split('@')[1]
            }
            return email
        except:
            self.logger.error("Failed to create email using backup service")
            return None

    def get_verification_code(self, max_attempts=15, delay=5):
        """Get verification code from temporary email."""
        if not hasattr(self, 'temp_email'):
            self.logger.error("No temporary email found")
            return None
            
        for attempt in range(max_attempts):
            try:
                if 'hash' in self.temp_email:  # temp-mail.org
                    response = requests.get(
                        f"https://api.temp-mail.org/request/mail/id/{self.temp_email['hash']}/format/json",
                        timeout=10
                    )
                    emails = response.json()
                    
                    for email in emails:
                        if "Instagram" in email.get('subject', ''):
                            code_match = re.search(r'(\d{6})', email['text'])
                            if code_match:
                                return code_match.group(1)
                else:  # 1secmail
                    login, domain = self.temp_email['address'].split('@')
                    response = requests.get(
                        f"https://www.1secmail.com/api/v1/?action=getMessages&login={login}&domain={domain}",
                        timeout=10
                    )
                    emails = response.json()
                    
                    for email in emails:
                        if "Instagram" in email.get('subject', ''):
                            msg_id = email['id']
                            msg_response = requests.get(
                                f"https://www.1secmail.com/api/v1/?action=readMessage&login={login}&domain={domain}&id={msg_id}",
                                timeout=10
                            )
                            msg_content = msg_response.json()
                            code_match = re.search(r'(\d{6})', msg_content['body'])
                            if code_match:
                                return code_match.group(1)
                                
                self.logger.info(f"Waiting for verification email (attempt {attempt + 1}/{max_attempts})")
                time.sleep(delay)
                
            except Exception as e:
                self.logger.error(f"Error checking email: {e}")
                time.sleep(delay)
                
        return None


class InstagramManagerGUI:
    def __init__(self, root):
        """Initialize the GUI."""
        self.root = root
        self.root.title("Instagram Account Manager")
        self.root.geometry("900x600")
        self.root.minsize(800, 500)
        
        # Set theme colors
        self.bg_color = "#2c2c2c"
        self.fg_color = "#ffffff"
        self.accent_color = "#e1306c"  # Instagram pink/purple
        self.secondary_color = "#405de6"  # Instagram blue
        
        # Apply theme
        self.root.configure(bg=self.bg_color)
        self.style = ttk.Style()
        self.style.configure("TFrame", background=self.bg_color)
        self.style.configure("TButton", 
                             background=self.accent_color, 
                             foreground=self.fg_color, 
                             font=("Helvetica", 10, "bold"))
        self.style.configure("TLabel", 
                             background=self.bg_color, 
                             foreground=self.fg_color, 
                             font=("Helvetica", 10))
        self.style.configure("Header.TLabel", 
                             background=self.bg_color, 
                             foreground=self.accent_color, 
                             font=("Helvetica", 14, "bold"))
        
        # Create log queue
        self.log_queue = queue.Queue()
        
        # Initialize the account manager
        self.manager = InstagramAccountManager(log_queue=self.log_queue)
        
        # Create main frame
        self.main_frame = ttk.Frame(self.root)
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create header
        header_label = ttk.Label(self.main_frame, 
                                text="Instagram Account Manager", 
                                style="Header.TLabel")
        header_label.pack(pady=(0, 10))
        
        # Create tabs
        self.tab_control = ttk.Notebook(self.main_frame)
        
        # Account tab
        self.account_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.account_tab, text="Accounts")
        
        # Report tab
        self.report_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.report_tab, text="Report")
        
        # Data extraction tab
        self.data_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.data_tab, text="Data Extraction")
        
        # Settings tab
        self.settings_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.settings_tab, text="Settings")
        
        self.tab_control.pack(fill=tk.BOTH, expand=True)
        
        # Create log frame
        self.log_frame = ttk.Frame(self.main_frame)
        self.log_frame.pack(fill=tk.BOTH, expand=True, pady=(10, 0))
        
        # Log header
        log_header = ttk.Label(self.log_frame, text="Activity Log", style="Header.TLabel")
        log_header.pack(anchor=tk.W)
        
        # Create log text widget
        self.log_text = scrolledtext.ScrolledText(self.log_frame, height=10)
        self.log_text.pack(fill=tk.BOTH, expand=True)
        self.log_text.config(state=tk.DISABLED)
        
        # Setup account tab
        self.setup_account_tab()
        
        # Setup report tab
        self.setup_report_tab()
        
        # Setup data extraction tab
        self.setup_data_tab()
        
        # Setup settings tab
        self.setup_settings_tab()
        
        # Start log updater
        self.update_log()
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Start proxy loading in background
        self.status_var.set("Loading proxies...")
        
        # Bind close event
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
    
    def setup_account_tab(self):
        """Setup the account management tab."""
        # Account frame
        account_frame = ttk.Frame(self.account_tab)
        account_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Account creation frame
        create_frame = ttk.LabelFrame(account_frame, text="Create Account")
        create_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Email field
        email_frame = ttk.Frame(create_frame)
        email_frame.pack(fill=tk.X, padx=5, pady=5)
        
        email_label = ttk.Label(email_frame, text="Email:")
        email_label.pack(side=tk.LEFT, padx=(0, 5))
        
        self.email_var = tk.StringVar()
        email_entry = ttk.Entry(email_frame, textvariable=self.email_var, width=30)
        email_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # Username field
        username_frame = ttk.Frame(create_frame)
        username_frame.pack(fill=tk.X, padx=5, pady=5)
        
        username_label = ttk.Label(username_frame, text="Username:")
        username_label.pack(side=tk.LEFT, padx=(0, 5))
        
        self.username_var = tk.StringVar()
        username_entry = ttk.Entry(username_frame, textvariable=self.username_var, width=30)
        username_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # Password field
        password_frame = ttk.Frame(create_frame)
        password_frame.pack(fill=tk.X, padx=5, pady=5)
        
        password_label = ttk.Label(password_frame, text="Password:")
        password_label.pack(side=tk.LEFT, padx=(0, 5))
        
        self.password_var = tk.StringVar()
        password_entry = ttk.Entry(password_frame, textvariable=self.password_var, width=30, show="*")
        password_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # Create account button
        create_button = ttk.Button(create_frame, text="Create Account", 
                                  command=self.create_account)
        create_button.pack(pady=10)
        
        # Random account button
        random_button = ttk.Button(create_frame, text="Create Random Account", 
                                  command=self.create_random_account)
        random_button.pack(pady=(0, 10))
        
        # Account list frame
        list_frame = ttk.LabelFrame(account_frame, text="Account List")
        list_frame.pack(fill=tk.BOTH, expand=True)
        
        # Account listbox
        self.account_listbox = tk.Listbox(list_frame)
        self.account_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Scrollbar for listbox
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.account_listbox.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.account_listbox.configure(yscrollcommand=scrollbar.set)
        
        # Button frame
        button_frame = ttk.Frame(list_frame)
        button_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Login button
        login_button = ttk.Button(button_frame, text="Login Selected", 
                                 command=self.login_selected_account)
        login_button.pack(side=tk.LEFT, padx=5)
        
        # Remove button
        remove_button = ttk.Button(button_frame, text="Remove Selected", 
                                  command=self.remove_selected_account)
        remove_button.pack(side=tk.LEFT, padx=5)
    
    def setup_report_tab(self):
        """Setup the reporting tab."""
        # Report frame
        report_frame = ttk.Frame(self.report_tab)
        report_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Target username field
        target_frame = ttk.Frame(report_frame)
        target_frame.pack(fill=tk.X, pady=10)
        
        target_label = ttk.Label(target_frame, text="Target Username:")
        target_label.pack(side=tk.LEFT, padx=(0, 5))
        
        self.target_var = tk.StringVar()
        target_entry = ttk.Entry(target_frame, textvariable=self.target_var, width=30)
        target_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # Reason selection
        reason_frame = ttk.Frame(report_frame)
        reason_frame.pack(fill=tk.X, pady=10)
        
        reason_label = ttk.Label(reason_frame, text="Report Reason:")
        reason_label.pack(side=tk.LEFT, padx=(0, 5))
        
        self.reason_var = tk.StringVar()
        self.reason_var.set("spam")
        
        reasons = ["spam", "inappropriate", "violence", "harassment", "false information", 
                  "hate speech", "self-injury", "terrorism"]
        reason_dropdown = ttk.Combobox(reason_frame, textvariable=self.reason_var, 
                                      values=reasons, state="readonly", width=30)
        reason_dropdown.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # Report button
        report_button = ttk.Button(report_frame, text="Report Account", 
                                  command=self.report_account)
        report_button.pack(pady=10)
        
        # Mass report frame
        mass_frame = ttk.LabelFrame(report_frame, text="Mass Reporting")
        mass_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        # Number of accounts
        num_frame = ttk.Frame(mass_frame)
        num_frame.pack(fill=tk.X, padx=5, pady=5)
        
        num_label = ttk.Label(num_frame, text="Number of Accounts:")
        num_label.pack(side=tk.LEFT, padx=(0, 5))
        
        self.num_accounts_var = tk.IntVar()
        self.num_accounts_var.set(5)
        
        num_spinbox = ttk.Spinbox(num_frame, from_=1, to=20, textvariable=self.num_accounts_var, width=5)
        num_spinbox.pack(side=tk.LEFT)
        
        # Mass report button
        mass_button = ttk.Button(mass_frame, text="Start Mass Report", 
                               command=self.start_mass_report)
        mass_button.pack(pady=10)
    
    def setup_data_tab(self):
        """Setup the data extraction tab."""
        # Data frame
        data_frame = ttk.Frame(self.data_tab)
        data_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Target username field
        target_frame = ttk.Frame(data_frame)
        target_frame.pack(fill=tk.X, pady=10)
        
        target_label = ttk.Label(target_frame, text="Target Username:")
        target_label.pack(side=tk.LEFT, padx=(0, 5))
        
        self.data_target_var = tk.StringVar()
        target_entry = ttk.Entry(target_frame, textvariable=self.data_target_var, width=30)
        target_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # Extract button
        extract_button = ttk.Button(data_frame, text="Extract User Data", 
                                   command=self.extract_user_data)
        extract_button.pack(pady=10)
        
        # Results frame
        results_frame = ttk.LabelFrame(data_frame, text="Extraction Results")
        results_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        # Results text
        self.results_text = scrolledtext.ScrolledText(results_frame)
        self.results_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    def setup_settings_tab(self):
        """Setup the settings tab."""
        # Settings frame
        settings_frame = ttk.Frame(self.settings_tab)
        settings_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Proxy settings
        proxy_frame = ttk.LabelFrame(settings_frame, text="Proxy Settings")
        proxy_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Refresh proxies button
        refresh_button = ttk.Button(proxy_frame, text="Refresh Proxies", 
                                   command=self.refresh_proxies)
        refresh_button.pack(pady=10)
        
        # Proxy count label
        self.proxy_count_var = tk.StringVar()
        self.proxy_count_var.set("Proxies: Loading...")
        
        proxy_count_label = ttk.Label(proxy_frame, textvariable=self.proxy_count_var)
        proxy_count_label.pack(pady=(0, 10))
        
        # Report settings
        report_frame = ttk.LabelFrame(settings_frame, text="Report Settings")
        report_frame.pack(fill=tk.X, pady=10)
        
        # Max reports per day
        max_reports_frame = ttk.Frame(report_frame)
        max_reports_frame.pack(fill=tk.X, padx=5, pady=5)
        
        max_reports_label = ttk.Label(max_reports_frame, text="Max Reports Per Day:")
        max_reports_label.pack(side=tk.LEFT, padx=(0, 5))
        
        self.max_reports_var = tk.IntVar()
        self.max_reports_var.set(self.manager.settings["max_reports_per_day"])
        
        # after new request:-

        max_reports_spinbox = ttk.Spinbox(max_reports_frame, from_=1, to=100, 
                                         textvariable=self.max_reports_var, width=5)
        max_reports_spinbox.pack(side=tk.LEFT)
        
        # Report interval
        interval_frame = ttk.Frame(report_frame)
        interval_frame.pack(fill=tk.X, padx=5, pady=5)
        
        interval_label = ttk.Label(interval_frame, text="Report Interval (seconds):")
        interval_label.pack(side=tk.LEFT, padx=(0, 5))
        
        self.interval_var = tk.IntVar()
        self.interval_var.set(self.manager.settings["report_interval_seconds"])
        
        interval_spinbox = ttk.Spinbox(interval_frame, from_=60, to=86400, 
                                      textvariable=self.interval_var, width=5)
        interval_spinbox.pack(side=tk.LEFT)
        
        # Save settings button
        save_button = ttk.Button(settings_frame, text="Save Settings", 
                                command=self.save_settings)
        save_button.pack(pady=10)
    
    def update_log(self):
        """Update the log text widget with new log messages."""
        while not self.log_queue.empty():
            message = self.log_queue.get()
            self.log_text.config(state=tk.NORMAL)
            self.log_text.insert(tk.END, message + "\n")
            self.log_text.see(tk.END)
            self.log_text.config(state=tk.DISABLED)
        
        # Schedule the next update
        self.root.after(100, self.update_log)
    
    def create_account(self):
        """Create an account with the provided details."""
        email = self.email_var.get()
        username = self.username_var.get()
        password = self.password_var.get()
        
        if not username or not password:
            messagebox.showerror("Error", "Username and password are required")
            return
        
        # Create the account
        account = self.manager.create_temporary_account(email, username, password)
        
        # Update the listbox
        self.update_account_listbox()
        
        # Clear the fields
        self.email_var.set("")
        self.username_var.set("")
        self.password_var.set("")
        
        self.status_var.set(f"Account created: {username}")
    
    def create_random_account(self):
        """Create a random account."""
        account = self.manager.create_temporary_account()
        
        # Update the listbox
        self.update_account_listbox()
        
        self.status_var.set(f"Random account created: {account['username']}")
    
    def update_account_listbox(self):
        """Update the account listbox with current accounts."""
        self.account_listbox.delete(0, tk.END)
        
        for account in self.manager.accounts:
            self.account_listbox.insert(tk.END, f"{account['username']} ({account['email']})")
    
    def login_selected_account(self):
        """Login with the selected account."""
        selection = self.account_listbox.curselection()
        
        if not selection:
            messagebox.showerror("Error", "No account selected")
            return
        
        index = selection[0]
        account = self.manager.accounts[index]
        
        # Start login in a separate thread to avoid freezing the GUI
        self.status_var.set(f"Logging in as {account['username']}...")
        
        threading.Thread(target=self.login_thread, args=(account,), daemon=True).start()
    
    def login_thread(self, account):
        """Thread function for login."""
        success = self.manager.login(account)
        
        # Update status in the main thread
        self.root.after(0, self.update_login_status, success, account['username'])
    
    def update_login_status(self, success, username):
        """Update the status after login attempt."""
        if success:
            self.status_var.set(f"Successfully logged in as {username}")
        else:
            self.status_var.set(f"Failed to log in as {username}")
            messagebox.showerror("Login Failed", f"Failed to log in as {username}")
    
    def remove_selected_account(self):
        """Remove the selected account."""
        selection = self.account_listbox.curselection()
        
        if not selection:
            messagebox.showerror("Error", "No account selected")
            return
        
        index = selection[0]
        account = self.manager.accounts[index]
        
        # Remove the account
        self.manager.accounts.pop(index)
        
        # Update the listbox
        self.update_account_listbox()
        
        self.status_var.set(f"Account removed: {account['username']}")
    
    def report_account(self):
        """Report the specified account."""
        target = self.target_var.get()
        reason = self.reason_var.get()
        
        if not target:
            messagebox.showerror("Error", "Target username is required")
            return
        
        # Check if we're logged in
        if not self.manager.driver:
            messagebox.showinfo("Login Required", "You need to login first")
            return
        
        # Start reporting in a separate thread
        self.status_var.set(f"Reporting account {target}...")
        
        threading.Thread(target=self.report_thread, args=(target, reason), daemon=True).start()
    
    def report_thread(self, target, reason):
        """Thread function for reporting."""
        success = self.manager.report_account(target, reason)
        
        # Update status in the main thread
        self.root.after(0, self.update_report_status, success, target)
    
    def update_report_status(self, success, target):
        """Update the status after report attempt."""
        if success:
            self.status_var.set(f"Successfully reported {target}")
            messagebox.showinfo("Success", f"Successfully reported {target}")
        else:
            self.status_var.set(f"Failed to report {target}")
            messagebox.showerror("Report Failed", f"Failed to report {target}")
    
    def start_mass_report(self):
        """Start mass reporting with multiple accounts."""
        target = self.target_var.get()
        reason = self.reason_var.get()
        num_accounts = self.num_accounts_var.get()
        
        if not target:
            messagebox.showerror("Error", "Target username is required")
            return
        
        # Confirm the operation
        if not messagebox.askyesno("Confirm", f"Are you sure you want to report {target} using {num_accounts} accounts?"):
            return
        
        # Start mass reporting in a separate thread
        self.status_var.set(f"Starting mass report on {target}...")
        
        threading.Thread(target=self.mass_report_thread, 
                        args=(target, reason, num_accounts), daemon=True).start()
    
    def mass_report_thread(self, target, reason, num_accounts):
        """Thread function for mass reporting."""
        # Create accounts if needed
        while len(self.manager.accounts) < num_accounts:
            self.manager.create_temporary_account()
            # Update the listbox in the main thread
            self.root.after(0, self.update_account_listbox)
        
        # Use the accounts to report
        success_count = 0
        for i, account in enumerate(self.manager.accounts[:num_accounts]):
            # Update status in the main thread
            self.root.after(0, self.status_var.set, 
                          f"Using account {i+1}/{num_accounts}: {account['username']}")
            
            # Login with the account
            if self.manager.login(account):
                # Report the target account
                if self.manager.report_account(target, reason):
                    success_count += 1
                
                # Add a delay between accounts to avoid detection
                if i < num_accounts - 1:
                    delay = random.uniform(3, 7)
                    time.sleep(delay)
        
        # Final update in the main thread
        self.root.after(0, self.update_mass_report_status, success_count, num_accounts, target)
    
    def update_mass_report_status(self, success_count, total, target):
        """Update the status after mass report."""
        self.status_var.set(f"Mass report complete: {success_count}/{total} successful reports on {target}")
        messagebox.showinfo("Mass Report Complete", 
                           f"Completed mass report on {target}\n{success_count}/{total} successful reports")
    
    def extract_user_data(self):
        """Extract data for the specified user."""
        target = self.data_target_var.get()
        
        if not target:
            messagebox.showerror("Error", "Target username is required")
            return
        
        # Check if we're logged in
        if not self.manager.driver:
            messagebox.showinfo("Login Required", "You need to login first")
            return
        
        # Start extraction in a separate thread
        self.status_var.set(f"Extracting data for {target}...")
        self.results_text.delete(1.0, tk.END)
        
        threading.Thread(target=self.extract_thread, args=(target,), daemon=True).start()
    
    def extract_thread(self, target):
        """Thread function for data extraction."""
        user_data = self.manager.extract_user_data(target)
        
        # Update results in the main thread
        self.root.after(0, self.update_extraction_results, user_data)
    
    def update_extraction_results(self, user_data):
        """Update the extraction results."""
        if not user_data:
            self.status_var.set("Data extraction failed")
            self.results_text.insert(tk.END, "Failed to extract data")
            return
        
        # Format the results
        results = f"Data for user: {user_data['username']}\n"
        results += f"User ID: {user_data['user_id'] or 'Not found'}\n"
        results += f"Full Name: {user_data['full_name'] or 'Not found'}\n"
        results += f"Email: {user_data['email'] or 'Not found'}\n"
        results += f"Phone: {user_data['phone'] or 'Not found'}\n"
        results += f"Private Account: {user_data['is_private'] or 'Unknown'}\n\n"
        
        if user_data['additional_data']:
            results += "Additional Data:\n"
            for key, value in user_data['additional_data'].items():
                if value:
                    results += f"- {key.replace('_', ' ').title()}: {value}\n"
        
        # Update the results text
        self.results_text.insert(tk.END, results)
        self.status_var.set(f"Data extraction complete for {user_data['username']}")
    
    def refresh_proxies(self):
        """Refresh the proxy list."""
        self.status_var.set("Refreshing proxies...")
        self.proxy_count_var.set("Proxies: Loading...")
        
        threading.Thread(target=self.refresh_proxies_thread, daemon=True).start()
    
    def refresh_proxies_thread(self):
        """Thread function for refreshing proxies."""
        self.manager.proxies = []
        self.manager.load_proxies_from_internet()
        
        # Update the proxy count in the main thread
        self.root.after(0, self.update_proxy_count)
    
    def update_proxy_count(self):
        """Update the proxy count label."""
        count = len(self.manager.proxies)
        self.proxy_count_var.set(f"Proxies: {count} available")
        self.status_var.set(f"Refreshed proxies: {count} available")
    
    def save_settings(self):
        """Save the current settings."""
        self.manager.settings["max_reports_per_day"] = self.max_reports_var.get()
        self.manager.settings["report_interval_seconds"] = self.interval_var.get()
        
        self.status_var.set("Settings saved")
        messagebox.showinfo("Settings Saved", "Settings have been updated")
    
    def on_close(self):
        """Handle window close event."""
        if messagebox.askyesno("Quit", "Are you sure you want to quit?"):
            # Clean up resources
            self.manager.close()
            self.root.destroy()


def main():
    """Main function to start the application."""
    root = tk.Tk()
    app = InstagramManagerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
