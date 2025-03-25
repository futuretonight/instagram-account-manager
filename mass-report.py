import requests
import random
import time
import logging
import json
import os
import re
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, NoSuchElementException
from fake_useragent import UserAgent
from dotenv import load_dotenv
import concurrent.futures

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("account_management.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class AccountManager:
    def __init__(self, platform="instagram"):
        """Initialize the account manager with configuration."""
        self.platform = platform
        self.proxies = []
        self.accounts = []
        self.current_proxy = None
        self.current_account = None
        self.driver = None
        self.user_agent = UserAgent()
        self.session = requests.Session()
        
        # Load configuration
        self.config = self._load_config()
        
        # URLs for different platforms
        self.platform_urls = {
            "instagram": {
                "base": "https://www.instagram.com/",
                "login": "https://www.instagram.com/accounts/login/",
                "report": "https://help.instagram.com/contact/1652567838289083",
                "api": "https://i.instagram.com/api/v1/"
            }
        }
        
        # Load proxies from reliable sources
        self._load_proxies_from_reliable_sources()

    def _load_config(self):
        """Load configuration from file."""
        try:
            with open('config.json', 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            logger.warning("Config file not found. Using default settings.")
            default_config = {
                "max_accounts": 5,
                "max_reports_per_day": 10,
                "report_interval_seconds": 3600,
                "retry_attempts": 3,
                "backoff_factor": 2,
                "proxy_timeout": 5,
                "proxy_test_threads": 10,
                "use_direct_connection_fallback": True
            }
            # Save default config
            with open('config.json', 'w') as f:
                json.dump(default_config, f, indent=4)
            return default_config

    def _load_proxies_from_reliable_sources(self):
        """Load proxies from reliable sources."""
        logger.info("Loading proxies from reliable sources")
        
        # Check for existing proxies first
        if os.path.exists('proxies.txt'):
            try:
                with open('proxies.txt', 'r') as f:
                    file_proxies = [line.strip() for line in f if line.strip()]
                    if file_proxies:
                        logger.info(f"Loaded {len(file_proxies)} proxies from file")
                        self.proxies = file_proxies
                        # Verify a few proxies to confirm they're still working
                        sample = random.sample(self.proxies, min(5, len(self.proxies)))
                        if self._verify_proxy_list(sample):
                            logger.info("Proxy file contains working proxies")
                            return
                        else:
                            logger.warning("Proxies from file not working, will fetch new ones")
            except Exception as e:
                logger.error(f"Error loading proxies from file: {e}")
        
        # Define headers to avoid scraping detection
        headers = {
            'User-Agent': self.user_agent.random,
            'Accept': 'text/html,application/xhtml+xml,application/xml',
            'Accept-Language': 'en-US,en;q=0.9',
            'Connection': 'keep-alive',
        }
        
        proxy_sources = {
            'spys_one': {
                'url': 'https://spys.one/en/https-ssl-proxy/',
                'parser': self._parse_spys_one
            },
            'free_proxy_cz': {
                'url': 'http://free-proxy.cz/en/proxylist/country/all/https/ping/all',
                'parser': self._parse_free_proxy_cz
            },
            'proxyscrape': {
                'url': 'https://api.proxyscrape.com/v2/?request=getproxies&protocol=http&timeout=10000&country=all&ssl=all&anonymity=all',
                'parser': self._parse_plain_text
            },
            'ssl_proxies': {
                'url': 'https://www.sslproxies.org/',
                'parser': self._parse_ssl_proxies
            },
            'open_proxy_space': {
                'url': 'https://openproxy.space/list/http',
                'parser': self._parse_open_proxy_space
            }
        }
        
        all_proxies = []
        
        # Try each source
        for source_name, source_info in proxy_sources.items():
            try:
                logger.info(f"Fetching proxies from {source_name}")
                response = requests.get(source_info['url'], headers=headers, timeout=15)
                if response.status_code == 200:
                    parsed_proxies = source_info['parser'](response.text)
                    logger.info(f"Found {len(parsed_proxies)} proxies from {source_name}")
                    all_proxies.extend(parsed_proxies)
                else:
                    logger.warning(f"Failed to fetch from {source_name} - Status code: {response.status_code}")
            except Exception as e:
                logger.error(f"Error fetching from {source_name}: {e}")
        
        # Remove duplicates
        all_proxies = list(set(all_proxies))
        logger.info(f"Total of {len(all_proxies)} unique proxies collected")
        
        if not all_proxies:
            logger.warning("No proxies found from any sources. Adding fallback proxies.")
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
        
        if not self.proxies and self.config.get("use_direct_connection_fallback", True):
            logger.warning("No working proxies found. Using direct connection as fallback.")
            self.proxies = [""]  # Empty string for direct connection
        
        # Save working proxies
        with open('proxies.txt', 'w') as f:
            f.write('\n'.join(self.proxies))
        
        logger.info(f"Saved {len(self.proxies)} verified proxies to file")

    def _parse_spys_one(self, html_content):
        """Parse proxies from spys.one."""
        proxies = []
        pattern = r'<tr class=spy1x.*?<td>\s*(\d+\.\d+\.\d+\.\d+).*?<td>(\d+)'
        matches = re.findall(pattern, html_content, re.DOTALL)
        for ip, port in matches:
            proxies.append(f"{ip}:{port}")
        return proxies

    def _parse_free_proxy_cz(self, html_content):
        """Parse proxies from free-proxy.cz."""
        proxies = []
        pattern = r'<tr><td style="text-align:center">(\d+\.\d+\.\d+\.\d+)</td><td style="text-align:center">(\d+)</td>'
        matches = re.findall(pattern, html_content)
        for ip, port in matches:
            proxies.append(f"{ip}:{port}")
        return proxies

    def _parse_plain_text(self, text_content):
        """Parse proxies from plain text content."""
        proxies = []
        lines = text_content.strip().split('\n')
        for line in lines:
            if ':' in line and line.strip():
                proxies.append(line.strip())
        return proxies

    def _parse_ssl_proxies(self, html_content):
        """Parse proxies from sslproxies.org."""
        proxies = []
        pattern = r'<tr><td>(\d+\.\d+\.\d+\.\d+)</td><td>(\d+)</td>'
        matches = re.findall(pattern, html_content)
        for ip, port in matches:
            proxies.append(f"{ip}:{port}")
        return proxies

    def _parse_open_proxy_space(self, html_content):
        """Parse proxies from openproxy.space."""
        proxies = []
        pattern = r'"ip":"(\d+\.\d+\.\d+\.\d+)","port":(\d+)'
        matches = re.findall(pattern, html_content)
        for ip, port in matches:
            proxies.append(f"{ip}:{port}")
        return proxies

    def _verify_proxy_list(self, proxy_list):
        """Verify a list of proxies and return working ones."""
        verified_proxies = []
        test_url = "https://httpbin.org/ip"
        timeout = self.config.get("proxy_timeout", 5)
        
        logger.info(f"Verifying {len(proxy_list)} proxies")
        for proxy in proxy_list:
            try:
                if not proxy:  # Empty proxy is direct connection
                    verified_proxies.append("")
                    continue
                    
                proxy_dict = {"http": f"http://{proxy}", "https": f"http://{proxy}"}
                
                response = requests.get(
                    test_url, 
                    proxies=proxy_dict, 
                    timeout=timeout
                )
                if response.status_code == 200:
                    verified_proxies.append(proxy)
                    logger.debug(f"Verified proxy: {proxy}")
            except:
                pass
        
        logger.info(f"Verified {len(verified_proxies)} working proxies")
        return verified_proxies

    def _verify_proxy(self, proxy):
        """Verify a single proxy and return it if working."""
        if not proxy:  # Empty proxy is direct connection
            return ""
            
        try:
            test_url = "https://httpbin.org/ip"
            timeout = self.config.get("proxy_timeout", 5)
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
        max_threads = self.config.get("proxy_test_threads", 10)
        logger.info(f"Verifying proxies in parallel with {max_threads} threads")
        
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
        
        logger.info(f"Found {len(verified_proxies)} working proxies")
        return verified_proxies

    def _get_random_proxy(self):
        """Get a random proxy from the available pool."""
        if not self.proxies:
            logger.warning("No proxies available, using direct connection")
            return ""
        
        return random.choice(self.proxies)

    def _setup_driver(self):
        """Set up the Selenium WebDriver with proxy and user agent."""
        if self.driver:
            try:
                self.driver.quit()
            except:
                pass
        
        options = Options()
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--disable-gpu")
        options.add_argument("--disable-extensions")
        options.add_argument("--disable-notifications")
        options.add_argument("--start-maximized")
        options.add_argument("--window-size=1920,1080")
        
        # Set random user agent
        random_user_agent = self.user_agent.random
        options.add_argument(f"user-agent={random_user_agent}")
        
        # Set proxy if available
        self.current_proxy = self._get_random_proxy()
        if self.current_proxy and self.current_proxy != "":
            options.add_argument(f"--proxy-server={self.current_proxy}")
            logger.info(f"Using proxy: {self.current_proxy}")
        else:
            logger.info("Using direct connection (no proxy)")
        
        try:
            self.driver = webdriver.Chrome(options=options)
            self.driver.set_page_load_timeout(30)
            logger.info("WebDriver initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize WebDriver: {e}")
            # Try again without proxy
            try:
                options = Options()
                options.add_argument("--no-sandbox")
                options.add_argument("--disable-dev-shm-usage")
                options.add_argument("--disable-gpu")
                options.add_argument("--disable-extensions")
                options.add_argument("--disable-notifications")
                options.add_argument("--start-maximized")
                options.add_argument(f"user-agent={random_user_agent}")
                self.driver = webdriver.Chrome(options=options)
                self.driver.set_page_load_timeout(30)
                logger.info("WebDriver initialized without proxy")
            except Exception as e2:
                logger.critical(f"Failed to initialize WebDriver without proxy: {e2}")
                raise

    def create_temporary_account(self, email=None, username=None, password=None):
        """Create a temporary account for reporting purposes."""
        # Use provided credentials or generate them
        if not email:
            email = f"report_{random.randint(1000, 9999)}@temporarymail.com"
        if not username:
            username = f"reporter_{random.randint(1000, 9999)}"
        if not password:
            password = f"SecurePass{random.randint(100000, 999999)}"
        
        account = {
            "email": email,
            "username": username,
            "password": password,
            "created_at": time.time(),
            "reports_made": 0,
            "last_report_time": 0
        }
        
        logger.info(f"Created temporary account: {username}")
        self.accounts.append(account)
        return account

    def login(self, account=None):
        """Log in to a platform using the specified account."""
        if not account:
            if not self.accounts:
                account = self.create_temporary_account()
            else:
                account = random.choice(self.accounts)
        
        self.current_account = account
        
        if not self.driver:
            self._setup_driver()
        
        try:
            # Access login page
            self.driver.get(self.platform_urls[self.platform]["login"])
            logger.info(f"Accessing login page: {self.platform_urls[self.platform]['login']}")
            time.sleep(random.uniform(3, 5))  # Random wait to avoid detection
            
            # Check if login page loaded properly
            page_source = self.driver.page_source
            if "login" not in page_source.lower():
                logger.warning("Login page might not have loaded correctly")
                # Try refreshing
                self.driver.refresh()
                time.sleep(random.uniform(3, 5))
            
            # Enter username with explicit wait
            try:
                username_field = WebDriverWait(self.driver, 15).until(
                    EC.presence_of_element_located((By.NAME, "username"))
                )
                username_field.clear()
                for char in account["username"]:
                    username_field.send_keys(char)
                    time.sleep(random.uniform(0.05, 0.15))  # Mimic human typing
                logger.info("Username entered")
            except Exception as e:
                logger.error(f"Failed to find username field: {e}")
                # Try alternative selector
                try:
                    username_field = WebDriverWait(self.driver, 10).until(
                        EC.presence_of_element_located((By.CSS_SELECTOR, "input[name='username']"))
                    )
                    username_field.clear()
                    username_field.send_keys(account["username"])
                    logger.info("Username entered (alternative method)")
                except:
                    logger.error("All methods to find username field failed")
                    return False
            
            # Enter password
            try:
                password_field = WebDriverWait(self.driver, 10).until(
                    EC.presence_of_element_located((By.NAME, "password"))
                )
                password_field.clear()
                for char in account["password"]:
                    password_field.send_keys(char)
                    time.sleep(random.uniform(0.05, 0.15))  # Mimic human typing
                logger.info("Password entered")
            except Exception as e:
                logger.error(f"Failed to find password field: {e}")
                return False
            
            # Submit form with explicit wait
            try:
                submit_button = WebDriverWait(self.driver, 10).until(
                    EC.element_to_be_clickable((By.CSS_SELECTOR, "button[type='submit']"))
                )
                submit_button.click()
                logger.info("Login form submitted")
            except:
                try:
                    # Fallback to pressing Enter key
                    password_field.submit()
                    logger.info("Login form submitted via Enter key")
                except:
                    logger.error("Failed to submit login form")
                    return False
            
            # Wait for successful login
            try:
                WebDriverWait(self.driver, 20).until(
                    EC.presence_of_element_located((By.CSS_SELECTOR, "main"))
                )
                logger.info(f"Successfully logged in as {account['username']}")
                return True
            except:
                logger.error("Failed to detect successful login")
                return False
            
        except TimeoutException:
            logger.error("Timeout while attempting to log in")
            return False
        except Exception as e:
            logger.error(f"Error during login: {e}")
            return False

    def report_account(self, target_username, reason, exception=None):

        """Report an account for violating platform guidelines."""
        if not self.driver:
            if not self.login():
                logger.error("Cannot report account: Login failed")
                return False
        
        # Check if we can make another report, and handle exceptions

        if self.current_account["reports_made"] >= self.config["max_reports_per_day"]:
            logger.warning("Daily report limit reached for this account")
            return False
        
        # Check if we need to wait before making another report
        time_since_last_report = time.time() - self.current_account["last_report_time"]
        if time_since_last_report < self.config["report_interval_seconds"]:
            wait_time = self.config["report_interval_seconds"] - time_since_last_report
            logger.info(f"Waiting {wait_time:.0f} seconds before making another report")
            time.sleep(wait_time)
        
        try:
            # Navigate to target profile
            self.driver.get(f"{self.platform_urls[self.platform]['base']}{target_username}")
            time.sleep(random.uniform(2, 5))
            
            # Click on report button (implementation depends on platform)
            # This is a simplified example
            menu_button = WebDriverWait(self.driver, 10).until(
                EC.element_to_be_clickable((By.CSS_SELECTOR, "button[aria-label='More options']"))
            )
            menu_button.click()
            
            report_option = WebDriverWait(self.driver, 10).until(
                EC.element_to_be_clickable((By.XPATH, "//button[contains(text(), 'Report')]"))
            )
            report_option.click()
            
            # Select reason (implementation depends on platform)
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
            
            logger.info(f"Successfully reported account {target_username} for {reason}")
            return True
            
        except Exception as e:
            logger.error(f"Error reporting account {target_username}: {e}", exc_info=exception)

            return self._handle_error(e, "report_account", target_username, reason)

    def _handle_error(self, error, operation, *args):
        """Handle errors with exponential backoff and retry logic."""
        # Check for specific error types
        if isinstance(error, TimeoutException):
            logger.warning(f"Timeout during {operation}. Refreshing driver and proxy.")
            self._setup_driver()
        elif "rate limit" in str(error).lower():
            logger.warning(f"Rate limit detected during {operation}. Switching account and proxy.")
            self._setup_driver()
            if self.accounts and len(self.accounts) > 1:
                # Switch to a different account
                new_account = random.choice([a for a in self.accounts if a != self.current_account])
                self.login(new_account)
        
        # Implement retry with exponential backoff
        for attempt in range(1, self.config["retry_attempts"] + 1):
            wait_time = self.config["backoff_factor"] ** attempt
            logger.info(f"Retrying {operation} in {wait_time} seconds (attempt {attempt}/{self.config['retry_attempts']})")
            time.sleep(wait_time)
            
            try:
                # Call the original operation again
                method = getattr(self, operation)
                return method(*args)
            except Exception as retry_error:
                logger.error(f"Retry {attempt} failed: {retry_error}")
        
        logger.error(f"All retry attempts for {operation} failed")
        return False

    def extract_user_data(self, username):
        """
        Extract user data through Instagram API calls.
        For bug bounty/security research demonstration purposes.
        """
        logger.info(f"Attempting to extract data for user: {username}")
        
        if not self.driver:
            if not self.login():
                logger.error("Cannot extract data: Login failed")
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
            # Step 1: Get the user ID
            self.driver.get(f"{self.platform_urls[self.platform]['base']}{username}")
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
                logger.info(f"Found user ID: {user_data['user_id']}")
            
            # Method 2: Using JavaScript execution (more reliable)
            if not user_data["user_id"]:
                try:
                    js_result = self.driver.execute_script(
                        "return window._sharedData.entry_data.ProfilePage[0].graphql.user.id"
                    )
                    if js_result:
                        user_data["user_id"] = js_result
                        logger.info(f"Found user ID via JS: {user_data['user_id']}")
                except:
                    logger.warning("Failed to extract user ID via JavaScript")
            
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
                try:
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
                                logger.info(f"Found user ID via API: {user_data['user_id']}")
                        except:
                            logger.warning("Failed to parse JSON response from API")
                    else:
                        logger.warning(f"API request failed with status code: {response.status_code}")
                except Exception as e:
                    logger.warning(f"Failed to make API request for user ID: {e}")
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
                    response = requests.get(
                        api_url,
                        headers=api_headers,
                        proxies={"http": f"http://{self.current_proxy}", "https": f"http://{self.current_proxy}"} if self.current_proxy and self.current_proxy != "" else None,
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
                        
                        logger.info(f"Successfully extracted basic user data for {username}")
                    else:
                        logger.warning(f"User info API request failed with status code: {response.status_code}")
                except Exception as e:
                    logger.error(f"Error accessing user info API: {e}")
                
                # Step 3: Get contact info (for bug bounty research purposes)
                try:
                    contact_api_url = f"https://i.instagram.com/api/v1/users/{user_data['user_id']}/contact_info/"
                    
                    response = requests.get(
                        contact_api_url,
                        headers=api_headers,
                        proxies={"http": f"http://{self.current_proxy}", "https": f"http://{self.current_proxy}"} if self.current_proxy and self.current_proxy != "" else None,
                        timeout=10
                    )
                    
                    if response.status_code == 200:
                        contact_info = response.json()
                        
                        # Extract email and phone (masked/partial for ethical research)
                        user_data["email"] = contact_info.get("user", {}).get("email")
                        user_data["phone"] = contact_info.get("user", {}).get("phone_number")
                        
                        logger.info(f"Successfully extracted contact information for {username}")
                    else:
                        logger.warning(f"Contact API request failed with status code: {response.status_code}")
                except Exception as e:
                    logger.error(f"Error accessing contact API: {e}")
            
            return user_data
            
        except Exception as e:
            logger.error(f"Error extracting user data: {e}")
            return user_data  # Return partial data if we have any

    def close(self):
        """Clean up resources before shutting down."""
        if self.driver:
            try:
                self.driver.quit()
            except:
                pass
        logger.info("Resources cleaned up")


def main():
    """Main function to create multiple accounts and report simultaneously."""
    # Initialize the account manager
    manager = AccountManager(platform="instagram")
    
    # Number of accounts to create
    num_accounts = 5
    target_username = "the_way_i_.blink"
    reason = "spam"
    
    accounts = []
    
    try:
        # Create multiple temporary accounts
        for i in range(num_accounts):
            account = manager.create_temporary_account()
            accounts.append(account)
            logger.info(f"Created account {i+1}/{num_accounts}: {account['username']}")
        
        # Use multiple accounts to report
        for i, account in enumerate(accounts):
            logger.info(f"Using account {i+1}/{num_accounts}: {account['username']}")
            
            # Login with the account
            if manager.login(account):
                logger.info(f"Login successful for account: {account['username']}")
                
                # Report the target account
                if manager.report_account(target_username, reason):
                    logger.info(f"Successfully reported {target_username} using account {account['username']}")
                else:
                    logger.error(f"Failed to report {target_username} using account {account['username']}")
                
                # Extract user data (for research purposes only)
                user_data = manager.extract_user_data(target_username)
                if user_data:
                    logger.info(f"Extracted data for user {target_username} using account {account['username']}")
                
                # Optional: Add a delay between accounts to avoid detection
                if i < len(accounts) - 1:
                    delay = random.uniform(3, 7)
                    logger.info(f"Waiting {delay:.2f} seconds before using next account")
                    time.sleep(delay)
            else:
                logger.error(f"Login failed for account: {account['username']}")
    except Exception as e:
        logger.error(f"Error in main process: {e}")
    finally:
        # Always clean up resources
        manager.close()

if __name__ == "__main__":
    main()
