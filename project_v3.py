import random
import time
import ssl
import certifi
import urllib3
import threading
import requests
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import queue
import os
import json
import re
import string
import logging
import concurrent.futures
import urllib.parse
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from colorama import Fore, Style, init
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from requests.adapters import HTTPAdapter
from urllib3 import Retry
from urllib.parse import urlparse
from requests.adapters import HTTPAdapter
from urllib3 import Retry
from concurrent.futures import ThreadPoolExecutor

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Initialize colorama
init(autoreset=True)

class DebugConsole:
    def __init__(self, root):
        """Initialize the debug console."""
        self.root = root
        self.console_window = tk.Toplevel(root)
        self.console_window.title("Debug Console")
        self.console_window.geometry("600x400")
        self.console_window.minsize(500, 300)
        
        # Configure the console window to match the main app style
        self.console_window.configure(bg="#2c2c2c")
        
        # Create the text widget
        self.text_widget = scrolledtext.ScrolledText(
            self.console_window, 
            wrap=tk.WORD, 
            font=("Courier", 10),
            bg="#1c1c1c",
            fg="#ffffff"
        )
        self.text_widget.pack(fill=tk.BOTH, expand=True)
        self.text_widget.config(state=tk.DISABLED)
        
        # Create a queue for thread-safe logging
        self.log_queue = queue.Queue()
        
        # Start the update process
        self.update_console()
    
    def log(self, message, color=Fore.WHITE):
        """Add a colored message to the log queue."""
        self.log_queue.put((message, color))
    
    def update_console(self):
        """Update the console with new messages from the queue."""
        while not self.log_queue.empty():
            message, color = self.log_queue.get()
            self.text_widget.config(state=tk.NORMAL)
            
            # Map colorama colors to Tkinter tags
            tag = None
            if color == Fore.RED:
                tag = "error"
            elif color == Fore.GREEN:
                tag = "success"
            elif color == Fore.YELLOW:
                tag = "warning"
            elif color == Fore.CYAN:
                tag = "info"
            elif color == Fore.MAGENTA:
                tag = "highlight"
            
            # Insert the message with the appropriate tag
            self.text_widget.insert(tk.END, message + "\n", tag if tag else None)
            
            # Configure tags with appropriate colors
            if tag:
                color_map = {
                    "error": "#ff5555",
                    "success": "#55ff55",
                    "warning": "#ffff55",
                    "info": "#55ffff",
                    "highlight": "#ff55ff"
                }
                self.text_widget.tag_config(tag, foreground=color_map[tag])
            
            self.text_widget.see(tk.END)
            self.text_widget.config(state=tk.DISABLED)
        
        # Schedule the next update
        self.console_window.after(100, self.update_console)

class AccountGenerator:
    def __init__(self, debug_console, manager):
        """Initialize the account generator."""
        self.debug_console = debug_console
        self.manager = manager
        self.accounts = []
        self.running = False
        self.stop_flag = threading.Event()
    
    def generate_username(self):
        """Generate a random username."""
    real_names = [  "Liam", "Olivia", "Noah", "Emma", "Oliver", "Ava", "Elijah", "Sophia",
        "William", "Isabella", "James", "Charlotte", "Benjamin", "Amelia",
        "Henry", "Mia", "Alexander", "Evelyn", "Ethan", "Harper", "Michael",
        "Abigail", "Daniel", "Emily", "Matthew", "Elizabeth", "Joseph",
        "Sofia", "David", "Madison", "Samuel", "Ella", "Anthony", "Scarlett",
        "Christopher", "Grace", "John", "Chloe", "Andrew", "Victoria",
        "Joshua", "Aria", "Ryan", "Lily", "Jackson", "Aubrey", "Nathan",
        "Zoey", "Caleb", "Penelope", "Tyler", "Layla", "Nicholas", "Riley",
        "Brandon", "Nora", "Austin", "Addison", "Kevin", "Hannah", "Zachary",
        "Brooklyn", "Jose", "Paisley", "Adam", "Leah", "Bryan", "Hazel",
        "Aaron", "Violet", "Justin", "Aurora", "Adrian", "Alice", "Albert",
        "Allison", "Alan", "Alyssa", "Albert", "Amanda", "Alex", "Amber",
        "Alfred", "Andrea", "Arthur", "Angela", "Arnold", "Anita", "August",
        "Ashley", "Ben", "Beverly", "Bill", "Bonnie", "Bobby", "Brandi",
        "Bradley", "Brandy", "Brent", "Briana", "Brian", "Brittany", "Bruce",
        "Candace", "Carl", "Carole", "Carlos", "Carrie", "Casey", "Catherine",
        "Cecil", "Cecilia", "Cedric", "Celeste", "Chad", "Chelsea", "Charles",
        "Cheryl", "Chester", "Christina", "Chris", "Christine", "Clarence", "Claudia",
        "Clayton", "Cleo", "Clifford", "Colleen", "Corey", "Courtney", "Craig",
        "Crystal", "Curtis", "Cynthia", "Dale", "Dana", "Darrell", "Darlene",
        "Darren", "Dawn", "Dave", "Deanna", "Dennis", "Denise", "Derek", "Desiree",
        "Devin", "Diana", "Don", "Donna", "Douglas", "Dustin", "Dwayne", "Dwight",
        "Earl", "Edgar", "Edith", "Edmund", "Eileen", "Eldon", "Eleanor", "Eli",
        "Elisa", "Elliot", "Eloise", "Elmer", "Elsa", "Elvis", "Erica", "Ernest",
        "Estelle", "Eugene", "Eva", "Everett", "Faith", "Floyd", "Francis", "Fred",
        "Gabriel", "Gail", "Gary", "Genevieve", "Geoffrey", "Georgia", "Gerald", "Gina",
        "Glen", "Glenda", "Gordon", "Gwen", "Hannah", "Harley", "Harold", "Hazel",
        "Hector", "Heidi", "Herbert", "Hilda", "Homer", "Hope", "Howard", "Hunter",
        "Ian", "Ida", "Ignacio", "Irene", "Isaac", "Iris", "Ismael", "Ivy", "Jack",
        "Jacqueline", "Jaime", "Janet", "Janice", "Jared", "Jasmin", "Jason", "Jay",
        "Jean", "Jeff", "Jenna", "Jennifer", "Jenny", "Jeremiah", "Jeremy", "Jerome",
        "Jerry", "Jesse", "Jessica", "Jessie", "Jill", "Jim", "Joan", "Joann", "Joe",
        "Joel", "Joey", "John", "Johnny", "Jon", "Jonathan", "Jordon", "Jordan", "Jorge",
        "Joseph", "Josh", "Joshua", "Joyce", "Juan", "Judith", "Judy", "Julia", "Julian",
        "Julie", "Julio", "Justin", "Kara", "Karen", "Kari", "Karl", "Kate", "Kathleen",
        "Kathy", "Katie", "Keith", "Kelly", "Ken", "Kendra", "Kenneth", "Kerry", "Kevin",
        "Kim", "Kimberly", "Kirk", "Krista", "Kristen", "Kristin", "Kristy", "Kurt", "Kyle",
        "Lacey", "Lana", "Lance", "Laura", "Lauren", "Laurie", "Lawrence", "Lee", "Leigh",
        "Leo", "Leon", "Leonard", "Leslie", "Levi", "Lewis", "Lillian", "Linda", "Lindsay",
        "Lisa", "Lloyd", "Logan", "Lois", "Loretta", "Lori", "Louis", "Lucas", "Lucille",
        "Lucy", "Luis", "Luke", "Lydia", "Lynn", "Mabel", "Mack", "Madeline", "Maggie",
        "Malcolm", "Mandy", "Manuel", "Marc", "Marcia", "Marcus", "Margaret", "Maria",
        "Marian", "Marie", "Marilyn", "Mario", "Marissa", "Mark", "Marsha", "Martin",
        "Marty", "Marvin", "Mary", "Mason", "Matt", "Maureen", "Maurice", "Max", "Megan",
        "Melinda", "Melissa", "Melvin", "Meredith", "Merle", "Mia", "Micah", "Michael",
        "Michele", "Mickey", "Miguel", "Mildred", "Miles", "Milton", "Mindy", "Miriam",
        "Mitchell", "Moises", "Mollie", "Mona", "Monica", "Morgan", "Morris", "Morton",
        "Moses", "Muriel", "Myra", "Myrna", "Nancy", "Nathan", "Neal", "Neil", "Nettie",
        "Nicholas", "Nick", "Nicolas", "Nicole", "Nina", "Noah", "Norma", "Norman", "Ola",
        "Olive", "Oliver", "Ollie", "Omar", "Ophelia", "Oscar", "Owen", "Pablo", "Paige",
        "Pamela", "Pat", "Patricia", "Patrick", "Paul", "Paula", "Peggy", "Penny", "Percy",
        "Pete", "Peter", "Phil", "Philip", "Phoebe", "Phyllis", "Polly", "Preston", "Prudence",
        "Quentin", "Rachel", "Rafael", "Ralph", "Ramon", "Randall", "Randy", "Raoul", "Ray",
        "Raymond", "Rebecca", "Regina", "Reginald", "Renee", "Rex", "Ricardo", "Richard",
        "Rick", "Rita", "Robert", "Roberta", "Roberto", "Robin", "Rochelle", "Rod", "Rodney",
        "Roger", "Roland", "Roma", "Ronald", "Rosa", "Rose", "Rosemary", "Ross", "Roxanne",
        "Roy", "Ruby", "Rudolph", "Russell", "Ruth", "Ryan", "Sabrina", "Sadie", "Sally",
        "Salvadore", "Sam", "Samantha", "Samuel", "Sandra", "Sandy", "Sara", "Sarah", "Saul",
        "Scott", "Sean", "Sebastian", "Selena", "Serena", "Seth", "Shane", "Shannon", "Shari",
        "Sharon", "Shaun", "Shawn", "Sheila", "Shelley", "Shelly", "Sheri", "Sherri", "Sherry",
        "Shirley", "Sidney", "Silvia", "Simon", "Solomon", "Sonia", "Sonja", "Sophia", "Stacey",
        "Stacy", "Stan", "Stanley", "Stefanie", "Stephen", "Sterling", "Steve", "Steven", "Stuart",
        "Sue", "Summer", "Susan", "Suzanne", "Sydney", "Sylvia", "Tabitha", "Tamara", "Tami",
        "Tammy", "Tanya", "Tara", "Tasha", "Taylor", "Ted", "Teddy", "Terence", "Teresa", "Teri",
        "Terry", "Thad", "Thelma", "Theodore", "Theresa", "Thomas", "Tim", "Timothy", "Tina",
        "Toby", "Todd", "Tom", "Tommy", "Toni", "Tonya", "Tracey", "Tracy", "Travis", "Trent",
        "Trevor", "Troy", "Tyler", "Tyrone", "Una", "Ursula", "Valerie", "Vanessa", "Vera",
        "Vernon", "Veronica", "Victor", "Victoria", "Vincent", "Viola", "Virgil", "Virginia",
        "Vivian", "Wade", "Wallace", "Walter", "Wanda", "Wayne", "Wendy", "Wesley", "Whitney",
        "Wilbert", "Wilbur", "Wiley", "Willard", "William", "Willie", "Wilson", "Winifred", "Woodrow",
        "Wyatt", "Yolanda", "Yvonne", "Zachary", "Zane", "Zara"
        ]
        
    prefixes = [
        "", "the", "official", "real", "unique", "one", "just", "hey", "ask",
        "top", "pro", "cool", "art", "style", "vibes", "world", "daily", "moment",
        "space", "light", "dark", "wild", "urban", "retro", "modern", "eco", "zen",
        "raw", "pure", "kind", "joy", "code", "tech", "web", "data", "pixel", "ink",
        "aura", "glow", "mrs", "mr", "miss", "ms", "sir", "madam", "lord", "lady",
        "dr", "prof", "capt", "gen", "rev", "hon", "amb", "gov", "mayor", "coach",
        "chief", "officer", "agent", "expert", "guru", "ace", "king", "queen", "prince",
        "princess", "count", "countess", "duke", "duchess", "earl", "baron", "knight",
        "saint", "angel", "alpha", "omega", "prime", "elite", "legend", "master",
        "vision", "quest", "peak", "summit", "zenith", "nova", "star", "comet",
        "galaxy", "cosmos", "orbit", "echo", "rhythm", "melody", "harmony", "grace",
        "muse", "saga", "tale", "myth", "rune", "quest", "path", "voyage", "journey"
    ]
        
    suffixes = [
        "", "_official", "_real", "_one", "_pro", "_art", "_style", "_vibes",
        "_world", "_daily", "_moment", "_space", "_light", "_dark", "_wild",
        "_urban", "_retro", "_modern", "_eco", "_zen", "_raw", "_pure", "_kind",
        "_joy", "_code", "_tech", "_web", "_data", "_pixel", "_ink", "_aura", "_glow",
        "fan", "lover", "user", "official", "real", "original", "creator", "artist",
        "dev", "hub", "zone", "lab", "source", "hq", "base", "life", "gram", "ig",
        "now", "here", "today", "plus", "edit", "x", "id", "247", "007", "_",
        "online", "active", "united", "global", "nation", "central", "media",
        "works", "inc", "ltd", "group", "team", "network", "systems", "solutions",
        "design", "studio", "digital", "connect", "engage", "impact", "fusion",
        "matrix", "sphere", "domain", "nexus", "infinity", "legacy", "dynasty",
        "empire", "kingdom", "clan", "crew", "squad", "fam", "gang", "posse",
        "tribe", "comm", "unity", "collective", "syndicate", "alliance", "federation",
        "union", "league", "order", "guild", "circle", "forum", "summit", "haven",
        "oasis", "sanctuary", "refuge", "citadel", "fortress", "bastion", "stronghold"
    ]
        
    name_part = random.choice(real_names).lower()
    prefix_part = random.choice(prefixes).lower()
    suffix_part = random.choice(suffixes).lower()
    random_num = random.randint(10, 999)
    years = ["2023", "2024", "2025", ""]
    year = random.choice(years)

    parts = [prefix_part, name_part, suffix_part]
    random.shuffle(parts)

    username = "".join(parts) + str(random_num)

    if random.random() < 0.3:  # 30% chance to include a year
        username += year

    username = username.replace("__", "_")
    if username.startswith("_"):
        username = username[1:]
    if username.endswith("_"):
        username = username[:-1]

    def generate_email(self, username):
        """Generate a random email based on username."""
        domains = ["gmail.com", "outlook.com", "yahoo.com", "protonmail.com", "mail.com"]
        return f"{username}{random.randint(10, 99)}@{random.choice(domains)}"
    
    def generate_password(self):
        """Generate a strong random password."""
        length = random.randint(10, 16)
        chars = string.ascii_letters + string.digits + "!@#$%^&*"
        password = ''.join(random.choice(chars) for _ in range(length))
        
        # Ensure password has at least one uppercase, lowercase, digit, and special char
        if not any(c.isupper() for c in password):
            password = password[:-1] + random.choice(string.ascii_uppercase)
        if not any(c.islower() for c in password):
            password = password[:-1] + random.choice(string.ascii_lowercase)
        if not any(c.isdigit() for c in password):
            password = password[:-1] + random.choice(string.digits)
        if not any(c in "!@#$%^&*" for c in password):
            password = password[:-1] + random.choice("!@#$%^&*")
            
        return password
    
    def generate_account(self):
        """Generate account details."""
        username = self.generate_username()
        email = self.generate_email(username)
        password = self.generate_password()
        return {"username": username, "email": email, "password": password}
    
    def verify_account(self, account):
        """Verify if an Instagram username is available."""
        self.debug_console.log(f"Verifying {account['username']}...", Fore.YELLOW)
        
        # Select a working proxy
        proxy = None
        if self.manager.proxies:
            proxy = random.choice(self.manager.proxies)
            if proxy.startswith("http://"):
                proxy_dict = {"http": proxy}  # Only use HTTP
            elif proxy.startswith("https://"):
                proxy_dict = {"https": proxy}  # Only use HTTPS
            else:
                self.debug_console.log(f"[✖] Skipping invalid proxy: {proxy}", Fore.RED)
                return False
        else:
            proxy_dict = None
        
        self.debug_console.log(f"Checking proxy: {proxy}", Fore.CYAN)
        
        # Perform API request with retry strategy
        session = requests.Session()
        retry_strategy = Retry(
            total=3,  # Retry 3 times before failing
            status_forcelist=[500, 502, 503, 504],
            allowed_methods=["GET"]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("https://", adapter)
        session.mount("http://", adapter)

        try:
            response = session.get(
                f"https://www.instagram.com/web/search/topsearch/?query={account['username']}",
                proxies=proxy_dict, timeout=10
            )
            if response.status_code == 200:
                data = response.json()
                if not any(user.get("user", {}).get("username", "").lower() == account['username'].lower() for user in data.get("users", [])):
                    self.debug_console.log(f"[✔] Username {account['username']} is available", Fore.GREEN)
                    return True
                
                else:
                    self.debug_console.log(f"[✖] Username {account['username']} is taken", Fore.RED)
            else:
                self.debug_console.log(f"[✖] API returned status code {response.status_code}", Fore.RED)
        except requests.RequestException as e:
            self.debug_console.log(f"[✖] Proxy Error: {proxy} - {e}", Fore.RED)

        return False
    
    def create_accounts(self, count=5, verify=True):
        """Create multiple accounts."""
        if self.running:
            self.debug_console.log("Account generation already in progress!", Fore.YELLOW)
            return
        
        self.running = True
        self.stop_flag.clear()
        
        self.debug_console.log(f"Starting generation of {count} accounts...", Fore.CYAN)
        successful = 0
        
        for i in range(count):
            if self.stop_flag.is_set():
                self.debug_console.log("Account generation stopped by user", Fore.YELLOW)
                break
                
            self.debug_console.log(f"Generating account {i+1}/{count}...", Fore.CYAN)
            account = self.generate_account()
            
            if not verify or self.verify_account(account):
                self.accounts.append(account)
                self.manager.accounts.append(account)
                successful += 1
                self.debug_console.log(f"Account created: {account['username']} / {account['email']}", Fore.GREEN)
            
            # Add a random delay between account creations
            if i < count - 1 and not self.stop_flag.is_set():
                delay = random.uniform(0.5, 2.0)
                time.sleep(delay)
        
        self.debug_console.log(f"Account generation completed! Created {successful} accounts.", Fore.MAGENTA)
        self.running = False
        
        # Return the newly created accounts
        return self.accounts[-successful:] if successful > 0 else []
    
    def stop_generation(self):
        """Stop the account generation process."""
        if self.running:
            self.stop_flag.set()
            self.debug_console.log("Stopping account generation...", Fore.YELLOW)
        else:
            self.debug_console.log("No account generation in progress", Fore.YELLOW)

def extract_proxies_from_html(html_content, url):
    """Extracts proxies from HTML content"""
    proxies = set()
    try:
        soup = BeautifulSoup(html_content, 'html.parser')

        # 1. IP:PORT from tables
        for table in soup.find_all('table'):
            for row in table.find_all('tr'):
                columns = row.find_all('td')
                if len(columns) >= 2:
                    ip_match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", columns[0].text.strip())
                    port_match = re.search(r"(\d{2,5})", columns[1].text.strip())
                    if ip_match and port_match:
                        ip = ip_match.group(1)
                        port = port_match.group(1)
                        proxies.add(f"{ip}:{port}")
                        logging.debug(f"Extracted proxy {ip}:{port} from table in {url}")

        # 2. IP:PORT from text, outside tables
        body_text = soup.body.get_text() if soup.body else ""
        ip_port_pairs = re.findall(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{2,5})", body_text)
        proxies.update(ip_port_pairs)
        for proxy in ip_port_pairs:
            logging.debug(f"Extracted proxy {proxy} from text in {url}")

        # 3. Script tags
        for script in soup.find_all('script'):
            script_text = script.text
            ip_port_pairs = re.findall(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{2,5})", script_text)
            proxies.update(ip_port_pairs)
        for proxy in ip_port_pairs:
            logging.debug(f"Extracted proxy {proxy} from script in {url}")

    except Exception as e:
        logging.error(f"Error extracting proxies from {url}: {e}")
    return proxies

def search_internet_for_proxies(start_urls, max_pages_per_domain=5, max_total_pages=50):
    """Searches the internet for proxies"""
    found_proxies = set()
    visited_urls = set()
    urls_to_visit = list(start_urls)
    pages_per_domain = {}
    total_pages_visited = 0
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }
    max_threads = 10  # Reduced number of threads for safety
    # Configure retry mechanism
    retry_strategy = Retry(
        total=3,
        status_forcelist=[429, 500, 502, 503, 504, 520, 521, 522, 523, 524, 525, 526, 527, 528, 529, 530],
        allowed_methods=["GET"]
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    http = requests.Session()
    http.mount("https://", adapter)
    http.mount("http://", adapter)

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        while urls_to_visit and total_pages_visited < max_total_pages:
            url = urls_to_visit.pop(0)
            if url in visited_urls:
                continue
            visited_urls.add(url)
            total_pages_visited += 1

            try:
                domain = urlparse(url).netloc  # Extract the domain using urllib
                if domain in pages_per_domain and pages_per_domain[domain] >= max_pages_per_domain:
                    logging.info(f"Skipping domain {domain}: Reached max pages")
                    continue

                logging.info(f"Fetching URL: {url} (Total pages visited: {total_pages_visited})")
                response = http.get(url, headers=headers, timeout=10)
                response.raise_for_status()
                html_content = response.text

                # Use a thread to extract proxies
                future = executor.submit(extract_proxies_from_html, html_content, url)

                # Find new URLs on the page, more robust URL handling
                soup = BeautifulSoup(html_content, 'html.parser')
                for a_tag in soup.find_all('a', href=True):
                    href = a_tag['href']
                    # Join the URLs
                    abs_url = urllib.parse.urljoin(url, href)
                    if abs_url.startswith('http') and domain in abs_url:
                        if abs_url not in visited_urls and abs_url not in urls_to_visit:
                            urls_to_visit.append(abs_url)

                extracted_proxies = future.result()
                found_proxies.update(extracted_proxies)

                pages_per_domain[domain] = pages_per_domain.get(domain, 0) + 1

            except requests.exceptions.RequestException as e:
                logging.error(f"Error fetching {url}: {e}")
            except Exception as e:
                logging.error(f"Error processing {url}: {e}")
            time.sleep(1)  # Increased delay

    return found_proxies

def check_proxy(proxy):
    """Checks if a proxy is working with SSL verification fixes"""
    test_url = "https://www.instagram.com"
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }
    start_time = time.time()
    try:
        # Create a session with retry capabilities
        session = requests.Session()
        retries = Retry(total=2, backoff_factor=0.5, status_forcelist=[500, 502, 503, 504])
        session.mount('http://', HTTPAdapter(max_retries=retries))
        session.mount('https://', HTTPAdapter(max_retries=retries))
        
        # Import SSL context
        import ssl
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        
        # Format the proxy correctly
        proxy_dict = {}
        if proxy:
            if not proxy.startswith('http'):
                proxy_with_protocol = f'http://{proxy}'
                proxy_dict = {
                    'http': proxy_with_protocol,
                    'https': proxy_with_protocol
                }
            else:
                proxy_dict = {
                    'http': proxy,
                    'https': proxy
                }
        
        response = session.get(
            test_url,
            headers=headers,
            proxies=proxy_dict,
            timeout=5,
            verify=False  # Disable SSL verification for testing
        )
        
        if response.status_code == 200 and (time.time() - start_time) < 5:
            logging.info(f"Proxy {proxy} is working")
            return True
        else:
            logging.warning(f"Proxy {proxy} failed: Status Code: {response.status_code}, Time: {time.time() - start_time:.2f}s")
            return False
    except requests.exceptions.SSLError as e:
        logging.warning(f"Proxy {proxy} SSL error: {e}")
        # Try again with SSL verification disabled
        try:
            response = session.get(
                test_url,
                headers=headers,
                proxies=proxy_dict,
                timeout=5,
                verify=False
            )
            if response.status_code == 200:
                logging.info(f"Proxy {proxy} is working (SSL verification disabled)")
                return True
        except Exception as retry_e:
            logging.warning(f"Proxy {proxy} retry failed: {retry_e}")
        return False
    except Exception as e:
        logging.warning(f"Proxy {proxy} error: {e}")
        return False

def get_working_proxies(proxies):
    """Checks a list of proxies and returns only the working ones."""
    working_proxies = []
    for proxy in proxies:
        if check_proxy(proxy):
            working_proxies.append(proxy)
        else:
            logging.warning(f"Removing dead proxy: {proxy}")
    
    return working_proxies

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

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
        
        # Initialize debug console
        self.debug_console = DebugConsole(self.root)
        
        # Initialize account generator
        self.account_generator = AccountGenerator(self.debug_console, self.manager)
        
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
        
        # Generator tab (NEW)
        self.generator_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.generator_tab, text="Generator")
        
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
        
        # Setup generator tab (NEW)
        self.setup_generator_tab()
        
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
        
        # Log startup
        self.debug_console.log("Instagram Account Manager started", Fore.CYAN)
        self.debug_console.log("Debug console initialized", Fore.GREEN)
    
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
    
    def login_selected_account(self):
        """Login with the selected account from the listbox."""
        selected_index = self.account_listbox.curselection()
        if not selected_index:
            messagebox.showerror("Error", "No account selected")
            return
        
        selected_account = self.manager.accounts[selected_index[0]]
        self.debug_console.log(f"Logging in with account: {selected_account['username']}", Fore.CYAN)
        
        # Start login in a separate thread
        threading.Thread(target=self.login_thread, args=(selected_account,)).start()
    
    def login_thread(self, account):
        """Thread to handle the login process."""
        success = self.manager.login(account)
        self.update_login_status(success, account["username"])
    
    def update_login_status(self, success, username):
        """Update the login status in the GUI."""
        if success:
            self.debug_console.log(f"Successfully logged in as {username}", Fore.GREEN)
        else:
            self.debug_console.log(f"Failed to log in as {username}", Fore.RED)
    
    def remove_selected_account(self):
        """Remove the selected account from the listbox and manager."""
        selected_index = self.account_listbox.curselection()
        if not selected_index:
            messagebox.showerror("Error", "No account selected")
            return
        
        selected_account = self.manager.accounts.pop(selected_index[0])
        self.account_listbox.delete(selected_index)
        self.debug_console.log(f"Removed account: {selected_account['username']}", Fore.YELLOW)
    
    def report_thread(self, target, reason):
        """Thread to handle the reporting process."""
        success = self.manager.report_account(target, reason)
        self.update_report_status(success, target)
    
    def update_report_status(self, success, target):
        """Update the report status in the GUI."""
        if success:
            self.debug_console.log(f"Successfully reported {target}", Fore.GREEN)
        else:
            self.debug_console.log(f"Failed to report {target}", Fore.RED)
    
    def start_mass_report(self):
        """Start mass reporting with multiple accounts."""
        target_username = self.target_var.get()
        reason = self.reason_var.get()
        num_accounts = self.num_accounts_var.get()
        
        if not target_username or not reason:
            messagebox.showerror("Error", "Target username and reason are required")
            return
        
        self.debug_console.log(f"Starting mass report on {target_username} for {reason} using {num_accounts} accounts", Fore.CYAN)
        
        # Generate random accounts
        self.debug_console.log(f"Generating {num_accounts} random accounts for mass reporting...", Fore.CYAN)
        random_accounts = self.account_generator.create_accounts(count=num_accounts, verify=False)
        
        if not random_accounts:
            messagebox.showerror("Error", "Failed to generate random accounts")
            return
        
        self.debug_console.log(f"Generated {len(random_accounts)} random accounts", Fore.CYAN)
        
        # Start mass reporting in a separate thread
        threading.Thread(target=self.mass_report_thread, args=(target_username, reason, random_accounts)).start()
    
    def mass_report_thread(self, target, reason, accounts):
        """Thread to handle the mass reporting process."""
        success_count = 0
        for i, account in enumerate(accounts):
            self.manager.current_account = account
            success = self.manager.report_account(target, reason)
            if success:
                success_count += 1
            self.update_mass_report_status(success_count, i + 1, target)
            time.sleep(self.manager.settings["report_interval_seconds"])
    
    def update_mass_report_status(self, success_count, total, target):
        """Update the mass report status in the GUI."""
        self.debug_console.log(f"Mass report status: {success_count}/{total} reports successful for {target}", Fore.CYAN)

    def extract_user_data(self):
        """Extract data for the specified user."""
        target_username = self.data_target_var.get()
        
        if not target_username:
            messagebox.showerror("Error", "Target username is required")
            return
        
        self.debug_console.log(f"Extracting data for {target_username}", Fore.CYAN)
        
        # Start data extraction in a separate thread
        threading.Thread(target=self.extract_thread, args=(target_username,)).start()
    
    def extract_thread(self, target):
        """Thread to handle the data extraction process."""
        user_data = self.manager.extract_user_data(target)
        self.update_extraction_results(user_data)
    
    def update_extraction_results(self, user_data):
        """Update the extraction results in the GUI."""
        self.results_text.config(state=tk.NORMAL)
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, json.dumps(user_data, indent=4))
        self.results_text.config(state=tk.DISABLED)
    
    def refresh_proxies(self):
        """Refresh the list of proxies."""
        self.debug_console.log("Refreshing proxies...", Fore.CYAN)
        
        # Start proxy refresh in a separate thread
        threading.Thread(target=self.refresh_proxies_thread).start()
    
    def refresh_proxies_thread(self):
        """Thread to handle the proxy refresh process."""
        self.manager.load_proxies()
        self.update_proxy_count()
    
    def update_proxy_count(self):
        """Update the proxy count in the GUI."""
        self.proxy_count_var.set(f"Proxies: {len(self.manager.proxies)}")
    
    def save_settings(self):
        """Save the settings."""
        self.manager.settings["max_reports_per_day"] = self.max_reports_var.get()
        self.manager.settings["report_interval_seconds"] = self.interval_var.get()
        self.debug_console.log("Settings saved", Fore.GREEN)

    def report_account(self):
        """Report the selected account for the specified reason."""
        target_username = self.target_var.get()
        reason = self.reason_var.get()
        
        if not target_username or not reason:
            messagebox.showerror("Error", "Target username and reason are required")
            return
        
        self.debug_console.log(f"Reporting account: {target_username} for {reason}", Fore.CYAN)
        
        # Start reporting in a separate thread
        threading.Thread(target=self.report_thread, args=(target_username, reason)).start()
    
    def report_thread(self, target, reason):
        """Thread to handle the reporting process."""
        success = self.manager.report_account(target, reason)
        self.update_report_status(success, target)
    
    def update_report_status(self, success, target):
        """Update the report status in the GUI."""
        if success:
            self.debug_console.log(f"Successfully reported {target}", Fore.GREEN)
        else:
            self.debug_console.log(f"Failed to report {target}", Fore.RED)


    def setup_account_tab(self):
        """

        This method initializes the account tab by creating the necessary frames, 
        labels, entry fields, buttons, and listbox for managing Instagram accounts.
        It includes fields for email, username, and password, and buttons for creating 
        accounts and logging in with selected accounts.
        """
        """Setup the account tab."""
        # Add your implementation for setting up the account tab here
        
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
        """Setup the report tab."""
        # Add your implementation for setting up the report tab here
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
        # Add your implementation for setting up the data extraction tab here
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
    
    
    def setup_generator_tab(self):
        """Setup the account generator tab."""
        # Add your implementation for setting up the generator tab here
        pass
    
    def setup_settings_tab(self):
        """Setup the settings tab."""
        # Add your implementation for setting up the settings tab here
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
            self.log_text.config(state=tk.DISABLED)
            self.log_text.yview(tk.END)
        self.root.after(100, self.update_log)
    
    def on_close(self):
        """Handle the close event."""
        self.manager.close()
        self.root.destroy()

# Update the InstagramAccountManager class to integrate with the new components
def close(self):
    """Properly close all resources"""
    if self.driver:
        try:
            self.driver.quit()
        except:
            pass
    
    # Save accounts to file
    try:
        with open("accounts.json", "w") as f:
            json.dump(self.accounts, f)
    except Exception as e:
        self.logger.error(f"Error saving accounts: {e}")

class InstagramAccountManager:
    def __init__(self, log_queue=None, debug_console=None):
        """Initialize the account manager."""
        self.log_queue = log_queue
        self.debug_console = debug_console
        self.logger = self.setup_logger()
        self.accounts = []
        self.current_account = None
        self.driver = None
        
        # Updated platform URLs with additional endpoints
        self.platform_urls = {
            "base": "https://www.instagram.com/",
            "login": "https://www.instagram.com/accounts/login/",
            "report": "https://help.instagram.com/contact/1652567838289083",
            "api": "https://graph.instagram.com/v12.0/",
            "signup": "https://www.instagram.com/accounts/emailsignup/"
        }
        
        self.settings = {
            "max_reports_per_day": 5,
            "report_interval_seconds": 3600,
            "proxy_timeout_seconds": 10,
            "headless_mode": True,
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        }
        
        # Initialize proxy manager with improved handling
        self.proxy_manager = ProxyManager(debug_console)
        self.stop_proxy_fetching = threading.Event()
        self.current_proxy = None
        threading.Thread(target=self.load_proxies, daemon=True).start()

    def setup_logger(self):
        """Setup logger for the account manager."""
        logger = logging.getLogger("InstagramManager")
        logger.setLevel(logging.INFO)
        logger.handlers = []
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

        class DebugConsoleHandler(logging.Handler):
            def __init__(self, debug_console):
                super().__init__()
                self.debug_console = debug_console

            def emit(self, record):
                color_map = {
                    logging.ERROR: Fore.RED,
                    logging.WARNING: Fore.YELLOW,
                    logging.INFO: Fore.WHITE,
                    logging.DEBUG: Fore.CYAN
                }
                color = color_map.get(record.levelno, Fore.WHITE)
                formatted_message = self.format(record)
                if self.debug_console:
                    self.debug_console.log(formatted_message, color)

        if self.debug_console:
            console_handler = DebugConsoleHandler(self.debug_console)
            console_handler.setFormatter(formatter)
            logger.addHandler(console_handler)

        if self.log_queue:
            queue_handler = logging.Handler()
            queue_handler.setFormatter(formatter)
            queue_handler.emit = lambda record: self.log_queue.put(queue_handler.format(record))
            logger.addHandler(queue_handler)

        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

        return logger

    def load_proxies(self):
        """Load and verify proxies with improved error handling."""
        if self.stop_proxy_fetching.is_set():
            self.logger.info("Proxy fetching disabled")
            return

        try:
            start_urls = [
                "https://www.freeproxylists.net/",
                "https://free-proxy-list.net/",
                "https://www.sslproxies.org/",
                "https://www.us-proxy.org/",
                "https://hidemy.name/en/proxy-list/",
                "https://spys.one/free-proxy-list/",
                "https://www.proxynova.com/proxy-server-list/",
                "https://proxylist.geonode.com/",
                "https://www.proxyscan.io/",
                "https://www.proxy-list.download/"
            ]

            all_found_proxies = search_internet_for_proxies(start_urls, max_pages_per_domain=5, max_total_pages=50)
            self.logger.info(f"Found {len(all_found_proxies)} proxies across the internet.")

            working_proxies = get_working_proxies(all_found_proxies)
            if working_proxies:
                self.proxy_manager.add_proxies(working_proxies)
                self.logger.info(f"Verified {len(working_proxies)} working proxies")
            else:
                self.logger.warning("No working proxies found.")

        except Exception as e:
            self.logger.error(f"Error loading proxies: {e}")

    def stop_proxy_fetching(self):
        """Stop the proxy fetching process."""
        self.stop_proxy_fetching.set()
        self.logger.info("Proxy fetching stopped")
        
    def close(self):
        """Properly close all resources"""
        if self.driver:
            try:
                self.driver.quit()
            except:
                pass
            self.driver = None

        self.stop_proxy_fetching()
        
        # Save accounts to file
        try:
            with open("accounts.json", "w") as f:
                json.dump(self.accounts, f)
        except Exception as e:
            self.logger.error(f"Error saving accounts: {e}")

    def create_temporary_account(self, email=None, username=None, password=None):
        """Create a temporary account for testing."""
        if not email:
            username = f"user{random.randint(1000, 9999)}"
            email = f"{username}@example.com"
            password = f"Pass{random.randint(100000, 999999)}!"

        account = {
            "username": username,
            "email": email,
            "password": password,
            "reports_made": 0,
            "last_report_time": 0
        }

        self.accounts.append(account)
        self.logger.info(f"Created temporary account: {username}")
        return account

    def initialize_driver(self):
        """Initialize the WebDriver with improved resource management"""
        if self.driver:
            try:
                self.driver.quit()
            except:
                pass
            self.driver = None

        options = Options()
        if self.settings["headless_mode"]:
            options.add_argument("--headless")

        options.add_argument("--disable-gpu")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--disable-extensions")
        options.add_argument(f"user-agent={self.settings['user_agent']}")
        options.add_argument("--window-size=1920,1080")
        options.add_experimental_option("excludeSwitches", ["enable-automation"])
        options.add_experimental_option("useAutomationExtension", False)

        # Get proxy from proxy manager with improved handling
        proxy = self.proxy_manager.get_proxy()
        if proxy:
            options.add_argument(f'--proxy-server={proxy}')
            self.logger.info(f"Using proxy: {proxy}")
            self.current_proxy = proxy
        else:
            self.current_proxy = None
            self.logger.warning("No proxy available, using direct connection")

        try:
            self.driver = webdriver.Chrome(options=options)
            # Add stealth settings
            self.driver.execute_cdp_cmd("Page.addScriptToEvaluateOnNewDocument", {
                "source": """
                    Object.defineProperty(navigator, 'webdriver', {
                        get: () => undefined
                    });
                """
            })
            self.logger.info("WebDriver initialized successfully")
            return True
        except Exception as e:
            if self.current_proxy:
                self.proxy_manager.mark_dead(self.current_proxy)
                self.current_proxy = None
            self.logger.error(f"Error initializing WebDriver: {e}")
            return False

    def close(self):
        """Properly close all resources"""
        if self.driver:
            try:
                self.driver.quit()
            except:
                pass

        # Save accounts to file
        try:
            with open("accounts.json", "w") as f:
                json.dump(self.accounts, f)
        except Exception as e:
            self.logger.error(f"Error saving accounts: {e}")

    def login(self, account=None):
        """Login to Instagram with improved error handling and anti-detection measures."""
        if not account and self.accounts:
            account = self.accounts[0]
        elif not account:
            self.logger.error("No account provided for login")
            return False

        self.current_account = account
        
        if not self.driver and not self.initialize_driver():
            return False

        try:
            self.driver.get(self.platform_urls["login"])
            self.logger.info("Navigating to login page")
            time.sleep(random.uniform(2, 4))

            # Verify page load and refresh if needed
            try:
                page_source = self.driver.page_source
                if "login" not in page_source.lower():
                    self.logger.warning("Login page might not have loaded correctly")
                    self.driver.refresh()
                    time.sleep(random.uniform(3, 5))
            except:
                pass

            # Multiple selector fallbacks for username field
            username_selectors = [
                (By.NAME, "username"),
                (By.CSS_SELECTOR, "input[name='username']"),
                (By.CSS_SELECTOR, "input[aria-label='Phone number, username, or email']")
            ]
            
            username_field = None
            for by, selector in username_selectors:
                try:
                    username_field = WebDriverWait(self.driver, 5).until(
                        EC.presence_of_element_located((by, selector))
                    )
                    break
                except:
                    continue

            if not username_field:
                self.logger.error("Could not find username field")
                return False

            # Human-like typing
            username_field.clear()
            for char in account["username"]:
                username_field.send_keys(char)
                time.sleep(random.uniform(0.1, 0.3))

            # Similar pattern for password field
            password_selectors = [
                (By.NAME, "password"),
                (By.CSS_SELECTOR, "input[type='password']"),
                (By.CSS_SELECTOR, "input[aria-label='Password']")
            ]
            
            password_field = None
            for by, selector in password_selectors:
                try:
                    password_field = WebDriverWait(self.driver, 5).until(
                        EC.presence_of_element_located((by, selector))
                    )
                    break
                except:
                    continue

            if not password_field:
                self.logger.error("Could not find password field")
                return False

            # Human-like password typing
            password_field.clear()
            for char in account["password"]:
                password_field.send_keys(char)
                time.sleep(random.uniform(0.1, 0.3))

            time.sleep(random.uniform(0.5, 1.5))

            # Multiple submit button attempts
            try:
                submit_button = WebDriverWait(self.driver, 5).until(
                    EC.element_to_be_clickable((By.CSS_SELECTOR, "button[type='submit']"))
                )
                submit_button.click()
            except:
                try:
                    password_field.submit()
                except:
                    self.logger.error("Failed to submit login form")
                    return False

            # Verify successful login with multiple indicators
            success_selectors = [
                (By.CSS_SELECTOR, "main"),
                (By.CSS_SELECTOR, "nav"),
                (By.XPATH, "//a[contains(@href, '/direct/inbox')]"),
                (By.XPATH, "//a[contains(@href, '/explore')]")
            ]
            
            login_successful = False
            for by, selector in success_selectors:
                try:
                    WebDriverWait(self.driver, 5).until(
                        EC.presence_of_element_located((by, selector))
                    )
                    login_successful = True
                    break
                except:
                    continue

            if login_successful:
                self.logger.info(f"Successfully logged in as {account['username']}")
                return True
            else:
                self.logger.error("Could not verify successful login")
                return False

        except Exception as e:
            self.logger.error(f"Login process failed: {e}")
            return False

    def report_account(self, target_username, reason):
        """Report an account with improved anti-ban measures"""

        if not self.driver:
            if not self.login():
                self.logger.error("Cannot report account: Login failed")
                return False

        if self.current_account["reports_made"] >= self.settings["max_reports_per_day"]:
            self.logger.warning("Daily report limit reached for this account")
            return False

        time_since_last_report = time.time() - self.current_account["last_report_time"]
        if time_since_last_report < self.settings["report_interval_seconds"]:
            wait_time = self.settings["report_interval_seconds"] - time_since_last_report
            self.logger.info(f"Waiting {wait_time:.0f} seconds before making another report")
            time.sleep(wait_time)

        try:
            self.driver.get(f"{self.platform_urls['base']}{target_username}")
            time.sleep(random.uniform(2, 5))

            try:
                menu_selectors = [
                    "button[aria-label='More options']",
                    "button[aria-label='More']",
                    "span[aria-label='More options']"
                ]
                menu_clicked = False
                for selector in menu_selectors:
                    try:
                        menu_button = WebDriverWait(self.driver, 5).until(
                            EC.element_to_be_clickable((By.CSS_SELECTOR, selector))
                        )
                        menu_button.click()
                        menu_clicked = True
                        self.logger.info("Clicked menu button")
                        break
                    except:
                        continue

                if not menu_clicked:
                    self.logger.error("Could not find menu button")
                    return False

                report_selectors = [
                    "//button[contains(text(), 'Report')]",
                    "//span[contains(text(), 'Report')]",
                    "//div[contains(text(), 'Report')]"
                ]
                report_clicked = False
                for selector in report_selectors:
                    try:
                        report_button = WebDriverWait(self.driver, 5).until(
                            EC.element_to_be_clickable((By.XPATH, selector))
                        )
                        report_button.click()
                        report_clicked = True
                        self.logger.info("Clicked report button")
                        break
                    except:
                        continue

                if not report_clicked:
                    self.logger.error("Could not find report button")
                    return False

                reason_selectors = [
                    f"//button[contains(text(), '{reason}')]",
                    f"//span[contains(text(), '{reason}')]",
                    f"//div[contains(text(), '{reason}')]"
                ]
                reason_clicked = False
                for selector in reason_selectors:
                    try:
                        reason_button = WebDriverWait(self.driver, 5).until(
                            EC.element_to_be_clickable((By.XPATH, selector))
                        )
                        reason_button.click()
                        reason_clicked = True
                        self.logger.info(f"Selected reason: {reason}")
                        break
                    except:
                        continue

                if not reason_clicked:
                    self.logger.error("Could not select reason")
                    return False

                submit_selectors = [
                    "//button[contains(text(), 'Submit')]",
                    "//button[contains(text(), 'Submit report')]",
                    "//span[contains(text(), 'Submit')]"
                ]
                submit_clicked = False
                for selector in submit_selectors:
                    try:
                        submit_button = WebDriverWait(self.driver, 5).until(
                            EC.element_to_be_clickable((By.XPATH, selector))
                        )
                        submit_button.click()
                        submit_clicked = True
                        self.logger.info("Submitted report")
                        break
                    except:
                        continue

                if not submit_clicked:
                    self.logger.error("Could not submit report")
                    return False

                self.current_account["reports_made"] += 1
                self.current_account["last_report_time"] = time.time()
                self.logger.info(f"Successfully reported {target_username} for {reason}")
                return True

            except Exception as e:
                self.logger.error(f"Error reporting account {target_username}: {e}")
                return False
        except Exception as e:
            self.logger.error(f"Error navigating to profile: {e}")
            return False

    def extract_user_data(self, target_username):
        """Extract user data with improved error handling and data collection"""
        user_data = {
            "username": target_username,
            "email": None,
            "phone": None,
            "user_id": None,
            "full_name": None,
            "profile_pic": None,
            "is_private": None,
            "bio": None,
            "website": None,
            "followers": 0,
            "following": 0,
            "posts": 0,
            "additional_data": {}
        }
        
        # ...rest of V2's extraction logic...

    def extract_user_data(self):
        """Extract data from a user profile with improved error handling"""
        target = self.data_target_var.get()
        if not target:
            messagebox.showerror("Error", "Target username is required")
            return

        if not self.current_account:
            messagebox.showwarning("Warning", "No account logged in. Some data may be limited.")

        self.debug_console.log(f"Extracting data for: {target}", Fore.CYAN)
        self.results_text.config(state=tk.NORMAL)
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, f"Extracting data for {target}...\n")
        self.results_text.config(state=tk.DISABLED)

        # Start extraction in a separate thread
        threading.Thread(target=self.extract_thread, args=(target,), daemon=True).start()

    def extract_thread(self, target):
        """Thread to handle data extraction with robust error handling"""
        try:
            # Initialize driver if needed
            if not self.driver:
                self.initialize_driver()

            # Visit profile
            self.driver.get(f"{self.platform_urls['base']}{target}/")

            try:
                # Check if profile exists
                WebDriverWait(self.driver, 5).until(
                    EC.presence_of_element_located((By.XPATH, "//h2[contains(text(), 'Sorry, this page')]"))
                )
                self.update_results(f"Profile '{target}' does not exist or is private.")
                return
            except:
                # Profile exists, continue
                pass

            # Wait for profile to load
            WebDriverWait(self.driver, 10).until(
                EC.presence_of_element_located((By.XPATH, "//header"))
            )

            # Extract basic profile data
            data = {}
            try:
                data["username"] = target
                data["full_name"] = self.driver.find_element(By.XPATH, "//header//h1").text
            except Exception as e:
                self.logger.error(f"Error extracting name: {e}")
                data["full_name"] = "Not found"

            try:
                bio_elem = self.driver.find_element(By.XPATH, "//div[contains(@class, '-vDIg')]/span")
                data["bio"] = bio_elem.text
            except:
                data["bio"] = "No bio"

            # Extract counts
            try:
                counts = self.driver.find_elements(By.XPATH, "//header//ul/li")
                if len(counts) >= 3:
                    data["posts"] = counts[0].text.split()[0]
                    data["followers"] = counts[1].text.split()[0]
                    data["following"] = counts[2].text.split()[0]
                else:
                    data["posts"] = "N/A"
                    data["followers"] = "N/A"
                    data["following"] = "N/A"
            except Exception as e:
                self.logger.error(f"Error extracting counts: {e}")
                data["posts"] = "N/A"
                data["followers"] = "N/A"
                data["following"] = "N/A"

            # Extract profile picture URL
            try:
                profile_pic_elem = self.driver.find_element(By.XPATH, "//header//img")
                data["profile_picture"] = profile_pic_elem.get_attribute("src")
            except Exception as e:
                self.logger.error(f"Error extracting profile picture: {e}")
                data["profile_picture"] = "N/A"

            self.update_results(json.dumps(data, indent=4))
        except Exception as e:
            self.logger.error(f"Error extracting data for {target}: {e}")
            self.update_results(f"Error extracting data for {target}: {e}")

    def update_results(self, message):
        """Update the results text widget with the given message."""
        self.results_text.config(state=tk.NORMAL)
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, message)
        self.results_text.config(state=tk.DISABLED)

class ProxyManager:
    """Manages a pool of proxies with thread-safe operations."""
    def __init__(self, debug_console=None):
        self.proxies = []
        self.dead_proxies = set()
        self.lock = threading.Lock()
        self.debug_console = debug_console
        self.logger = logging.getLogger("ProxyManager")
    
    def add_proxies(self, proxy_list):
        """Add new proxies to the pool"""
        with self.lock:
            for proxy in proxy_list:
                if proxy not in self.dead_proxies and proxy not in self.proxies:
                    self.proxies.append(proxy)
            self.log(f"Added {len(proxy_list)} proxies. Total: {len(self.proxies)}")
    
    def get_proxy(self):
        """Get a random working proxy"""
        with self.lock:
            if not self.proxies:
                return None
            return random.choice(self.proxies)
    
    def mark_dead(self, proxy):
        """Mark a proxy as dead and remove it from the pool"""
        with self.lock:
            if proxy in self.proxies:
                self.proxies.remove(proxy)
                self.dead_proxies.add(proxy)
                self.log(f"Marked proxy as dead: {proxy}. Remaining: {len(self.proxies)}", Fore.YELLOW)
    
    def log(self, message, color=Fore.WHITE):
        """Log a message to the debug console"""
        self.logger.info(message)
        if self.debug_console:
            self.debug_console.log(message, color)

def main():
    """Main function to start the application."""
    root = tk.Tk()
    app = InstagramManagerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
