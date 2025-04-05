import os
import time
import random
import logging
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager

class WebDriverManager:
    def __init__(self, logger=None):
        self.driver = None
        self.logger = logger or logging.getLogger(__name__)

    def setup_driver(self, headless=True, user_agent=None):
        options = Options()
        if headless:
            options.add_argument('--headless=new')
        if user_agent:
            options.add_argument(f'user-agent={user_agent}')
        
        options.add_argument('--no-sandbox')
        options.add_argument('--disable-dev-shm-usage')
        options.add_argument('--disable-gpu')
        options.add_argument('--disable-extensions')
        options.add_argument('--log-level=3')
        options.add_argument('--silent')

        try:
            self.logger.debug("Initializing Chrome driver...")
            service = Service(ChromeDriverManager().install())
            self.driver = webdriver.Chrome(service=service, options=options)
            self.logger.info("WebDriver setup complete.")
            time.sleep(random.uniform(1.5, 4.5))  # Random delay
            return True
        except Exception as e:
            self.logger.error(f"Error initializing WebDriver: {e}")
            return False

    def quit_driver(self):
        if self.driver:
            self.logger.debug("Quitting WebDriver instance.")
            self.driver.quit()
            self.driver = None