# README for Instagram Account Manager

## Overview
The Instagram Account Manager is a Python application designed to automate the management of Instagram accounts. It includes features for creating temporary email addresses, managing proxies, and handling Instagram account operations.

## Project Structure
```
instagram-account-manager
├── src
│   ├── __init__.py
│   ├── managers
│   │   ├── __init__.py
│   │   ├── account_manager.py
│   │   ├── email_manager.py
│   │   └── proxy_manager.py
│   ├── utils
│   │   ├── __init__.py
│   │   ├── logging_handler.py
│   │   ├── config.py
│   │   └── helpers.py
│   ├── drivers
│   │   ├── __init__.py
│   │   └── webdriver.py
│   ├── models
│   │   ├── __init__.py
│   │   └── account.py
│   ├── constants
│   │   ├── __init__.py
│   │   └── urls.py
│   └── main.py
├── tests
│   ├── __init__.py
│   └── test_managers
│       ├── __init__.py
│       ├── test_account_manager.py
│       ├── test_email_manager.py
│       └── test_proxy_manager.py
├── logs
├── requirements.txt
└── README.md
```

## Installation
1. Clone the repository:
   ```
   git clone <repository-url>
   cd instagram-account-manager
   ```

2. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```

## Usage
To run the application, execute the following command:
```
python src/main.py
```

## Features
- **Account Management**: Create and manage multiple Instagram accounts.
- **Email Creation**: Generate temporary email addresses for account verification.
- **Proxy Management**: Load and verify proxies for enhanced privacy and security.

## Logging
Logs are stored in the `logs` directory. You can monitor the log files for detailed information about the application's operations.

## Testing
Unit tests are provided in the `tests` directory. To run the tests, use:
```
pytest
```

## Contributing
Contributions are welcome! Please submit a pull request or open an issue for any enhancements or bug fixes.

## License
This project is licensed under the MIT License. See the LICENSE file for more details.