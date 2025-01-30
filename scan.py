import requests
from bs4 import BeautifulSoup
import sys
from urllib.parse import urljoin
import urllib3

# Suppress InsecureRequestWarning (SSL verification warnings)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Create a session to handle requests
s = requests.Session()
s.headers["User-Agent"] = "Mozilla/5.0(Windows NT 10.0; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36"

# Function to get all forms from the page
def get_forms(url):
    try:
        soup = BeautifulSoup(s.get(url, verify=False).content, "html.parser")  # Disabling SSL verification temporarily
        return soup.find_all("form")
    except requests.exceptions.RequestException as e:
        print(f"Error while requesting {url}: {e}")
        return []

# Function to extract form details like action, method, and inputs
def form_details(form):
    detailsOfForm = {}
    action = form.attrs.get("action")
    method = form.attrs.get("method", "get")
    inputs = []

    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        input_value = input_tag.attrs.get("value", "")
        inputs.append({
            "type": input_type,
            "name": input_name,
            "value": input_value,
        })

    detailsOfForm['action'] = action
    detailsOfForm['method'] = method
    detailsOfForm['inputs'] = inputs
    return detailsOfForm

# Check if the response content contains SQL errors
def vulnerable(response):
    errors = {
        "quoted string not properly terminated",
        "unclosed quotation mark after the character string",
        "you have an error in your SQL syntax"
    }
    for error in errors:
        if error in response.content.decode().lower():
            return True
    return False

# Main function to scan for SQL injection vulnerabilities
def sql_injection_scan(url):
    forms = get_forms(url)
    print(f"[+] Detected {len(forms)} forms on {url}.")

    for form in forms:
        details = form_details(form)

        # Iterate through each quote and apostrophe to simulate a SQL injection attempt
        for i in "\"'":
            data = {}
            for input_tag in details["inputs"]:
                if input_tag["type"] == "hidden" or input_tag["value"]:
                    data[input_tag['name']] = input_tag["value"]
                elif input_tag["type"] != "submit":
                    data[input_tag['name']] = f"test{i}"

            # Initialize res as None in case no request is made
            res = None
            
            # Send the test data to the form only if the method is valid
            if details["method"] == "post":
                res = s.post(url, data=data, verify=False)  # Disable SSL verification
            elif details["method"] == "get":
                res = s.get(url, params=data, verify=False)  # Disable SSL verification

            # Make sure res is not None before checking for vulnerabilities
            if res and vulnerable(res):
                print(f"[!] SQL Injection vulnerability detected in form at: {url}")
                break  # Stop after detecting an attack in this form

        # If no vulnerability was found, continue checking the other forms
        if res is None or not vulnerable(res):
            print(f"[+] No SQL injection vulnerability detected in form: {url}")

if __name__ == "__main__":
    # The URL you want to check for vulnerabilities
    urlToBeChecked = "https://" # enter address
    sql_injection_scan(urlToBeChecked)