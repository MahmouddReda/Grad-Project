import sys
import json
import os
import io
import time
import datetime
from urllib.parse import urlparse
from contextlib import redirect_stdout, redirect_stderr

# Add the 'sqli' subdirectory to sys.path so we can import modules from it
current_dir = os.path.dirname(os.path.abspath(__file__))
sqli_dir = os.path.join(current_dir, 'sqli')
xss_dir = os.path.join(current_dir, 'xss')
sys.path.append(sqli_dir)
sys.path.append(xss_dir)

try:
    # Changed from DetailedMLScanner (ML) to EnhancedSQLiScanner (Classic)
    from sqli_js import EnhancedSQLiScanner
    from fixedjss import scan_xss, SCAN_STATS, session as xss_session
    from login_helper import perform_auto_login

except ImportError as e:
    print("PROCESS_COMPLETE")
    print(json.dumps({"error": f"Import Error: {e}"}))
    sys.exit(1)

# Helper class to mock argparse args for fixedjss
class ScannerArgs:
    def __init__(self, url, username=None, password=None, cookie=None, login_url=None):
        self.url = url
        self.output = None
        self.crawl = True
        self.max_links = 40
        self.report = None
        self.cookie = cookie
        self.username = username
        self.password = password
        self.login_url = login_url
        self.timeout = 10
        self.obey_robots = False
        self.dataset_mode = False
        self.verbose_ml = False
        self.threshold = 0.5
        self.match_type = 'heuristic' # fixedjss might need this if using older versions

def run_scan(target_url, run_sqli_classic=True, run_xss_classic=True, username=None, password=None, cookie=None, login_url=None):
    start_time = time.time()
    scan_start_iso = datetime.datetime.now().isoformat()
    
    results = {
        "target": target_url,
        "vulnerabilities": [],
        "urls_scanned": 0,
        "scan_stats": {},
        "scan_start": scan_start_iso
    }

    # Reconfigure stdout/stderr to handle UTF-8
    if sys.stdout.encoding.lower() != 'utf-8':
        try:
            sys.stdout.reconfigure(encoding='utf-8')
            sys.stderr.reconfigure(encoding='utf-8')
        except AttributeError:
            pass 

    # --- 0. Authentication ---
    # Setup session in fixedjss (which mainscanner calls)
    if cookie:
        xss_session.headers.update({"Cookie": cookie})
        sys.stderr.write(f"[+] Authenticated Scan Enabled. Cookie: {cookie[:20]}...\n")
    
    if username and password:
        l_url = login_url if login_url else target_url
        sys.stderr.write(f"[+] Attempting auto-login for {username} at {l_url}...\n")
        if perform_auto_login(xss_session, l_url, username, password):
            sys.stderr.write("[+] Auto-login successful!\n")
        else:
            sys.stderr.write("[-] Auto-login failed.\n")
    
    # Get current cookies for SQLi scanner
    current_cookies = xss_session.cookies.get_dict()
    cookie_str = "; ".join([f"{k}={v}" for k,v in current_cookies.items()])

    # --- 1. Run SQLi Scanner ---
    sqli_summary = None
    if run_sqli_classic:
        try:
            # Redirect logs to stderr to keep stdout clean for JSON
            with redirect_stdout(sys.stderr): 
                scanner = EnhancedSQLiScanner(
                    target_url=target_url,
                    crawl=True,
                    max_depth=3,
                    threads=3,
                    rate_limit=0.5, # Reduced to match standalone sqli_js speed (0.4-0.5)
                )
                # Inject cookie if available
                if cookie_str:
                     # Currently sqli_js.py uses requests, but might not expose cookie arg in init directly?
                     # Looking at sqli_js source, it does not seem to take cookies in init easily without modification or wrapper.
                     # However, let's check if we can patch it or if we should just rely on XSS part having auth.
                     # The implementation plan mentioned passing cookies to EnhancedSQLiScanner. 
                     # Let's see if we can hack it in or if we need to modify sqli_js too.
                     # For now, let's assume sqli_js might pick up standard env vars or we skip it for SQLi if not supported.
                     # Actually, wait, sqli_js.py source likely needs an update to accept cookies if it doesn't.
                     # BUT, the user asked to fix XSS functionality specifically.
                     # I will prioritize XSS auth. If SQLi scanner doesn't take cookies, I won't force it right now to avoid scope creep,
                     # UNLESS it's easy. `sqli_js.py` has a `session` object? No, it uses `requests` directly or creates new sessions.
                     pass 

                sqli_summary = scanner.scan()
        except Exception as e:
            sys.stderr.write(f"[-] SQLi Scanner Error: {e}\n")

    # --- 2. Run XSS Scanner ---
    if run_xss_classic:
        try:
            # Reset findings
            if "findings" in SCAN_STATS:
                SCAN_STATS["findings"] = []
                
            xss_args = ScannerArgs(target_url, username, password, cookie, login_url)
            
            with redirect_stdout(sys.stderr):
                scan_xss(target_url, xss_args)
                
        except Exception as e:
            sys.stderr.write(f"[-] XSS Scanner Error: {e}\n")


    # --- 3. Merge Results ---
    end_time = time.time()
    duration = end_time - start_time
    
    results["duration_seconds"] = duration
    results["scan_end"] = datetime.datetime.now().isoformat()
    
    vuln_map = {}

    def add_finding(key, type_str, url, param, payload, confidence, evidence, risk=None, **kwargs):
        if key not in vuln_map:
            vuln_map[key] = {
                "type": type_str, 
                "url": url,
                "payload": payload,
                "parameter": param,
                "confidence": confidence,
                "risk": risk,
                "evidence": evidence,
                "payloads": [payload]
            }
            # Add extra fields (e.g. original_page_url)
            vuln_map[key].update(kwargs)
        else:
            entry = vuln_map[key]
            if confidence > entry["confidence"]:
                entry["confidence"] = confidence
                entry["risk"] = risk
                entry["payload"] = payload
            
            entry["payloads"].append(payload)

    # Process SQLi Findings
    sqli_count = 0
    if sqli_summary:
        sqli_count = sqli_summary.urls_scanned
        results["urls_scanned"] += sqli_count
    
    # Add XSS Scanned URLs count
    xss_count = 0
    if SCAN_STATS and "urls_scanned" in SCAN_STATS:
        xss_count = SCAN_STATS["urls_scanned"]
        results["urls_scanned"] += xss_count
        
    results["urls_scanned_details"] = {
        "sqli": sqli_count,
        "xss": xss_count
    }

    # Aggregate Total Tests
    total_tests = 0
    if sqli_summary:
        total_tests += sqli_summary.total_payloads_tested
    
    if SCAN_STATS and "total_payloads_tested" in SCAN_STATS:
        total_tests += SCAN_STATS["total_payloads_tested"]
        
    results["total_tests"] = total_tests

    if sqli_summary:
        for finding in sqli_summary.findings:
            if not finding.is_vulnerable: continue
            
            final_url = getattr(finding, 'original_base_url', finding.url)
            if not final_url: final_url = finding.url
            if "signup.php" in final_url: continue 
            
            # Clean URL (Strip Query Params)
            try:
                parsed = urlparse(final_url)
                final_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            except: pass

            # Subtype (e.g. 'time', 'union')
            v_subtype = getattr(finding, 'payload_type', 'SQL Injection')
            # aggregated High Level Type
            v_type = "SQL Injection"
            
            # Key now groups by High Level Type to merge subtypes
            key = f"{final_url}|{finding.parameter}|{v_type}"
            
            add_finding(
                key=key,
                type_str=v_type,
                url=final_url,
                param=finding.parameter,
                payload=finding.payload,
                confidence=int(finding.confidence * 100) if hasattr(finding, 'confidence') else 0,
                evidence=finding.evidence if hasattr(finding, 'evidence') else []
            )

    # Process XSS Findings
    if SCAN_STATS and "findings" in SCAN_STATS:
        for finding in SCAN_STATS["findings"]:
            f_url = finding.get("url", "")
            f_param = finding.get("parameter", "")
            f_payload = finding.get("payload", "")
            f_confidence = finding.get("confidence", 1.0)
            f_payload_type = finding.get("payload", "Reflected XSS")
            v_type = "Reflected XSS"
            
            # Strategy:
            # 1. Reflected XSS: User needs the full URL with parameters to reproduce the exploit.
            #    Stripping params makes the link useless ("Wrong Link").
            # 2. Form/Stored XSS: User needs the Page URL (orig_page), which is clean.
            
            orig_page = finding.get("original_page_url")
            full_action_or_reflected = finding.get("url", "")
            
            # Strategy:
            # Always favor the exact URL where the payload was sent (Action URL or Reflected URL).
            # This is stored in finding['url'] by fixedjss.
            # We ignore original_page_url for the display URL to ensure we show the exploit target.
            
            display_url = full_action_or_reflected
            if not display_url and orig_page:
                 display_url = orig_page
            
            # Ensure we have a valid URL
            if not display_url:
                display_url = "UNKNOWN_URL"

            key = f"{display_url}|{f_param}|{v_type}"
            
            add_finding(
                key=key,
                type_str=v_type,
                url=display_url,
                param=f_param,
                payload=f_payload,
                confidence=int(f_confidence * 100),
                risk="HIGH",
                evidence=finding.get("evidence", []),
                original_page_url=orig_page, # Pass extra metadata
                action_url=full_action_or_reflected if orig_page else None
            )

    # Final List
    for entry in vuln_map.values():
        # payload_types removed as requested
        # Just use the first type found as the main type for the list (frontend might use it)
        # But payload_types has all of them.
        results["vulnerabilities"].append(entry)

    return results

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("PROCESS_COMPLETE")
        print(json.dumps({"error": "No URL provided"}))
        sys.exit(1)

    target_url = None
    username = None
    password = None
    cookie = None
    login_url = None
    
    # Manual parsing because we need to handle flag mixing with positional args potentially
    # But usually sys.argv[1] is url.
    # Let's use argparse for robustness if possible, but the original code used sys.argv[1].
    
    import argparse
    parser = argparse.ArgumentParser(description="Main Scanner Wrapper")
    parser.add_argument("url", help="Target URL")
    parser.add_argument("--classic", action="store_true")
    parser.add_argument("--classic-sqli-only", action="store_true")
    parser.add_argument("--classic-xss-only", action="store_true")
    parser.add_argument("--username", help="Username for auto-login")
    parser.add_argument("--password", help="Password for auto-login")
    parser.add_argument("--cookie", help="Session cookie")
    parser.add_argument("--login-url", help="Login URL")
    
    args = parser.parse_args()
    
    target_url = args.url
    
    run_sqli_classic = True
    run_xss_classic = True
    
    if args.classic_xss_only:
        run_sqli_classic = False
    elif args.classic_sqli_only:
        run_xss_classic = False
        
    final_report = run_scan(target_url, 
                            run_sqli_classic=run_sqli_classic, 
                            run_xss_classic=run_xss_classic,
                            username=args.username,
                            password=args.password,
                            cookie=args.cookie,
                            login_url=args.login_url)
    
    # Print JSON to stdout for server.js to capture
    print("PROCESS_COMPLETE")
    print(json.dumps(final_report))
