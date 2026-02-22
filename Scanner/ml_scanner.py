import sys
import json
import os
import io
import time
import datetime
import re
from contextlib import redirect_stdout, redirect_stderr
from urllib.parse import urlparse

# Add paths for sub-scanners
current_dir = os.path.dirname(os.path.abspath(__file__))
sqli_dir = os.path.join(current_dir, 'sqli')
xss_dir = os.path.join(current_dir, 'xss')
sys.path.append(sqli_dir)
sys.path.append(xss_dir)

try:
    # ---------------------------------------------------------
    # ML SCANNER IMPORTS
    # ---------------------------------------------------------
    # Import sqli_ml_final (consolidated ML scanner)
    import sqli_ml_final
    # Use DetailedMLScanner which enforces MLSQLiDetector
    from sqli_ml_final import DetailedMLScanner as EnhancedSQLiScanner
    
    # Import fixedjss_ml module to access load_model
    import fixedjss_ml
    from fixedjss_ml import scan_xss, SCAN_STATS, test_payload_worker
    # Import login helper from the xss directory package (using name found in path)
    from login_helper import perform_auto_login
    
    # Threading imports
    from concurrent.futures import ThreadPoolExecutor, as_completed
    import threading
    from bs4 import BeautifulSoup as bs
    from urllib.parse import urlparse, parse_qs, urlencode, unquote, urljoin
    import pandas as pd

    
except ImportError as e:
    print("PROCESS_COMPLETE")
    print(json.dumps({"error": f"Import Error (ML): {e}"}))
    sys.exit(1)

# Argument Helper
class ScannerArgs:
    def __init__(self, url):
        self.url = url
        self.output = None
        self.crawl = True
        self.max_links = 40
        self.report = None
        self.cookie = None
        self.username = None
        self.password = None
        self.login_url = None
        self.timeout = 10
        self.obey_robots = False
        self.dataset_mode = False
        self.verbose_ml = False
        self.threshold = 0.1 # Lowered from 0.5 to match successful standalone scans (e.g. 0.48 probability findings)
        self.match_type = 'heuristic' 
        self.threads = 10 # Default to 10 threads 

# --- MONKEY PATCH FUNCTIONS ---

# --- MONKEY PATCH FUNCTIONS ---

def test_form_payload_worker(payload, form_details, url, target_input_name, args, stop_event):
    """
    Worker function to test a single form payload. Called by thread pool.
    """
    if stop_event.is_set():
        return None

    # Submit form (using fixedjss_ml.submit_form)
    response, request_info = fixedjss_ml.submit_form(form_details, url, payload, target_input_name=target_input_name)
    if response is None:
        return None

    req_url = request_info.get("url", "")  # Form action URL
    original_page_url = request_info.get("original_page_url", url)  # Page where form was found
    req_method = request_info.get("method", "GET")
    req_body = request_info.get("body", "")

    try: 
        raw_text = response.content.decode('utf-8', errors='ignore')
        resp_text = unquote(raw_text)
    except: 
        resp_text = str(response.content)

    try: attack_soup = bs(resp_text, "html.parser")
    except: attack_soup = None
    
    # Use fixedjss_ml feature extractor
    features = fixedjss_ml.extract_features_dict(req_url, attack_soup, req_method, req_body)
    is_ml_vuln = False
    vuln_prob = 0.0
    
    if fixedjss_ml.MODEL:
            try:
                df = pd.DataFrame([features]).drop(columns=['label', 'URL', 'Method', 'Body'], errors='ignore')
                df = df[fixedjss_ml.EXPECTED_FEATURES]
                probas = fixedjss_ml.MODEL.predict_proba(df)
                vuln_prob = probas[0][1]
                if vuln_prob >= args.threshold: is_ml_vuln = True
            except Exception:
                pass

    # Heuristic check
    is_heur_vuln = fixedjss_ml.check_vulnerability(payload, resp_text)
    label = 1 if is_heur_vuln else 0
    features['label'] = label
    
    # Stats update
    with fixedjss_ml.stats_lock:
        fixedjss_ml.SCAN_STATS["total_payloads_tested"] += 1
    
    if args.dataset_mode or args.output:
        fixedjss_ml.save_features(req_url, attack_soup, args, req_method, req_body, label=label, features=features)
    
    if is_ml_vuln:
        return {
            'is_vulnerable': True,
            'req_url': req_url,
            'original_page_url': original_page_url,
            'parameter': target_input_name,
            'payload': payload,
            'confidence': vuln_prob
        }
    
    return None

def optimized_scan_xss(start_url, args):
    # Determine the target domain first
    try:
        start_parsed = urlparse(start_url)
        target_domain = start_parsed.netloc
        domain_base = f"{start_parsed.scheme}://{start_parsed.netloc}"
    except Exception:
        print("[-] Invalid Start URL")
        return

    queue = [start_url]
    scanned_urls = set()
    
    while queue:
        url = queue.pop(0)
        
        if url in scanned_urls:
            continue
        scanned_urls.add(url)
        fixedjss_ml.SCAN_STATS["urls_scanned"] += 1
        
        # Scope check
        try:
            parsed = urlparse(url)
            if parsed.netloc != target_domain:
                continue
        except:
            continue

        # 1. Scan Parameters (Already parallelized in fixedjss_ml)
        fixedjss_ml.scan_url_params(url, args)
        
        # 2. Scan Forms
        forms = fixedjss_ml.get_all_forms(url)
        if forms:
            print(f"\\n[+] Detected {len(forms)} forms on {url}")
        
        # Assume crawl_allowed (args.obey_robots is simplified)
        
        for form in forms:
            form_details = fixedjss_ml.get_form_details(form)
            form_inputs = form_details.get("inputs", [])
            
            for input_entry in form_inputs:
                target_input_name = input_entry.get("name")
                input_type = input_entry.get("type", "text").lower()
                
                if not target_input_name:
                    continue
                    
                if input_type not in ["text", "search", "url", "email", "password", "number", "hidden", "textarea"]:
                    continue

                if args.verbose_ml:
                    print(f"    [>] Fuzzing input: {target_input_name} ({input_type})")

                input_vulnerable = False
                stop_event = threading.Event()

                # PARALLEL FORM SCANNING (OPTIMIZATION)
                with ThreadPoolExecutor(max_workers=args.threads) as executor:
                    futures = {
                        executor.submit(test_form_payload_worker, payload, form_details, url, target_input_name, args, stop_event): payload
                        for payload in fixedjss_ml.XSS_PAYLOADS
                    }
                    
                    for future in as_completed(futures):
                        if stop_event.is_set() and not args.dataset_mode:
                            break
                        
                        result = future.result()
                        if result and result['is_vulnerable']:
                            payload = result['payload']
                            vuln_prob = result['confidence']
                            
                            base = result['original_page_url'].split('?')[0].lower()
                            vuln_key = f"{base}:{target_input_name}"
                            
                            if vuln_key not in fixedjss_ml.found_vulnerabilities:
                                fixedjss_ml.found_vulnerabilities.add(vuln_key)
                                print(f"\\n[+] Form XSS Detected (ML Prediction)!")
                                print(f"[*] Page: {result['original_page_url']}")
                                print(f"[*] Form Action: {result['req_url']}")
                                print(f"[*] Parameter: {target_input_name}")
                                print(f"[*] Payload: {payload}")
                                
                                with fixedjss_ml.stats_lock:
                                    fixedjss_ml.SCAN_STATS["findings"].append({
                                        "url": result['req_url'],
                                        "original_page_url": result['original_page_url'],
                                        "parameter": target_input_name,
                                        "payload": payload,
                                        "confidence": float(vuln_prob),
                                        "is_vulnerable": True,
                                        "evidence": ["ML Prediction", "Form-based XSS"],
                                        "timestamp": datetime.datetime.now().isoformat()
                                    })
                                    fixedjss_ml.SCAN_STATS["total_findings"] += 1

                                if args.output:
                                     with open(args.output, "a") as f:
                                        f.write(f"Form XSS: {result['req_url']}\\nPage: {result['original_page_url']}\\nParameter: {target_input_name}\\nPayload: {payload}\\nModel Predicted: True\\n\\n")

                            input_vulnerable = True
                            if not args.dataset_mode: 
                                stop_event.set()
                                break

        # 3. Crawl New Links
        if args.crawl:
            if args.max_links and len(fixedjss_ml.crawled_links) >= args.max_links:
                pass 
            else:
                current_links = fixedjss_ml.get_all_links(url)
                for link in current_links:
                    if link not in scanned_urls and link not in fixedjss_ml.crawled_links:
                        try:
                            l_parsed = urlparse(link)
                            if l_parsed.netloc == target_domain:
                                fixedjss_ml.crawled_links.add(link)
                                queue.append(link)
                                if args.max_links and len(fixedjss_ml.crawled_links) >= args.max_links:
                                    break
                        except: pass

# (Overridden functions removed to match exact behavior of fixedjss_ml.py)


def run_ml_scan(target_url, run_sqli=True, run_xss=True, threads=10):
    # Initialize ML models if needed
    try:
        if hasattr(fixedjss_ml, 'load_model'):
            # fixedjss_ml.load_model() # We load it later or now? fixedjss_ml usually loads at top level.
            # But let's call it to be safe if it's a function.
            pass
    except Exception as e:
        sys.stderr.write(f"[-] Failed to load XSS ML model: {e}\n")

    start_time = time.time()
    scan_start_iso = datetime.datetime.now().isoformat()
    
    results = {
        "target": target_url,
        "vulnerabilities": [],
        "urls_scanned": 0,
        "scan_stats": {},
        "scan_start": scan_start_iso,
        "scanner_type": "ML Scanner"
    }

    # Reconfigure stdout/stderr
    if sys.stdout.encoding.lower() != 'utf-8':
        try:
            sys.stdout.reconfigure(encoding='utf-8')
            sys.stderr.reconfigure(encoding='utf-8')
        except AttributeError:
            pass 

    # --- 1. Run ML SQLi Scanner ---
    sqli_summary = None
    if run_sqli:
        try:
            with redirect_stdout(sys.stderr): 
                print(f"[*] Starting ML SQLi Scan on {target_url}...", file=sys.stderr)
                scanner = EnhancedSQLiScanner(
                    target_url=target_url,
                    crawl=True,
                    max_depth=3,
                    threads=8,
                )
                sqli_summary = scanner.scan()
        except Exception as e:
            sys.stderr.write(f"[-] ML SQLi Scanner Error: {e}\n")

    # --- 2. Run ML XSS Scanner ---
    if run_xss:
        try:
            # Reset findings
            if "findings" in SCAN_STATS:
                SCAN_STATS["findings"] = []
                SCAN_STATS["total_findings"] = 0
                SCAN_STATS["urls_scanned"] = 0
                
            # Reset globals in fixedjss_ml if accessible
            if hasattr(fixedjss_ml, 'crawled_links'):
                fixedjss_ml.crawled_links = set()
            if hasattr(fixedjss_ml, 'found_vulnerabilities'):
                fixedjss_ml.found_vulnerabilities = set()
                
            xss_args = ScannerArgs(target_url)
            xss_args.threads = threads # Pass threads to arguments
            # Match standalone success (limit=40 prevents infinite loops on RetURL traps)
            xss_args.max_links = 40
            xss_args.dataset_mode = False # Disable dataset mode to stop early (Performance Fix)
            
            # RESET SESSION STATE to ensure clean scan (fix for missing links)
            # This was the crucial fix added before parallelization
            if hasattr(fixedjss_ml, 'session') and hasattr(fixedjss_ml, 'requests'):
                # Re-initialize session to clear any state from SQLi scan or previous runs
                fixedjss_ml.session = fixedjss_ml.requests.Session()
                fixedjss_ml.session.headers.update({
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36"
                })
                # Restore default cookies from fixedjss_ml
                fixedjss_ml.session.cookies.set("PHPSESSID", "1ga0osdggsuernnadkek5bmp20")
                fixedjss_ml.session.cookies.set("security_level", "0")
                fixedjss_ml.session.cookies.set("security_level", "0")
                print(f"[*] Reset XSS Session for {target_url}", file=sys.stderr)

            # --- MONKEY PATCH: Filter Logout links to prevent infinite loops ---
            # (Removed to match exact behavior of fixedjss_ml.py)
            # -----------------------------------------------------------------
                
            # Initialize XSS Model (ensure it's loaded)
            if hasattr(fixedjss_ml, 'load_model'):
                fixedjss_ml.load_model()
                
            # --- MONKEY PATCHING ---
            print(f"[*] Applying Runtime Performance Patch to fixedjss_ml...", file=sys.stderr)
            # Monkey patch scan_xss to use the optimized parallel version
            fixedjss_ml.scan_xss = optimized_scan_xss

            # -----------------------
            
            if "testasp.vulnweb.com" in target_url:
                xss_args.username = "admin"
                xss_args.password = "none"
                xss_args.login_url = "http://testasp.vulnweb.com/Login.asp"
            elif "testphp.vulnweb.com" in target_url:
                xss_args.username = "test"
                xss_args.password = "test"
                xss_args.login_url = "http://testphp.vulnweb.com/login.php"
                
            # Perform Login if credentials exist
            if xss_args.username and xss_args.password:
                try:
                    l_url = xss_args.login_url if xss_args.login_url else target_url
                    print(f"[*] Attempting XSS Scanner Auto-Login to {l_url}...", file=sys.stderr)
                    perform_auto_login(fixedjss_ml.session, l_url, xss_args.username, xss_args.password)
                except Exception as e:
                    sys.stderr.write(f"[-] Auto-Login Failed: {e}\n")

            with redirect_stdout(sys.stderr):
                print(f"[*] Starting ML XSS Scan on {target_url}...", file=sys.stderr)
                # Call the patched function explicitly
                fixedjss_ml.scan_xss(target_url, xss_args)
                
        except Exception as e:
            sys.stderr.write(f"[-] ML XSS Scanner Error: {e}\n")


    # --- 3. Merge Results (Identical logic to mainscanner.py) ---
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
        else:
            entry = vuln_map[key]
            # Keep highest confidence/risk
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

    # SQLi Mapping
    if sqli_summary:
        for finding in sqli_summary.findings:
            if not finding.is_vulnerable: continue
            
            # --- SQLi Fix: Robust Deduplication & Exploit Links ---
            
            # 1. Deduplication Key: Use Clean Base URL (no query) + Parameter
            # This handles cases where original_base_url might differ (e.g. ?id=1 vs ?id=2)
            # but represents the same vulnerability.
            raw_url = getattr(finding, 'original_base_url', finding.url)
            try:
                parsed = urlparse(raw_url)
                clean_base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            except:
                clean_base = raw_url.split('?')[0] # Fallback
                
            v_type = "SQL Injection"
            
            # Key: Base URL | Parameter | Type
            key = f"{clean_base}|{finding.parameter}|{v_type}"
            
            # 2. Display URL: Use the Exploit Link (with payload)
            exploit_url = finding.url
            if not exploit_url: exploit_url = raw_url
            
            evidence_list = finding.evidence if hasattr(finding, 'evidence') else []
            
            add_finding(
                key=key,
                type_str=v_type,
                url=exploit_url, # Show the exploit link
                param=finding.parameter,
                payload=finding.payload,
                confidence=int(finding.confidence * 100) if hasattr(finding, 'confidence') else 0,  
                evidence=evidence_list
            )

    # XSS Mapping
    if SCAN_STATS and "findings" in SCAN_STATS:
        for finding in SCAN_STATS["findings"]:
            f_url = finding.get("url", "")
            f_param = finding.get("parameter", "")
            f_payload = finding.get("payload", "")
            f_confidence = finding.get("confidence", 1.0)
            
            v_type = "Cross-Site Scripting (XSS)"
            
            # Only strip params if we have an original page (Form XSS logic not fully split here, but usually Reflected)
            # ML Scanner mostly outputs Reflected unless it has form metadata.
            # Actually, ML scanner results come from 'scan_xss' in fixedjss_ml/fixedjss which distinguishes.
            # But here we only have 'url' in finding dict from SCAN_STATS.
            # Scan stats for reflected has full url.
            
            # Check if it looks like a form vuln (has original_page_url in metadata)
            original_page = finding.get("original_page_url")
            
            if original_page:
                # FORM XSS: Use the page where the form was found
                clean_url = original_page
            else:
                # REFLECTED XSS: Use the full fuzzed URL
                clean_url = f_url

            key = f"{clean_url}|{f_param}|{v_type}"
            


            add_finding(
                key=key,
                type_str=v_type,
                url=clean_url,
                param=f_param,
                payload=f_payload,
                confidence=int(f_confidence * 100),
                risk="HIGH" if f_confidence >= 0.9 else "MEDIUM" if f_confidence >= 0.5 else "LOW",
                evidence=finding.get("evidence", [])
            )

    # Final List with Filtering
    for entry in vuln_map.values():
        # Filter out Default.asp ONLY for XSS (as originally requested to fix XSS FP)
        # SQLi might legitimately be on Default.asp (e.g. search)
        if "default.asp" in entry["url"].lower() and "xss" in entry["type"].lower():
             continue
             
        # payload_types removed as requested
        results["vulnerabilities"].append(entry)

    return results

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("PROCESS_COMPLETE")
        print(json.dumps({"error": "No URL provided"}))
        sys.exit(1)

    target_url = sys.argv[1]
    
    # Flags parsing
    run_sqli = True
    run_xss = True
    
    # New Flag Schema
    if "--ml-xss-only" in sys.argv:
        run_sqli = False
        run_xss = True
    elif "--ml-sqli-only" in sys.argv:
        run_sqli = True
        run_xss = False
    elif "--ml" in sys.argv:
        # Explicit full scan, defaults are already True but good to handle
        run_sqli = True
        run_xss = True
        
    # Maintain backward compatibility if needed, or just switch? 
    # User's server.js only sends new flags. We can drop old ones to be clean.
        
    args_threads = 10
    if "--threads" in sys.argv:
        try:
            t_idx = sys.argv.index("--threads")
            if t_idx + 1 < len(sys.argv):
                args_threads = int(sys.argv[t_idx + 1])
        except: pass

    final_report = run_ml_scan(target_url, run_sqli=run_sqli, run_xss=run_xss, threads=args_threads)
    
    print("PROCESS_COMPLETE")
    print(json.dumps(final_report))
