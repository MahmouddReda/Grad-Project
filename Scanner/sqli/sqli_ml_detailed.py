"""
Enhanced ML SQLi Scanner with Detailed Vulnerability Reporting
Shows: 1) Vulnerable URL, 2) Successful payloads, 3) ML reasoning
"""

import sys
from sqli_ML import MLSQLiDetector
from sqli_js import EnhancedSQLiScanner, VulnerabilityLevel
import argparse
from collections import defaultdict

class DetailedMLScanner(EnhancedSQLiScanner):
    """Extended scanner that provides detailed vulnerability reports"""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.detailed_vulns = defaultdict(list)
    
    def print_detailed_vulnerability_report(self):
        """Print comprehensive vulnerability report with ML reasoning"""
        print("\n" + "="*80)
        print("DETAILED VULNERABILITY REPORT")
        print("="*80)
        
        if not self.detailed_vulns:
            print("\n[+] No vulnerabilities detected with current thresholds")
            print("    (Strict ML threshold: 99% confidence required)")
            return
        
        for idx, (url, detections) in enumerate(self.detailed_vulns.items(), 1):
            print(f"\n[{idx}] VULNERABLE URL:")
            print(f"    {url}")
            print(f"\n    SUCCESSFUL PAYLOADS ({len(detections)}):")
            
            for det_idx, detection in enumerate(detections, 1):
                result = detection['result']
                payload = detection['payload']
                param = detection['param']
                
                print(f"\n    [{det_idx}] Parameter: {param}")
                print(f"        Payload: {payload[:100]}{'...' if len(payload) > 100 else ''}")
                print(f"\n        ML ANALYSIS:")
                print(f"        • Confidence: {result.ml_confidence:.4f} ({result.ml_confidence*100:.2f}%)")
                print(f"        • Prediction: {'VULNERABLE' if result.ml_prediction == 1 else 'SAFE'}")
                print(f"        • Vulnerability Level: {result.level.name}")
                
                print(f"\n        DETECTION REASONING:")
                for evidence in result.evidence:
                    print(f"        • {evidence}")
                
                # Show key features that triggered detection
                print(f"\n        KEY FEATURES:")
                if hasattr(result, 'response_features'):
                    rf = result.response_features
                    if rf.get('has_sql_error_keywords'):
                        print(f"        ✓ SQL error keywords present")
                    if rf.get('response_contains_credentials'):
                        print(f"        ✓ Credentials leaked in response")
                    if rf.get('has_database_keywords'):
                        print(f"        ✓ Database keywords detected")
                    if rf.get('is_slow_response'):
                        print(f"        ✓ Slow response ({result.response_time:.2f}s)")
                    if rf.get('response_length') > 2000:
                        print(f"        ✓ Large response ({rf.get('response_length')} bytes)")
                
                if hasattr(result, 'payload_features'):
                    pf = result.payload_features
                    payload_types = []
                    if pf.get('has_union'):
                        payload_types.append("UNION-based")
                    if pf.get('has_or_logic'):
                        payload_types.append("OR tautology")
                    if pf.get('has_sleep'):
                        payload_types.append("Time-based")
                    if pf.get('has_select'):
                        payload_types.append("SELECT query")
                    if payload_types:
                        print(f"        ✓ Payload type: {', '.join(payload_types)}")
                
                print(f"        • Response length: {result.response_length} bytes")
                print(f"        • Response time: {result.response_time:.3f}s")
        
        print("\n" + "="*80)
        print(f"SUMMARY: {len(self.detailed_vulns)} vulnerable URLs found")
        print("="*80 + "\n")
    
    def test_parameter(self, url, param, payload):
        """Override to capture detailed detection info"""
        try:
            result = super().test_parameter(url, param, payload)
            
            # If vulnerability detected, store detailed info
            if result and hasattr(result, 'is_vulnerable') and result.is_vulnerable:
                self.detailed_vulns[url].append({
                    'param': param.name if hasattr(param, 'name') else str(param),
                    'payload': payload.value if hasattr(payload, 'value') else str(payload),
                    'result': result,
                    'method': param.method if hasattr(param, 'method') else 'GET'
                })
            
            return result
        except Exception as e:
            print(f"[!] Error in test_parameter: {e}")
            # Return dummy finding to prevent crash
            class DummyFinding:
                def __init__(self):
                    self.confidence = 0.0
                    self.is_vulnerable = False
                    self.level = VulnerabilityLevel.NOT_VULNERABLE
                    self.evidence = []
                    self.risk_level = "safe"
            return DummyFinding()



def main():
    parser = argparse.ArgumentParser(
        description='ML-Powered SQLi Scanner with Detailed Reporting',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python sqli_ml_detailed.py -u http://testphp.vulnweb.com --crawl --depth 2
  python sqli_ml_detailed.py -u http://example.com/page.php?id=1
  python sqli_ml_detailed.py -u http://example.com --crawl --csv results.csv
        """
    )
    
    parser.add_argument('-u', '--url', required=True, help='Target URL')
    parser.add_argument('--crawl', action='store_true', help='Enable crawling')
    parser.add_argument('--depth', type=int, default=2, help='Crawl depth (default: 2)')
    parser.add_argument('--csv', help='Save results to CSV file')
    parser.add_argument('--html', help='Save results to HTML report')
    parser.add_argument('--text', help='Save results to Text report')
    parser.add_argument('--threads', type=int, default=5, help='Number of threads (default: 5)')
    
    args = parser.parse_args()
    
    print("="*80)
    print("ML-POWERED SQLI SCANNER - DETAILED REPORTING MODE")
    print("="*80)
    print(f"\nTarget: {args.url}")
    print(f"Crawling: {'Enabled' if args.crawl else 'Disabled'}")
    if args.crawl:
        print(f"Depth: {args.depth}")
    print(f"\nML Thresholds:")
    print(f"  • Pure ML detection: 99% confidence required")
    print(f"  • With SQL errors/credentials: 80% confidence required")
    print("\n" + "="*80 + "\n")
    
    # Create scanner
    from pathlib import Path
    scanner = DetailedMLScanner(
        target_url=args.url,
        crawl=args.crawl,
        max_depth=args.depth,
        threads=args.threads,
        csv_output=Path(args.csv) if args.csv else None,
        html_output=Path(args.html) if args.html else None,
        text_output=Path(args.text) if args.text else None
    )
    
    # Run scan
    try:
        summary = scanner.scan()
        
        # Print detailed report
        scanner.print_detailed_vulnerability_report()
        
        # Save to CSV if requested
        if args.csv:
            print(f"\n[+] Results saved to: {args.csv}")
            
        # Save to HTML if requested (handled by base class scan() but we verify here)
        if args.html and Path(args.html).exists():
             print(f"\n[+] HTML report saved to: {args.html}")
        elif args.html:
             print(f"\n[!] Warning: HTML report generation failed. Check for errors above.")
    
    except KeyboardInterrupt:
        print("\n\n[!] Scan interrupted by user")
        scanner.print_detailed_vulnerability_report()
    except Exception as e:
        print(f"\n[!] Error during scan: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
