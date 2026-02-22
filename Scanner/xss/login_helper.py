import requests
from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin

def perform_auto_login(session, login_url, username, password):
    """
    Attempts to automatically log in to the provided URL using the provided session.
    """
    print(f"[+] Attempting auto-login at {login_url}...")
    try:
        r = session.get(login_url, timeout=10)
        soup = bs(r.content, "html.parser")
        forms = soup.find_all("form")
        
        target_form = None
        user_field = None
        pass_field = None

        # Heuristic: Find the form with a password input
        for f in forms:
            inputs = f.find_all("input")
            for i in inputs:
                if i.get("type") == "password" or "pass" in str(i.get("name", "")).lower():
                    target_form = f
                    pass_field = i.get("name")
                    break
            if target_form:
                # Find the username field (usually text/email before the password)
                for i in inputs:
                    name = str(i.get("name", "")).lower()
                    i_type = i.get("type", "text")
                    if i_type in ["text", "email"] and name != pass_field:
                         # Prioritize common names
                         if any(x in name for x in ["user", "name", "login", "mail", "id"]):
                             user_field = i.get("name")
                             break
                # Fallback: just take the first text field if no keyword match
                if not user_field:
                    for i in inputs:
                        if i.get("type", "text") in ["text", "email"] and i.get("name") != pass_field:
                            user_field = i.get("name")
                            break
                break
        
        if not target_form or not user_field or not pass_field:
            print("[-] Could not detect login fields automatically. Please use --cookie instead.")
            return False

        print(f"    [>] Found Login Form. User Field: '{user_field}', Pass Field: '{pass_field}'")
        
        # Prepare Data
        action = target_form.get("action")
        method = target_form.get("method", "get").lower()
        post_url = urljoin(login_url, action) if action else login_url
        
        data = {}
        # Fill all inputs with defaults
        for i in target_form.find_all("input"):
            name = i.get("name")
            if not name: continue
            if name == user_field:
                data[name] = username
            elif name == pass_field:
                data[name] = password
            else:
                data[name] = i.get("value", "") # Hidden fields etc
        
        # Submit
        print(f"    [>] Submitting payload to {post_url}...")
        if method == "post":
            resp = session.post(post_url, data=data, allow_redirects=True, timeout=10)
        else:
            resp = session.get(post_url, params=data, allow_redirects=True, timeout=10)
            
        # Check Success
        if resp.ok and len(session.cookies) > 0:
            print(f"[+] Login Successful! Captured {len(session.cookies)} session cookies.")
            curr_cookies = "; ".join([f"{c.name}={c.value}" for c in session.cookies])
            print(f"    [>] Cookies: {curr_cookies[:50]}...")
            return True
        else:
            print("[-] Login failed (No cookies received or error status).")
            return False

    except Exception as e:
        print(f"[-] Auto-login error: {e}")
        return False
