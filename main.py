import httpx
import random
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qsl, urlunparse, urlencode
from collections import deque
import json
from difflib import SequenceMatcher

BASE_URL = 'http://localhost:8080'
SKIP_ACTIONS = ["logout.php", "login.php", "security", "setup", "csrf"]
SKIP_URLS = ["logout.php", "security", "setup", "csrf"] # Only for crawler

BOOLEAN_TRUE_PAYLOAD = "1' OR '1'='1"
BOOLEAN_FALSE_PAYLOAD = "1' AND '1'='2"

ERROR_PAYLOADS = [
    "'",
    "\"",
    "')",
    "' OR '1'='1",
    "1' OR '1'='1",
]

ERROR_SIGNATURES = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
]

def similarity(a: str, b: str) -> float:
    return SequenceMatcher(None, a, b).ratio()

def login(client: httpx.Client, username: str, password: str) -> tuple[bool, list[dict]]:
    login_url = f"{BASE_URL}/login.php"

    resp = client.get(login_url)
    links = extract_links(resp.text, login_url, BASE_URL)
    forms = extract_forms(resp.text, login_url)
    headers = check_headers(resp)
    cookies = check_cookies(resp)

    # Ugly but works, might fix later
    login_results = {
            'url': login_url,
            'status': resp.status_code,
            'forms': forms,
            'links_found': links,
            'headers': headers,
            'cookies': cookies
    }

    soup = BeautifulSoup(resp.text, "html.parser")

    token_input = soup.find("input", {"name": "user_token"})
    user_token = token_input.get("value")

    payload = {
        'username': username, 
        'password': password, 
        'user_token': user_token,
        'Login': 'Login'}

    login_resp = client.post(login_url, data=payload)

    print(login_resp)

    if login_resp.status_code == 302:
        print("im in")
        return True, login_results
    else:
        print("sad")
        return False, login_results

def set_security_level(client: httpx.Client, level: str = "low") -> bool:
    security_url = f"{BASE_URL}/security.php"

    resp = client.get(security_url)
    soup = BeautifulSoup(resp.text, "html.parser")

    token_input = soup.find("input", {"name" : "user_token"})
    user_token = token_input.get("value")

    payload = {
        "security": level,
        "seclev_submit": "Submit",
        "user_token": user_token
    }

    set_resp = client.post(security_url, data=payload)

    return set_resp.status_code == 302

def fetch_page(client: httpx.Client, url: str, timeout: float = 10.0) -> httpx.Response | None:
    try: 
        resp = client.get(url, timeout=timeout)

        if resp.status_code != 200:
            print(f"Non-200: {resp.status_code} for {resp.url}")

        return resp
    
    except httpx.RequestError as e:
        print(e)
        return None

def extract_links(html: str, current_url: str, base_url: str) -> list[str]:
    soup = BeautifulSoup(html, "html.parser")

    hrefs = [a.get('href') for a in soup.find_all('a')]

    found = []
    for href in hrefs:
        if href is None or href.startswith(("#", "javascript:", "mailto:", "tel:")):
            continue

        new_url = urljoin(current_url, href)
        parsed = urlparse(new_url)

        if parsed.netloc != urlparse(base_url).netloc:
            continue

        if new_url not in found:
            found.append(new_url)

    return found

def extract_forms(html: str, current_url: str) -> list[dict]:
    soup = BeautifulSoup(html, "html.parser")

    results = []
    for form in soup.find_all('form'):
        action = form.get('action')

        if not action:
            action = current_url

        action = urljoin(current_url, action)

        method = form.get('method', 'get').upper()

        inputs = []

        for tag in form.find_all(['input', 'select', 'textarea']):
            name = tag.get('name')

            if not name:
                continue

            input_type = tag.get("type", "text")
            value = tag.get("value", "") # Capture the current value, defaults to empty string

            inputs.append({
                "name": name,
                "type": input_type,
                "value": value
            })

        results.append({
            "action": action,
            "method": method,
            "inputs": inputs
        })

    return results
    
def normalize_url(url: str) -> str:
    parsed = urlparse(url)

    # <scheme>://<netloc>/<path>;<params>?<query>#<fragment>
    sorted_query = urlencode(sorted(parse_qsl(parsed.query)))

    # drop fragment, rebuild without it
    normalized = urlunparse((
        parsed.scheme,
        parsed.netloc,
        parsed.path.rstrip("/"),
        parsed.params,
        sorted_query,
        "" #Drop fragment
    ))
    return normalized

def save_results(pages: list[dict], filepath: str):
    with open(filepath, "w") as f:
        json.dump(pages, f, indent=2)

def _finding(issue: str, severity: str) -> dict:
    return {"issue": issue, "severity": severity}

def check_headers(response: httpx.Response) -> list[dict]:
    results = []
    headers = response.headers

    if "content-security-policy" not in headers:
        results.append(_finding(
            "Missing Content-Security-Policy header (XSS/injection risk)", "medium"
        ))

    if "x-frame-options" not in headers:
        results.append(_finding(
            "Missing X-Frame-Options header (clickjacking risk)", "medium"
        ))

    xcto = headers.get("x-content-type-options", "").lower()
    if xcto != "nosniff":
        results.append(_finding(
            "X-Content-Type-Options missing or not 'nosniff' (MIME-sniffing risk)", "low"
        ))

    if response.url.scheme == "https" and "strict-transport-security" not in headers:
        results.append(_finding(
            "Missing Strict-Transport-Security header on HTTPS response", "high"
        ))

    for leaky_header in ("server", "x-powered-by"):
        if leaky_header in headers:
            results.append(_finding(
                f"{leaky_header.title()} header exposes version info: {headers[leaky_header]}",
                "low"
            ))

    return results

def check_cookies(response: httpx.Response) -> list[dict]:
    results = []
    cookies = response.headers.get_list("set-cookie")

    for cookie_str in cookies:
        lower = cookie_str.lower()
        cookie_name = cookie_str.split("=")[0].strip()

        if "secure" not in lower:
            results.append(_finding(
                f"{cookie_name} - Secure flag not set, can leak over HTTP", "medium"
            ))

        if "httponly" not in lower:
            results.append(_finding(
                f"{cookie_name} - HttpOnly not set, XSS vulnerable", "high"
            ))

        if "samesite=none" in lower and "secure" not in lower:
            results.append(_finding(
                f"{cookie_name} - SameSite=None without Secure, CSRF exposure", "high"
            ))

        elif "samesite" not in lower:
            results.append(_finding(
                f"{cookie_name} - SameSite flag missing", "low"
            ))
                
    print(cookies)
    return results

def check_reflected_xss(client: httpx.Client, form: dict, marker: str) -> list[dict]:
    dangerous = "<script>"
    full_marker = marker + dangerous
    findings = []

    #print("FORM ACTION:", form["action"], "| METHOD:", form["method"])

    for target_input in form["inputs"]: # Gets all inputs on the page
        payload = {}
        for inp in form["inputs"]: # Checks one at a time
            if inp["name"] == target_input["name"]: # Current field being tested
                payload[inp["name"]] = full_marker # Example = {username: MARKER, password: 1, Login: 1}
            elif inp.get("type") == "hidden":
                payload[inp["name"]] = inp.get("value", "1") # Preserve the hidden fields
            else:
                payload[inp["name"]] = "1" # Sets other fields to 1 so the form submission does not fail

        #print(form["inputs"])
        try:
            if form["method"] == "GET":
                resp = client.get(form["action"], follow_redirects=True, params=payload)
                #print("=== FULL RESPONSE START ===")
                #print(resp.text)
                #print("=== FULL RESPONSE END ===")
            else:
                resp = client.post(form["action"], follow_redirects=True, data=payload)
        except httpx.RequestError:
            continue

        #print(f"Testing {form['action']} field={target_input['name']}")
        #print(resp.text)

        if marker not in resp.text:
            continue # Not reflected at all, try next field

        if dangerous not in resp.text:
            continue # Reflected but escaped, try next field

        # Vulnerable
        idx = resp.text.find(dangerous)
        evidence = resp.text[max(0, idx - 40): idx + 40] # Some context, without dumping the entire page

        findings.append({
            "url": form["action"],
            "field": target_input["name"],
            "payload": full_marker,
            "evidence": evidence
        })

    return findings

def scan_xss(client: httpx.Client, pages: list[dict]) -> list[dict]:
    all_findings = []

    for page in pages:
        for form in page["forms"]:
            if any(skip in form["action"] for skip in SKIP_ACTIONS): # Skips logout, login, etc
                print("SKIPPING:", form["action"])
                continue
            print("TESTING:", form["action"])
            marker = f"zxcv{random.randint(1000,9999)}XSS"
            findings = check_reflected_xss(client, form, marker)

            for f in findings:
                f["source_page"] = page["url"] # Logs which page had the form
                all_findings.append(f)

    return all_findings

def check_sqli(client: httpx.Client, form: dict, payloads: list[str], error_signatures: list[str]) -> list[dict]:
    findings = []

    for field in form["inputs"]:
        if field["type"] in ("hidden", "submit"):
            continue

        for payload in payloads:
            data = {}
            for inp in form["inputs"]:
                if inp["type"] == "hidden":
                    data[inp["name"]] = inp["value"] # Dont temper with CSRF and so on
                elif inp["name"] == field["name"]:
                    data[inp["name"]] = payload # Field being ran
                else:
                    data[inp["name"]] = inp["value"] if inp["value"] else "1" # Safe filler for other fields

            print(f"[check_sqli] sending data: {data}")

            try:
                if form["method"] == "GET":
                    resp = client.get(form["action"], follow_redirects=True, params=data)
                    print(f"[check_sqli] actual request URL: {resp.request.url}")
                else:
                    resp = client.post(form["action"], follow_redirects=True, data=data)
            except httpx.RequestError:
                continue

            resp_text = resp.text.lower()

            for sig in error_signatures:
                if sig in resp_text:
                    findings.append({
                        "url": form["action"],
                        "field": field["name"],
                        "payload": payload,
                        "evidence": sig,
                    })
                    break

    return findings

def check_sqli_boolean(client: httpx.Client, form: dict, true_payload: str, false_payload: str) -> list[dict]:
    findings = []

    for field in form["inputs"]:
        if field["type"] in ("hidden", "submit"):
            continue

        original_value = field["value"] if field["value"] else "1" #fallback

        data_baseline = {}
        for inp in form["inputs"]:
            if inp["type"] == "hidden":
                data_baseline[inp["name"]] = inp["value"]
            elif inp["name"] == field["name"]:
                data_baseline[inp["name"]] = original_value
            else:
                data_baseline[inp["name"]] = "1"

        data_true = {}
        for inp in form["inputs"]:
            if inp["type"] == "hidden":
                data_true[inp["name"]] = inp["value"]
            elif inp["name"] == field["name"]:
                data_true[inp["name"]] = true_payload
            else:
                data_true[inp["name"]] = "1"

        data_false = {}
        for inp in form["inputs"]:
            if inp["type"] == "hidden":
                data_false[inp["name"]] = inp["value"]
            elif inp["name"] == field["name"]:
                data_false[inp["name"]] = false_payload
            else:
                data_false[inp["name"]] = "1"

        try:
            if form["method"] == "GET":
                resp_baseline = client.get(form["action"], follow_redirects=True, params=data_baseline)
                resp_true = client.get(form["action"], follow_redirects=True, params=data_true)
                resp_false = client.get(form["action"], follow_redirects=True, params=data_false)
            else:
                resp_baseline = client.post(form["action"], follow_redirects=True, data=data_baseline)
                resp_true = client.post(form["action"], follow_redirects=True, data=data_true)
                resp_false = client.post(form["action"], follow_redirects=True, data=data_false)
        except httpx.RequestError:
            continue

        print("baseline len:", len(resp_baseline.text))
        print("true len:", len(resp_true.text))
        print("false len:", len(resp_false.text))

        print("sim_true:", similarity(resp_baseline.text, resp_true.text))
        print("sim_false:", similarity(resp_baseline.text, resp_false.text))        

        sim_true = similarity(resp_baseline.text, resp_true.text)
        sim_false = similarity(resp_baseline.text, resp_false.text)

        if sim_true != 1.0 and sim_false != 1.0: # CALIBRATE
            findings.append({
                "url": form["action"],
                "field": field["name"],
                "payload": f"{true_payload} / {false_payload}",
                "evidence": f"sim_true={sim_true:.2f}, sim_false={sim_false:.2f}",
            })

    return findings

def scan_sqli(client: httpx.Client, pages: list[dict]) -> list[dict]:
    findings = []

    for page in pages:
        for form in page["forms"]:
            print(f"[scan_sqli] Testing form on {page['url']} -> action={form['action']}")

            if form["action"] in SKIP_ACTIONS:
                print(f"  -> skipped (SKIP_ACTIONS)")
                continue

            #Error based
            error_findings = check_sqli(client, form, ERROR_PAYLOADS, ERROR_SIGNATURES)
            for f in error_findings:
                f["source_page"] = page["url"]
                f["type"] = "error-based"
            findings.extend(error_findings)

            #Boolean based
            boolean_findings = check_sqli_boolean(
                client,
                form=form, 
                true_payload=BOOLEAN_TRUE_PAYLOAD, 
                false_payload=BOOLEAN_FALSE_PAYLOAD)
            
            for f in boolean_findings:
                f["source_page"] = page["url"]
                f["type"] = "boolean-based"
            findings.extend(boolean_findings)

    return findings

def crawl(client: httpx.Client, start_url: str, max_depth: int=3) -> list[dict]:
    queue = deque([(start_url, 0)])
    visited = set()
    results = []
    all_discovered_urls = set()

    while queue:
        url, depth = queue.popleft()

        norm = normalize_url(url)
        if norm in visited:
            continue

        visited.add(norm)

        if norm not in visited:
            queue.append((url, depth + 1))

        page = fetch_page(client, url)
        if page is None:
            continue


        links = []
        if page.status_code == 200:
            links = extract_links(page.text, url, BASE_URL)
            forms = extract_forms(page.text, url)
            headers = check_headers(page)
            cookies = check_cookies(page)

            all_discovered_urls.update(normalize_url(l) for l in links)

            results.append({
                'url': norm,
                'status': page.status_code,
                'forms': forms,
                'links_found': links,
                'headers': headers,
                'cookies': cookies
            })

        if depth < max_depth:
            for link in links:
                if any(skip in link for skip in SKIP_URLS):
                    continue
                link_norm = normalize_url(link)
                if link_norm not in visited:
                    queue.append((link, depth + 1))

    return results, all_discovered_urls

def main():
    with httpx.Client() as client:
        ok, login_results = login(client, "admin", "password")
        if not ok:
            print("Login failed")
            return
        
        set_security_level(client, "low")
        client.get(BASE_URL + "/security.php", params={"phpids": "off"}) # Turn off PHPIDS if its enabled

        results, all_urls = crawl(client, BASE_URL, max_depth=3)
        ##print(results)

        results.insert(0, login_results)
        save_results(results, "sitemap.json")
        save_results(sorted(all_urls), "unique_paths.json")

        xss_findings = scan_xss(client, results)
        save_results(xss_findings, "xss_findings.json")
        print(f"Found {len(xss_findings)} potential XSS issues.")
        print(f"Crawled {len(results)} pages.")

        sqli_findings = scan_sqli(client, results)
        print(f"Found {len(sqli_findings)} SQLi findings:")
        save_results(sqli_findings, "sqli_findings.json")

if __name__ == "__main__":
    main()