import httpx
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qsl, urlunparse, urlencode
from collections import deque
import json

BASE_URL = 'http://localhost:8080'

def login(client: httpx.Client, base_url: str, username: str, password: str) -> bool:
    login_url = f"{BASE_URL}/login.php"

    resp = client.get(login_url)

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
        return True
    else:
        print("sad")
        return False
    pass

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

            inputs.append({
                "name": name,
                "type": input_type
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

            all_discovered_urls.update(normalize_url(l) for l in links)

            results.append({
                'url': norm,
                'status': page.status_code,
                'forms': forms,
                'links_found': links
            })

        if depth < max_depth:
            for link in links:
                link_norm = normalize_url(link)
                if link_norm not in visited:
                    queue.append((link, depth + 1))

    return results, all_discovered_urls



def main():
    with httpx.Client() as client:
        ok = login(client, BASE_URL, "admin", "password")
        if not ok:
            print("Login failed")
            return

        results, all_urls = crawl(client, BASE_URL, max_depth=3)
        print(results)
        save_results(results, "sitemap.json")
        save_results(sorted(all_urls), "unique_paths.json")
        print(f"Crawled {len(results)} pages.")


if __name__ == "__main__":
    main()