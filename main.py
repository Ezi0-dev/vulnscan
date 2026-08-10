import httpx
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from collections import deque

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

def extract_links(client: httpx.Client, path):
    resp = client.get(path)
    soup = BeautifulSoup(resp.text, "html.parser")
    hrefs = [a.get('href') for a in soup.find_all('a')]
    return hrefs

queue = deque(["/index.php"])
visited = set()

with httpx.Client(base_url=BASE_URL) as client:
    while queue:
        path = queue.popleft()

        if path in visited:
            continue
        visited.add(path)

        hrefs = get_links(client, path)

        for href in hrefs:
            if href is None:
                continue

            full_url = urljoin(f"{BASE_URL}{path}", href)
            parsed = urlparse(full_url)

            if parsed.netloc != urlparse(BASE_URL).netloc:
                continue

            new_path = parsed.path
            if parsed.query:
                new_path += f"?{parsed.query}"

            if new_path not in visited and new_path not in queue:
                queue.append(new_path)

