import requests
from urllib.parse import urljoin, urlparse

def fetch_robots(url, timeout=10):
    try:
        p = urlparse(url)
        base = f"{p.scheme}://{p.netloc}"
        robots_url = urljoin(base, '/robots.txt')
        r = requests.get(robots_url, timeout=timeout, allow_redirects=True, headers={'User-Agent': 'WASA-security-analyzer/1.0'})
        content_type = r.headers.get('content-type', '').lower()
        if r.status_code == 200 and r.text.strip() and ('html' not in content_type or 'text/plain' in content_type):
            return {'available': True, 'status': 'Available', 'url': robots_url, 'content': r.text}
        return {'available': True, 'status': 'Not Available', 'url': robots_url, 'status_code': r.status_code}
    except requests.RequestException as e:
        return {'available': False, 'status': 'Could Not Determine', 'url': robots_url, 'error': str(e)}
