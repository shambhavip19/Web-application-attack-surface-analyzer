from urllib.parse import urljoin, urlparse

import requests


def fetch_robots(url, timeout=10):
    try:
        p = urlparse(url)
        base = f"{p.scheme}://{p.netloc}"
        robots_url = urljoin(base, '/robots.txt')
        r = requests.get(robots_url, timeout=timeout, allow_redirects=True, headers={'User-Agent': 'WASA-security-analyzer/1.0'})
        content_type = r.headers.get('content-type', '').lower()
        if r.status_code == 200 and r.text.strip() and ('html' not in content_type or 'text/plain' in content_type):
            return {'available': True, 'status': 'AVAILABLE', 'url': robots_url, 'content': r.text, 'final_url': r.url}
        return {'available': True, 'status': 'NOT AVAILABLE', 'url': robots_url, 'status_code': r.status_code, 'final_url': r.url}
    except requests.RequestException as e:
        return {'available': False, 'status': 'COULD NOT DETERMINE', 'url': url, 'error': str(e)}
