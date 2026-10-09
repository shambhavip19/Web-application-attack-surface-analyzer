from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup


def find_js(url, timeout=10):
    try:
        r = requests.get(url, timeout=timeout, allow_redirects=True, headers={'User-Agent': 'WASA-security-analyzer/1.0'})
        soup = BeautifulSoup(r.text, 'html.parser')
        scripts = []
        for s in soup.find_all('script'):
            src = s.get('src')
            if src:
                scripts.append(urljoin(r.url, src))
        return {'available': True, 'status': 'AVAILABLE' if scripts else 'NOT AVAILABLE', 'scripts': scripts, 'page_url': r.url, 'final_url': r.url}
    except requests.RequestException as e:
        return {'available': False, 'status': 'COULD NOT DETERMINE', 'error': str(e), 'scripts': []}
