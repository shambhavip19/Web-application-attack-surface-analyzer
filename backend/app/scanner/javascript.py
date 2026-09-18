import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

def find_js(url, timeout=10):
    try:
        r = requests.get(url, timeout=timeout)
        soup = BeautifulSoup(r.text, 'html.parser')
        scripts = []
        for s in soup.find_all('script'):
            src = s.get('src')
            if src:
                scripts.append(urljoin(r.url, src))
        return {'available': True, 'status': 'Detected' if scripts else 'Not Detected', 'scripts': scripts}
    except Exception as e:
        return {'available': False, 'status': 'Could not determine', 'error': str(e), 'scripts': []}
