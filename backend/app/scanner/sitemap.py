import requests
from urllib.parse import urljoin, urlparse

def fetch_sitemap(url, timeout=10):
    try:
        p = urlparse(url)
        base = f"{p.scheme}://{p.netloc}"
        sitemap_url = urljoin(base, '/sitemap.xml')
        r = requests.get(sitemap_url, timeout=timeout)
        if r.status_code == 200:
            return {'available': True, 'status': 'Available', 'url': sitemap_url, 'content': r.text}
        return {'available': True, 'status': 'Not Available', 'url': sitemap_url, 'status_code': r.status_code}
    except Exception as e:
        return {'available': False, 'status': 'Could not determine', 'error': str(e)}
