import requests
from urllib.parse import urljoin, urlparse

def fetch_sitemap(url, timeout=10):
    try:
        p = urlparse(url)
        base = f"{p.scheme}://{p.netloc}"
        sitemap_url = urljoin(base, '/sitemap.xml')
        r = requests.get(sitemap_url, timeout=timeout, allow_redirects=True, headers={'User-Agent': 'WASA-security-analyzer/1.0'})
        content_type = r.headers.get('content-type', '').lower()
        if r.status_code == 200 and r.text.strip() and ('xml' in content_type or r.text.lstrip().startswith('<?xml') or '<urlset' in r.text[:500].lower() or '<sitemapindex' in r.text[:500].lower()):
            return {'available': True, 'status': 'Available', 'url': sitemap_url, 'content': r.text}
        return {'available': True, 'status': 'Not Available', 'url': sitemap_url, 'status_code': r.status_code}
    except requests.RequestException as e:
        return {'available': False, 'status': 'Could Not Determine', 'url': sitemap_url, 'error': str(e)}
