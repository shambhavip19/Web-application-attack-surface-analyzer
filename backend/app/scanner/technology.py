import requests
from bs4 import BeautifulSoup

def detect(url, timeout=10):
    try:
        r = requests.get(url, timeout=timeout)
        soup = BeautifulSoup(r.text, 'html.parser')
        tech = []
        server = r.headers.get('server')
        if server:
            tech.append({'name': 'Web server', 'value': server, 'evidence': 'Server response header'})
        powered = r.headers.get('x-powered-by')
        if powered:
            tech.append({'name': 'Runtime', 'value': powered, 'evidence': 'X-Powered-By response header'})
        generator = soup.find('meta', attrs={'name': lambda value: value and value.lower() == 'generator'})
        if generator and generator.get('content'):
            tech.append({'name': 'Generator', 'value': generator['content'], 'evidence': 'HTML generator meta tag'})

        html = r.text.lower()
        resource_text = ' '.join((tag.get('src') or '') + ' ' + (tag.get('href') or '') for tag in soup.find_all(['script', 'link'])).lower()
        fingerprints = [
            ('WordPress', ['wp-content', 'wp-includes']),
            ('Next.js', ['/_next/', '__next_data__']),
            ('React', ['react', 'data-reactroot']),
            ('Vue.js', ['vue', 'data-v-']),
            ('Angular', ['ng-version', 'angular']),
            ('Bootstrap', ['bootstrap']),
            ('jQuery', ['jquery']),
            ('Google Analytics', ['google-analytics', 'googletagmanager', 'gtag(']),
            ('Cloudflare', ['cf-ray'])
        ]
        for name, markers in fingerprints:
            marker = next((item for item in markers if item in html or item in resource_text), None)
            if marker:
                tech.append({'name': name, 'value': 'Detected', 'evidence': marker})
        unique = {item['name']: item for item in tech}
        return {'available': True, 'technologies': list(unique.values())}
    except Exception as e:
        return {'available': False, 'error': str(e), 'technologies': []}
