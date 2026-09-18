import requests
from bs4 import BeautifulSoup

def detect(url, timeout=10):
    try:
        r = requests.get(url, timeout=timeout)
        soup = BeautifulSoup(r.text, 'html.parser')
        tech = []
        server = r.headers.get('server')
        if server:
            tech.append({'name': 'Web server', 'value': server, 'evidence': 'Server response header', 'confidence': 'Confirmed'})
        powered = r.headers.get('x-powered-by')
        if powered:
            tech.append({'name': 'Runtime', 'value': powered, 'evidence': 'X-Powered-By response header', 'confidence': 'Confirmed'})
        generator = soup.find('meta', attrs={'name': lambda value: value and value.lower() == 'generator'})
        if generator and generator.get('content'):
            tech.append({'name': 'Generator', 'value': generator['content'], 'evidence': 'HTML generator meta tag', 'confidence': 'Confirmed'})

        html = r.text.lower()
        resource_text = ' '.join((tag.get('src') or '') + ' ' + (tag.get('href') or '') for tag in soup.find_all(['script', 'link'])).lower()
        scripts = ' '.join(tag.get('src') or '' for tag in soup.find_all('script')).lower()
        fingerprints = [
            ('WordPress', [('wp-content', 'HTML/resource path'), ('wp-includes', 'HTML/resource path')]),
            ('Next.js', [('/_next/', 'script/resource path'), ('__next_data__', 'Next.js data element')]),
            ('React', [('data-reactroot', 'React root attribute'), ('react.production.min.js', 'script URL')]),
            ('Vue.js', [('data-v-', 'Vue component attribute'), ('vue.global', 'script URL')]),
            ('Angular', [('ng-version', 'Angular version attribute'), ('angular.min.js', 'script URL')]),
            ('Bootstrap', [('bootstrap.min.css', 'stylesheet URL'), ('bootstrap.min.js', 'script URL')]),
            ('jQuery', [('jquery.min.js', 'script URL'), ('jquery.js', 'script URL')]),
            ('Google Analytics', [('google-analytics.com', 'script URL'), ('googletagmanager.com', 'script URL'), ('gtag(', 'inline script')]),
        ]
        for name, markers in fingerprints:
            marker, evidence = next(((item, source) for item, source in markers if item in html or item in resource_text or item in scripts), (None, None))
            if marker:
                confidence = 'Confirmed' if name in ('WordPress', 'Next.js') or evidence in ('script URL', 'stylesheet URL', 'Next.js data element', 'React root attribute', 'Vue component attribute', 'Angular version attribute') else 'Possible'
                tech.append({'name': name, 'value': name, 'evidence': f'{evidence}: {marker}', 'confidence': confidence})
        unique = {}
        for item in tech:
            current = unique.get(item['name'])
            if not current or item['confidence'] == 'Confirmed':
                unique[item['name']] = item
        return {'available': True, 'technologies': list(unique.values())}
    except Exception as e:
        return {'available': False, 'error': str(e), 'technologies': []}
