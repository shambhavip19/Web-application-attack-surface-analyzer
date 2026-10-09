import re

import requests
from bs4 import BeautifulSoup


def detect(url, timeout=10):
    try:
        r = requests.get(url, timeout=timeout, allow_redirects=True, headers={'User-Agent': 'WASA-security-analyzer/1.0'})
        soup = BeautifulSoup(r.text, 'html.parser')
        html = r.text.lower()
        script_urls = ' '.join((tag.get('src') or '') for tag in soup.find_all('script')).lower()
        link_urls = ' '.join((tag.get('href') or '') for tag in soup.find_all('link')).lower()
        tech = []

        def add_tech(name, value, evidence, confidence):
            tech.append({'technology': name, 'value': value, 'evidence': evidence, 'confidence': confidence})

        server = r.headers.get('server')
        if server:
            add_tech('Web server', server, 'Server response header', 'Confirmed')

        powered_by = r.headers.get('x-powered-by')
        if powered_by:
            add_tech('Runtime', powered_by, 'X-Powered-By response header', 'Confirmed')

        generator = soup.find('meta', attrs={'name': lambda value: value and value.lower() == 'generator'})
        if generator and generator.get('content'):
            add_tech('Generator', generator.get('content'), 'HTML meta generator tag', 'Confirmed')

        patterns = [
            ('React', ['data-reactroot', 'react.production.min.js', 'react-dom', 'reactjs.org'], 'script or HTML markers', 'Possible'),
            ('Next.js', ['/_next/', '__next_data__', 'next/script'], 'script or HTML markers', 'Confirmed'),
            ('Vue.js', ['vue.global', 'data-v-', 'vuejs.org'], 'script or HTML markers', 'Possible'),
            ('Angular', ['ng-version', 'angular.min.js', 'angular.io'], 'script or HTML markers', 'Possible'),
            ('Bootstrap', ['bootstrap.min.css', 'bootstrap.min.js'], 'link or script URLs', 'Confirmed'),
            ('jQuery', ['jquery.min.js', 'jquery.js'], 'script URLs', 'Confirmed'),
            ('WordPress', ['wp-content', 'wp-includes', 'wordpress'], 'HTML or resource paths', 'Confirmed'),
            ('Google Analytics', ['google-analytics.com', 'googletagmanager.com', 'gtag('], 'script or inline code markers', 'Confirmed'),
        ]

        for name, markers, source_text, confidence in patterns:
            for marker in markers:
                if marker in html or marker in script_urls or marker in link_urls:
                    add_tech(name, name, f'{source_text}: {marker}', confidence)
                    break

        if r.headers.get('x-aspnet-version'):
            add_tech('ASP.NET', r.headers.get('x-aspnet-version'), 'X-AspNet-Version response header', 'Confirmed')

        unique = {}
        for item in tech:
            key = item['technology']
            if key not in unique or item['confidence'] == 'Confirmed':
                unique[key] = item

        if not unique:
            return {'available': True, 'status': 'NOT AVAILABLE', 'final_url': r.url, 'technologies': [], 'message': 'Not enough evidence to confidently identify a framework or library.'}

        return {'available': True, 'status': 'PASS', 'final_url': r.url, 'technologies': list(unique.values())}
    except requests.RequestException as e:
        return {'available': False, 'status': 'COULD NOT DETERMINE', 'error': str(e), 'technologies': []}
