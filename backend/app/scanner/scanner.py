import json
from . import headers, cookies, ssl_check, robots, sitemap, javascript, technology, scoring

def run_scan(url, timeout=10):
    result = {}
    result['headers'] = headers.check_headers(url, timeout)
    result['cookies'] = cookies.check_cookies(url, timeout)
    result['ssl'] = ssl_check.check_ssl(url, timeout)
    result['robots'] = robots.fetch_robots(url, timeout)
    result['sitemap'] = sitemap.fetch_sitemap(url, timeout)
    result['javascript'] = javascript.find_js(url, timeout)
    result['technologies'] = technology.detect(url, timeout)
    result['score'] = scoring.score(result)
    result['recommendations'] = scoring.recommendations(result)
    result['findings'] = build_findings(result)
    return result

def build_findings(result):
    findings = []
    headers_result = result.get('headers', {})
    if headers_result.get('available'):
        for header in headers_result.get('missing', []):
            findings.append({'title': f'Missing {header}', 'severity': 'Medium', 'explanation': 'This browser protection instruction was not included in the response.', 'recommendation': f'Add the {header} header with a suitable policy.'})
    ssl_result = result.get('ssl', {})
    if ssl_result.get('available') and not ssl_result.get('https'):
        findings.append({'title': 'HTTPS is not enabled', 'severity': 'High', 'explanation': 'The connection is not encrypted, so information can be easier to read in transit.', 'recommendation': 'Serve the website over HTTPS with a valid certificate.'})
    return findings
