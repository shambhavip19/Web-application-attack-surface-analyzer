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
    return result
