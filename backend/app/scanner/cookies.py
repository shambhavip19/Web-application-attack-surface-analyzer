import requests

def check_cookies(url, timeout=10):
    try:
        r = requests.get(url, timeout=timeout, allow_redirects=True, headers={'User-Agent': 'WASA-security-analyzer/1.0'})
        cookies = []
        for c in r.cookies:
            cookies.append({
                'name': c.name,
                'value': c.value,
                'secure': c.secure,
                'httponly': c.has_nonstandard_attr('HttpOnly') if hasattr(c, 'has_nonstandard_attr') else False,
                'samesite': next((value for key, value in getattr(c, '_rest', {}).items() if key.lower() == 'samesite'), None),
                'domain': c.domain,
                'path': c.path
            })
        return {'available': True, 'status': 'Detected' if cookies else 'Not Detected', 'count': len(cookies), 'cookies': cookies}
    except requests.RequestException as e:
        return {'available': False, 'status': 'Could Not Determine', 'error': str(e), 'count': None, 'cookies': []}
