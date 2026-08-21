import requests

def check_cookies(url, timeout=10):
    try:
        r = requests.get(url, timeout=timeout)
        cookies = []
        for c in r.cookies:
            cookies.append({
                'name': c.name,
                'value': c.value,
                'secure': c.secure,
                'httponly': c.has_nonstandard_attr('HttpOnly') if hasattr(c, 'has_nonstandard_attr') else False,
                'samesite': c._rest.get('SameSite') if hasattr(c, '_rest') else None
            })
        return {'available': True, 'count': len(cookies), 'cookies': cookies}
    except Exception as e:
        return {'available': False, 'error': str(e), 'cookies': []}
