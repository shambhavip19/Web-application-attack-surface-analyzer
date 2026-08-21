import requests

SECURITY_HEADERS = [
    'content-security-policy',
    'strict-transport-security',
    'x-frame-options',
    'x-content-type-options',
    'referrer-policy',
    'permissions-policy'
]

def check_headers(url, timeout=10):
    try:
        r = requests.get(url, timeout=timeout, allow_redirects=True)
        h = {k.lower(): v for k, v in r.headers.items()}
        found = {k: h.get(k) for k in SECURITY_HEADERS}
        return {
            'available': True,
            'status_code': r.status_code,
            'final_url': r.url,
            'headers': found,
            'present': [k for k, value in found.items() if value],
            'missing': [k for k, value in found.items() if not value]
        }
    except Exception as e:
        return {'available': False, 'error': str(e), 'headers': {}}
