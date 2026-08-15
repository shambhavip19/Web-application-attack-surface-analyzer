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
        return {'status_code': r.status_code, 'headers': found}
    except Exception as e:
        return {'error': str(e)}
