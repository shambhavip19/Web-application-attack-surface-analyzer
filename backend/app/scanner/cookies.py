import requests


def _parse_cookie_header(raw_cookie):
    if not raw_cookie:
        return {}
    name_value, *attributes = raw_cookie.split(';')
    if '=' not in name_value:
        return {'name': name_value.strip(), 'value': ''}
    name, value = name_value.split('=', 1)
    parsed = {'name': name.strip(), 'value': value.strip()}
    for attribute in attributes:
        item = attribute.strip()
        if not item:
            continue
        if '=' in item:
            key, value_part = item.split('=', 1)
            parsed[key.strip().lower()] = value_part.strip()
        else:
            parsed[item.strip().lower()] = True
    return parsed


def check_cookies(url, timeout=10):
    try:
        r = requests.get(url, timeout=timeout, allow_redirects=True, headers={'User-Agent': 'WASA-security-analyzer/1.0'})
        raw_set_cookies = r.headers.getlist('Set-Cookie') if hasattr(r.headers, 'getlist') else []
        cookies = []
        if not raw_set_cookies:
            raw_set_cookies = []
            for cookie in r.cookies:
                raw_set_cookies.append(f"{cookie.name}={cookie.value}; {'Secure' if cookie.secure else ''}; {'HttpOnly' if getattr(cookie, 'httponly', False) else ''}; {'SameSite=' + cookie._rest.get('SameSite', '') if getattr(cookie, '_rest', None) else ''}".strip('; '))

        for raw in raw_set_cookies:
            cookie = _parse_cookie_header(raw)
            if not cookie:
                continue
            cookies.append({
                'name': cookie.get('name', 'unknown'),
                'value': cookie.get('value', ''),
                'secure': bool(cookie.get('secure')),
                'httponly': bool(cookie.get('httponly')),
                'samesite': cookie.get('samesite'),
                'domain': cookie.get('domain'),
                'path': cookie.get('path'),
                'raw': raw,
            })

        if not cookies:
            return {'available': True, 'status': 'NOT AVAILABLE', 'count': 0, 'cookies': [], 'final_url': r.url, 'message': 'No cookies were returned by the final response.'}

        insecure = [cookie for cookie in cookies if not cookie.get('secure') or not cookie.get('httponly') or not cookie.get('samesite')]
        overall_status = 'PASS' if not insecure else 'WARNING'
        return {'available': True, 'status': overall_status, 'count': len(cookies), 'cookies': cookies, 'final_url': r.url, 'insecure_count': len(insecure)}
    except requests.RequestException as e:
        return {'available': False, 'status': 'COULD NOT DETERMINE', 'error': str(e), 'count': None, 'cookies': []}
