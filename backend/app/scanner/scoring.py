def score(result: dict) -> dict:
    header_result = result.get('headers', {})
    if not header_result.get('available'):
        return {'score': None, 'level': 'Unavailable', 'missing_headers': [], 'reason': 'The target response could not be retrieved'}
    headers = header_result.get('headers', {})
    missing = [k for k, value in headers.items() if not value]
    present = len(headers) - len(missing)
    header_score = int((present / len(headers)) * 70) if headers else 0
    ssl_result = result.get('ssl', {})
    tls_score = 25 if ssl_result.get('available') else 0
    cookie_score = 10 if result.get('cookies', {}).get('available') else 0
    score_pct = min(100, header_score + tls_score + cookie_score)
    transport_failure = ssl_result.get('https') and not ssl_result.get('available')
    level = 'High' if transport_failure or score_pct < 25 else 'Medium' if score_pct < 70 else 'Low'
    return {'score': score_pct, 'level': level, 'missing_headers': missing, 'present_headers': present, 'total_headers': len(headers)}

def recommendations(result: dict) -> list:
    recs = []
    headers = result.get('headers', {}).get('headers', {}) if isinstance(result.get('headers'), dict) else {}
    if not result.get('headers', {}).get('available'):
        return ['Retry the scan after confirming the URL is reachable']
    for name, val in headers.items():
        if not val:
            recs.append(f'Add {name} header with recommended directives')
    if result.get('ssl', {}).get('note') == 'Non-HTTPS URL':
        recs.append('Use HTTPS with a valid TLS certificate')
    return recs
