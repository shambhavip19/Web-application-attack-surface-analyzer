def score(result: dict) -> dict:
    header_result = result.get('headers', {})
    if not header_result.get('available'):
        return {'score': None, 'level': 'Could Not Determine', 'missing_headers': [], 'reason': 'The target response could not be retrieved'}
    headers = header_result.get('headers', {})
    missing = [k for k, value in headers.items() if not value]
    present = len(headers) - len(missing)
    header_score = int((present / len(headers)) * 70) if headers else 0
    ssl_result = result.get('ssl', {})
    tls_score = 25 if ssl_result.get('available') and ssl_result.get('https') else 0
    cookie_result = result.get('cookies', {})
    cookie_score = 10 if cookie_result.get('available') else 0
    score_pct = min(100, header_score + tls_score + cookie_score)
    transport_failure = ssl_result.get('available') and not ssl_result.get('https')
    level = 'High' if transport_failure or score_pct < 25 else 'Medium' if score_pct < 70 else 'Low'
    return {'score': score_pct, 'level': level, 'missing_headers': missing, 'present_headers': present, 'total_headers': len(headers), 'scored_checks': ['headers', 'ssl', 'cookies']}

def severity_counts(findings: list) -> dict:
    counts = {level: 0 for level in ('Critical', 'High', 'Medium', 'Low', 'Informational')}
    for finding in findings:
        severity = finding.get('severity', 'Informational')
        counts[severity if severity in counts else 'Informational'] += 1
    return counts

def recommendations(result: dict) -> list:
    recs = []
    headers = result.get('headers', {}).get('headers', {}) if isinstance(result.get('headers'), dict) else {}
    if not result.get('headers', {}).get('available'):
        return ['Retry the scan after confirming the URL is reachable']
    for name, val in headers.items():
        if not val:
            recs.append(f'Add {name} header with recommended directives')
    if result.get('ssl', {}).get('available') and not result.get('ssl', {}).get('https'):
        recs.append('Use HTTPS with a valid TLS certificate')
    return recs
