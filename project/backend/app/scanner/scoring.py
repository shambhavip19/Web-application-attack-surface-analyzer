def score(result: dict) -> dict:
    # Very simple scoring: count missing recommended headers and give risk level
    headers = result.get('headers', {}).get('headers', {}) if isinstance(result.get('headers'), dict) else {}
    missing = [k for k, v in headers.items() if not v]
    total = len(headers)
    present = total - len(missing) if total else 0
    score_pct = int((present / total) * 100) if total else 0
    level = 'Low' if score_pct >= 80 else 'Medium' if score_pct >= 50 else 'High'
    return {'score': score_pct, 'level': level, 'missing_headers': missing}

def recommendations(result: dict) -> list:
    recs = []
    headers = result.get('headers', {}).get('headers', {}) if isinstance(result.get('headers'), dict) else {}
    for name, val in headers.items():
        if not val:
            recs.append(f'Add {name} header with recommended directives')
    if result.get('ssl', {}).get('note') == 'Non-HTTPS URL':
        recs.append('Use HTTPS with a valid TLS certificate')
    return recs
