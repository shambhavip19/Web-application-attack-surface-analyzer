SEVERITY_DEDUCTIONS = {
    'Critical': 15,
    'High': 10,
    'Medium': 5,
    'Low': 2,
    'Informational': 0,
}


def score(result: dict) -> dict:
    findings = result.get('findings', []) or []
    seen = set()
    deductions = 0
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        key = finding.get('issue_key') or finding.get('title') or str(finding)
        if key in seen:
            continue
        seen.add(key)
        severity = str(finding.get('severity', 'Informational')).title()
        deduction = finding.get('deduction')
        if deduction is None:
            deduction = SEVERITY_DEDUCTIONS.get(severity, 0)
        deductions += int(deduction)

    score_pct = max(0, min(100, 100 - deductions))
    if score_pct >= 80:
        level = 'Low'
    elif score_pct >= 60:
        level = 'Medium'
    elif score_pct >= 40:
        level = 'High'
    else:
        level = 'Critical'

    return {
        'score': score_pct,
        'level': level,
        'deductions': deductions,
        'scored_checks': ['headers', 'cookies', 'ssl', 'robots', 'sitemap', 'javascript', 'technology']
    }


def severity_counts(findings: list) -> dict:
    counts = {level: 0 for level in ('Critical', 'High', 'Medium', 'Low', 'Informational')}
    for finding in findings:
        severity = str(finding.get('severity', 'Informational')).title()
        counts[severity if severity in counts else 'Informational'] += 1
    return counts


def recommendations(result: dict) -> list:
    recs = []
    if not result.get('headers', {}).get('available'):
        return ['Retry the scan after confirming the target is reachable.']

    header_details = result.get('headers', {}).get('details', {})
    for name, detail in header_details.items():
        if isinstance(detail, dict) and detail.get('status') in {'WARNING', 'FAIL'}:
            recs.append(detail.get('recommendation') or f'Review the {detail.get("title", name)} configuration.')

    ssl_result = result.get('ssl', {})
    if ssl_result.get('https') is False:
        recs.append('Use HTTPS with a valid TLS certificate for encrypted browser traffic.')
    elif ssl_result.get('status') == 'WARNING':
        recs.append('Renew or replace the certificate before it expires to keep the HTTPS posture strong.')

    cookies = result.get('cookies', {})
    if cookies.get('status') == 'WARNING':
        recs.append('Review cookie settings and add Secure, HttpOnly, and SameSite attributes where appropriate.')

    return recs
