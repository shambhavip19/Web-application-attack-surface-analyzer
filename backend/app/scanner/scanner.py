from . import cookies, headers, javascript, robots, scoring, sitemap, ssl_check, technology


def _add_finding(findings, seen, title, severity, explanation, recommendation, evidence, issue_key=None, deduction=None):
    key = issue_key or title
    if key in seen:
        return
    seen.add(key)
    findings.append({
        'title': title,
        'severity': severity,
        'explanation': explanation,
        'recommendation': recommendation,
        'evidence': evidence,
        'issue_key': key,
        'deduction': deduction if deduction is not None else {'Critical': 15, 'High': 10, 'Medium': 5, 'Low': 2, 'Informational': 0}.get(severity, 0),
    })


def build_findings(result):
    findings = []
    seen = set()

    header_details = result.get('headers', {}).get('details', {})
    for name, detail in header_details.items():
        status = detail.get('status')
        if status == 'FAIL':
            _add_finding(
                findings,
                seen,
                f"{detail.get('title', name)} is too weak",
                detail.get('severity', 'Medium'),
                detail.get('explanation', 'The header is present but does not provide strong protection.'),
                detail.get('recommendation', 'Review the policy and enforce a safer configuration.'),
                detail.get('value', 'Not set'),
                issue_key=f'header:{name}',
                deduction=10 if detail.get('severity') == 'High' else 5,
            )
        elif status == 'WARNING':
            _add_finding(
                findings,
                seen,
                f"{detail.get('title', name)} is missing or weak",
                detail.get('severity', 'Low'),
                detail.get('explanation', 'This security control is either absent or not configured with a strong policy.'),
                detail.get('recommendation', detail.get('recommendation', 'Add or strengthen this header configuration.')),
                detail.get('value', 'Not set'),
                issue_key=f'header:{name}',
                deduction=2,
            )

    ssl_result = result.get('ssl', {})
    if ssl_result.get('https') is False:
        _add_finding(
            findings,
            seen,
            'Site is served over HTTP',
            'High',
            'The target is not protected by HTTPS, so data in transit can be observed or altered more easily.',
            'Use HTTPS and redirect all traffic to an encrypted endpoint.',
            'The final URL is using HTTP instead of HTTPS.',
            issue_key='http_only',
            deduction=10,
        )
    elif ssl_result.get('status') == 'FAIL':
        _add_finding(
            findings,
            seen,
            'Certificate is expired or invalid',
            'High',
            'The encrypted connection is not currently trusted or valid for the site.',
            'Renew the certificate and confirm the site is serving a valid chain.',
            ssl_result.get('not_after', 'Certificate data is not valid.'),
            issue_key='ssl_certificate',
            deduction=10,
        )
    elif ssl_result.get('status') == 'WARNING':
        _add_finding(
            findings,
            seen,
            'Certificate is expiring soon',
            'Medium',
            'The certificate is valid but may require renewal soon.',
            'Renew the certificate before the expiry window closes.',
            ssl_result.get('not_after', 'Certificate expiry is not available.'),
            issue_key='ssl_expiry',
            deduction=5,
        )

    cookie_result = result.get('cookies', {})
    if cookie_result.get('status') == 'WARNING':
        for cookie in cookie_result.get('cookies', []):
            missing = []
            if not cookie.get('secure'):
                missing.append('Secure')
            if not cookie.get('httponly'):
                missing.append('HttpOnly')
            if not cookie.get('samesite'):
                missing.append('SameSite')
            if missing:
                _add_finding(
                    findings,
                    seen,
                    f"Cookie {cookie.get('name', 'unknown')} is missing protections",
                    'Low',
                    f"This cookie is missing one or more recommended protection settings: {', '.join(missing)}.",
                    'Add the missing security attributes to the cookie configuration.',
                    cookie.get('raw', 'No cookie attributes were returned.'),
                    issue_key=f'cookie:{cookie.get("name", "unknown")}',
                    deduction=2,
                )

    findings = sorted(findings, key=lambda item: {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3, 'Informational': 4}.get(item.get('severity', 'Informational'), 5))
    return findings[:5]


def run_scan(url, timeout=10):
    result = {}
    result['headers'] = headers.check_headers(url, timeout)
    result['cookies'] = cookies.check_cookies(url, timeout)
    result['ssl'] = ssl_check.check_ssl(url, timeout)
    result['robots'] = robots.fetch_robots(url, timeout)
    result['sitemap'] = sitemap.fetch_sitemap(url, timeout)
    result['javascript'] = javascript.find_js(url, timeout)
    result['technologies'] = technology.detect(url, timeout)
    result['findings'] = build_findings(result)
    result['score'] = scoring.score(result)
    result['recommendations'] = scoring.recommendations(result)
    result['severity_counts'] = scoring.severity_counts(result['findings'])
    summary = {'passed': 0, 'warnings': 0, 'failed': 0, 'informational': 0}
    for detail in result.get('headers', {}).get('details', {}).values():
        status = detail.get('status', 'WARNING')
        if status == 'PASS':
            summary['passed'] += 1
        elif status == 'WARNING':
            summary['warnings'] += 1
        elif status == 'FAIL':
            summary['failed'] += 1
        else:
            summary['informational'] += 1
    ssl_status = result.get('ssl', {}).get('status', 'COULD NOT DETERMINE')
    if ssl_status == 'PASS':
        summary['passed'] += 1
    elif ssl_status == 'WARNING':
        summary['warnings'] += 1
    elif ssl_status == 'FAIL':
        summary['failed'] += 1
    else:
        summary['informational'] += 1

    if result.get('cookies', {}).get('status') == 'PASS':
        summary['passed'] += 1
    elif result.get('cookies', {}).get('status') == 'WARNING':
        summary['warnings'] += 1
    elif result.get('cookies', {}).get('status') == 'FAIL':
        summary['failed'] += 1
    else:
        summary['informational'] += 1

    result['summary'] = summary
    return result
