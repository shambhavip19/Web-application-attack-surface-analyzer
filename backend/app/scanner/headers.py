import re

import requests

SECURITY_HEADERS = [
    'content-security-policy',
    'strict-transport-security',
    'x-frame-options',
    'x-content-type-options',
    'referrer-policy',
    'permissions-policy',
]

HEADER_DETAILS = {
    'content-security-policy': {
        'title': 'Content-Security-Policy',
        'what_it_does': 'Restricts where scripts, styles, frames, and other active resources may load from.',
        'why_it_matters': 'This helps reduce cross-site scripting, mixed-content issues, and unsafe resource loading.',
        'recommendation': 'Set a restrictive policy that allows only trusted origins and avoids unsafe-inline when possible.'
    },
    'strict-transport-security': {
        'title': 'Strict-Transport-Security',
        'what_it_does': 'Forces browsers to use HTTPS for the site and its subdomains.',
        'why_it_matters': 'It prevents downgrade attacks and keeps browser traffic on encrypted channels.',
        'recommendation': 'Use max-age=31536000; includeSubDomains; preload where appropriate.'
    },
    'x-frame-options': {
        'title': 'X-Frame-Options',
        'what_it_does': 'Prevents the site from being embedded inside a frame or iframe.',
        'why_it_matters': 'This helps reduce clickjacking and UI redressing attacks.',
        'recommendation': 'Use DENY or SAMEORIGIN, or pair a CSP frame-ancestors policy with a suitable allowlist.'
    },
    'x-content-type-options': {
        'title': 'X-Content-Type-Options',
        'what_it_does': 'Stops browsers from MIME-sniffing files and guessing the wrong content type.',
        'why_it_matters': 'It reduces browser confusion and helps avoid unsafe content execution.',
        'recommendation': 'Set this header to nosniff.'
    },
    'referrer-policy': {
        'title': 'Referrer-Policy',
        'what_it_does': 'Controls how much referrer information is sent with links and resource requests.',
        'why_it_matters': 'This reduces unnecessary leakage of user browsing context and sensitive URL data.',
        'recommendation': 'Prefer a restrictive policy such as strict-origin or no-referrer.'
    },
    'permissions-policy': {
        'title': 'Permissions-Policy',
        'what_it_does': 'Limits browser features such as camera, microphone, and geolocation access.',
        'why_it_matters': 'It reduces unnecessary browser capability exposure and limits abuse surface.',
        'recommendation': 'Disable unused browser features and allow only required permissions.'
    },
}


def evaluate_header_status(name, value, headers=None):
    name = (name or '').lower()
    headers = headers or {}
    meta = HEADER_DETAILS.get(name, {"title": name.replace('-', ' ').title(), "what_it_does": "Controls browser behavior for the site.", "why_it_matters": "It helps reduce common browser-side risks.", "recommendation": "Review the recommended policy for this header."})
    normalized_value = (value or '').strip()

    if not normalized_value:
        csp = headers.get('content-security-policy') or headers.get('content-security-policy-report-only') or ''
        if name == 'x-frame-options' and csp and re.search(r'frame-ancestors\s+', csp, re.I):
            return {
                'name': name,
                'title': meta['title'],
                'status': 'PASS',
                'value': 'Not set',
                'severity': 'Low',
                'what_it_does': meta['what_it_does'],
                'why_it_matters': meta['why_it_matters'],
                'recommendation': 'CSP frame-ancestors is providing clickjacking protection, so X-Frame-Options is not required for this control.',
                'explanation': 'The browser is protected against framing via CSP frame-ancestors, which overlaps with X-Frame-Options protection.'
            }
        return {
            'name': name,
            'title': meta['title'],
            'status': 'WARNING',
            'value': 'Not set',
            'severity': 'Low',
            'what_it_does': meta['what_it_does'],
            'why_it_matters': meta['why_it_matters'],
            'recommendation': meta['recommendation'],
            'explanation': f'{meta["title"]} is missing. This is a recommended hardening control, but its absence alone is not necessarily a critical issue.'
        }

    upper_value = normalized_value.upper()

    if name == 'content-security-policy':
        if 'REPORT-ONLY' in upper_value:
            return {
                'name': name,
                'title': meta['title'],
                'status': 'WARNING',
                'value': normalized_value,
                'severity': 'Medium',
                'what_it_does': meta['what_it_does'],
                'why_it_matters': meta['why_it_matters'],
                'recommendation': 'Use a normal Content-Security-Policy instead of report-only mode if you want the browser to enforce the policy.',
                'explanation': 'A report-only CSP records policy violations but does not stop unsafe content from loading.'
            }
        if 'FRAME-ANCESTORS' in upper_value or 'DEFAULT-SRC' in upper_value:
            return {
                'name': name,
                'title': meta['title'],
                'status': 'PASS',
                'value': normalized_value,
                'severity': 'Low',
                'what_it_does': meta['what_it_does'],
                'why_it_matters': meta['why_it_matters'],
                'recommendation': 'Keep the current CSP policy and review it periodically for unnecessary exceptions.',
                'explanation': 'The site includes a browser-enforced CSP and it appears to define a restrictive resource policy.'
            }
        return {
            'name': name,
            'title': meta['title'],
            'status': 'WARNING',
            'value': normalized_value,
            'severity': 'Medium',
            'what_it_does': meta['what_it_does'],
            'why_it_matters': meta['why_it_matters'],
            'recommendation': 'Define a safer baseline policy with trusted sources and remove unnecessary allowances.',
            'explanation': 'The CSP is present but does not clearly show a strong restriction pattern for browser execution and framing controls.'
        }

    if name == 'strict-transport-security':
        match = re.search(r'max-age\s*=\s*(\d+)', normalized_value, re.I)
        max_age = int(match.group(1)) if match else 0
        if max_age >= 31536000:
            status = 'PASS'
            explanation = 'HSTS is enabled with a strong max-age, which keeps browsers on HTTPS.'
        else:
            status = 'WARNING'
            explanation = 'HSTS is present, but the max-age is shorter than a full year and offers weaker protection.'
        return {
            'name': name,
            'title': meta['title'],
            'status': status,
            'value': normalized_value,
            'severity': 'Low' if status == 'PASS' else 'Medium',
            'what_it_does': meta['what_it_does'],
            'why_it_matters': meta['why_it_matters'],
            'recommendation': meta['recommendation'],
            'explanation': explanation,
        }

    if name == 'x-frame-options':
        upper = normalized_value.upper()
        if 'DENY' in upper or 'SAMEORIGIN' in upper:
            status = 'PASS'
            explanation = 'The browser is told not to render the page in a frame unless explicitly allowed by policy.'
        elif 'ALLOW-FROM' in upper:
            status = 'WARNING'
            explanation = 'ALLOW-FROM is deprecated and not consistently supported across modern browsers, so it provides weaker protection.'
        else:
            status = 'WARNING'
            explanation = 'The value is not a strong framing policy and may not provide consistent user protection.'
        return {
            'name': name,
            'title': meta['title'],
            'status': status,
            'value': normalized_value,
            'severity': 'Low' if status == 'PASS' else 'Medium',
            'what_it_does': meta['what_it_does'],
            'why_it_matters': meta['why_it_matters'],
            'recommendation': meta['recommendation'],
            'explanation': explanation,
        }

    if name == 'x-content-type-options':
        if normalized_value.lower() == 'nosniff':
            status = 'PASS'
            explanation = 'Browsers are told not to sniff the response type and guess a different content type.'
        else:
            status = 'WARNING'
            explanation = 'The header is present but does not match the recommended nosniff value.'
        return {
            'name': name,
            'title': meta['title'],
            'status': status,
            'value': normalized_value,
            'severity': 'Low' if status == 'PASS' else 'Medium',
            'what_it_does': meta['what_it_does'],
            'why_it_matters': meta['why_it_matters'],
            'recommendation': meta['recommendation'],
            'explanation': explanation,
        }

    if name == 'referrer-policy':
        good_values = {'no-referrer', 'strict-origin', 'same-origin', 'no-referrer-when-downgrade'}
        if normalized_value.lower() in good_values or 'strict' in normalized_value.lower():
            status = 'PASS'
            explanation = 'The site is limiting referrer leakage to a reasonable level for user privacy.'
        else:
            status = 'WARNING'
            explanation = 'The policy is present but not strongly restrictive, so it may leak more referrer information than necessary.'
        return {
            'name': name,
            'title': meta['title'],
            'status': status,
            'value': normalized_value,
            'severity': 'Low' if status == 'PASS' else 'Medium',
            'what_it_does': meta['what_it_does'],
            'why_it_matters': meta['why_it_matters'],
            'recommendation': meta['recommendation'],
            'explanation': explanation,
        }

    if name == 'permissions-policy':
        if normalized_value and 'none' in normalized_value.lower() or 'self' in normalized_value.lower():
            status = 'PASS'
            explanation = 'The page is restricting the use of browser capabilities that are not required for normal operation.'
        else:
            status = 'WARNING'
            explanation = 'The policy is either absent or too permissive to fully reduce browser capability exposure.'
        return {
            'name': name,
            'title': meta['title'],
            'status': status,
            'value': normalized_value,
            'severity': 'Low' if status == 'PASS' else 'Medium',
            'what_it_does': meta['what_it_does'],
            'why_it_matters': meta['why_it_matters'],
            'recommendation': meta['recommendation'],
            'explanation': explanation,
        }

    return {
        'name': name,
        'title': meta['title'],
        'status': 'PASS' if normalized_value else 'WARNING',
        'value': normalized_value,
        'severity': 'Low',
        'what_it_does': meta['what_it_does'],
        'why_it_matters': meta['why_it_matters'],
        'recommendation': meta['recommendation'],
        'explanation': f'{meta["title"]} is present and has a usable value.'
    }


def check_headers(url, timeout=10):
    try:
        r = requests.get(url, timeout=timeout, allow_redirects=True, headers={'User-Agent': 'WASA-security-analyzer/1.0'})
        headers_map = {k.lower(): v for k, v in r.headers.items()}
        details = {name: evaluate_header_status(name, headers_map.get(name), headers_map) for name in SECURITY_HEADERS}
        report_only = headers_map.get('content-security-policy-report-only')
        if report_only:
            details['content-security-policy-report-only'] = evaluate_header_status('content-security-policy', report_only, headers_map)

        overall_status = 'PASS'
        if any(detail.get('status') == 'FAIL' for detail in details.values()):
            overall_status = 'FAIL'
        elif any(detail.get('status') == 'WARNING' for detail in details.values()):
            overall_status = 'WARNING'
        elif any(detail.get('status') == 'NOT AVAILABLE' for detail in details.values()):
            overall_status = 'NOT AVAILABLE'

        return {
            'available': True,
            'status': overall_status,
            'status_code': r.status_code,
            'final_url': r.url,
            'initial_url': url,
            'redirected': bool(r.history),
            'redirects': [{'from': redirect.url, 'to': redirect.headers.get('location'), 'status_code': redirect.status_code} for redirect in r.history],
            'headers': {name: headers_map.get(name) for name in SECURITY_HEADERS},
            'details': details,
            'present': [name for name, value in headers_map.items() if value and name.lower() in SECURITY_HEADERS],
            'missing': [name for name in SECURITY_HEADERS if not headers_map.get(name)],
        }
    except requests.RequestException as e:
        return {
            'available': False,
            'status': 'COULD NOT DETERMINE',
            'error': str(e),
            'headers': {},
            'details': {},
            'present': [],
            'missing': []
        }
