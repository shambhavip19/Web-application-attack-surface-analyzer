import datetime
import socket
import ssl
from urllib.parse import urlparse

import requests


def _cert_subject(cert):
    if not cert:
        return 'Not available'
    subject = cert.get('subject', [])
    if not subject:
        return 'Not available'
    for item in subject:
        for key, value in item:
            if key == 'commonName':
                return value
    return str(subject)


def _cert_issuer(cert):
    if not cert:
        return 'Not available'
    issuer = cert.get('issuer', [])
    if not issuer:
        return 'Not available'
    for item in issuer:
        for key, value in item:
            if key == 'commonName':
                return value
    return str(issuer)


def _parse_cert_time(value):
    try:
        return datetime.datetime.strptime(value, '%b %d %H:%M:%S %Y %Z')
    except (TypeError, ValueError):
        return None


def check_ssl(url, timeout=10):
    try:
        response = requests.get(url, timeout=timeout, allow_redirects=True, headers={'User-Agent': 'WASA-security-analyzer/1.0'})
        effective_url = response.url
        p = urlparse(effective_url)
        host = p.hostname
        port = p.port or (443 if p.scheme == 'https' else 80)
        if not host:
            return {'available': False, 'https': None, 'status': 'COULD NOT DETERMINE', 'error': 'URL has no hostname'}
        if p.scheme.lower() != 'https':
            return {'available': True, 'https': False, 'status': 'NOT AVAILABLE', 'note': 'The final response is using HTTP, so no certificate is available.', 'final_url': effective_url, 'redirected': bool(response.history)}

        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as raw_conn:
            with ctx.wrap_socket(raw_conn, server_hostname=host) as conn:
                cert = conn.getpeercert()

        if not cert:
            return {'available': True, 'https': True, 'status': 'WARNING', 'note': 'HTTPS is enabled but certificate details could not be retrieved.', 'certificate': {}, 'final_url': effective_url, 'redirected': bool(response.history)}

        not_before = _parse_cert_time(cert.get('notBefore'))
        not_after = _parse_cert_time(cert.get('notAfter'))
        now = datetime.datetime.utcnow()
        days_until_expiry = (not_after - now).days if not_after else None

        if not_after and not_after > now and days_until_expiry > 14:
            status = 'PASS'
        elif not_after and not_after > now:
            status = 'WARNING'
        else:
            status = 'FAIL'

        return {
            'available': True,
            'https': True,
            'status': status,
            'certificate_valid': status in {'PASS', 'WARNING'},
            'subject': _cert_subject(cert),
            'issuer': _cert_issuer(cert),
            'not_before': cert.get('notBefore'),
            'not_after': cert.get('notAfter'),
            'days_until_expiry': days_until_expiry,
            'certificate': cert,
            'final_url': effective_url,
            'redirected': bool(response.history),
        }
    except (ssl.SSLError, OSError, ValueError, requests.RequestException) as e:
        return {'available': False, 'https': True, 'status': 'COULD NOT DETERMINE', 'error': str(e)}
