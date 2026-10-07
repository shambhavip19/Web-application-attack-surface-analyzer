import ssl
import socket
from urllib.parse import urlparse

def check_ssl(url, timeout=10):
    try:
        p = urlparse(url)
        host = p.hostname
        port = p.port or (443 if p.scheme == 'https' else 80)
        if not host:
            return {'available': False, 'https': None, 'status': 'Could Not Determine', 'error': 'URL has no hostname'}
        if p.scheme != 'https':
            return {'available': True, 'https': False, 'status': 'Not Detected', 'note': 'The website is using HTTP, so an encrypted certificate cannot be checked.'}
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as raw_conn:
            with ctx.wrap_socket(raw_conn, server_hostname=host) as conn:
                cert = conn.getpeercert()
        return {'available': True, 'https': True, 'status': 'Detected', 'certificate': cert}
    except (ssl.SSLError, OSError, ValueError) as e:
        return {'available': False, 'https': True, 'status': 'Could Not Determine', 'error': str(e)}
