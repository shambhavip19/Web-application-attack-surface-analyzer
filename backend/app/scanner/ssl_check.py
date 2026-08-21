import ssl, socket
from urllib.parse import urlparse

def check_ssl(url, timeout=10):
    try:
        p = urlparse(url)
        host = p.hostname
        port = p.port or (443 if p.scheme == 'https' else 80)
        if p.scheme != 'https':
            return {'available': False, 'https': False, 'note': 'Non-HTTPS URL'}
        ctx = ssl.create_default_context()
        conn = ctx.wrap_socket(socket.socket(socket.AF_INET), server_hostname=host)
        conn.settimeout(timeout)
        conn.connect((host, port))
        cert = conn.getpeercert()
        conn.close()
        return {'available': True, 'https': True, 'certificate': cert}
    except Exception as e:
        return {'available': False, 'https': True, 'error': str(e)}
