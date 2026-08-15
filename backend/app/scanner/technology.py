import requests
from bs4 import BeautifulSoup

def detect(url, timeout=10):
    try:
        r = requests.get(url, timeout=timeout)
        tech = {}
        server = r.headers.get('server')
        if server:
            tech['server'] = server
        powered = r.headers.get('x-powered-by')
        if powered:
            tech['x-powered-by'] = powered
        soup = BeautifulSoup(r.text, 'html.parser')
        if soup.find('meta', attrs={'name': 'generator'}):
            tech['generator'] = soup.find('meta', attrs={'name': 'generator'}).get('content')
        return tech
    except Exception as e:
        return {'error': str(e)}
