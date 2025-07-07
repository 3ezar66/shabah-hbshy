import requests
from bs4 import BeautifulSoup

def get_user_agent():
    user_agents = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 11_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.2 Safari/604.1'
    ]
    return requests.random_user_agent(user_agents)

def get_headers():
    headers = {
        'User-Agent': get_user_agent(),
        'Accept': '*/*',
        'Connection': 'close'
    }
    return headers

def send_request(url, data=None):
    try:
        response = requests.post(url, headers=get_headers(), data=data)
        if response.status_code == 200:
            print('OK')
            return True
        else:
            print(f'Error: {response.status_code}')
            return False
    except Exception as e:
        print(e)
        return False

def get_config():
    try:
        with open('/etc/config.txt', 'r') as f:
            config = f.read()
            if not config:
                # تنظیماتdefault را در caseی absenceConfig می گیریم
                return {
                    'proxy': None,
                    'blocked_ips': [],
                    'blocked_ports': []
                }
            else:
                return eval(config)
    except Exception as e:
        print(e)

def block_config():
    try:
        config = get_config()
        if not config['proxy']:
            # تنظیماتdefault را در caseی absenceProxy می گیریم
            proxy_url = 'http://127.0.0.1:8080'
            with open('/etc/config.txt', 'w') as f:
                f.write(str({
                    'proxy': proxy_url,
                    'blocked_ips': config['blocked_ips'],
                    'blocked_ports': config['blocked_ports']
                }))
        else:
            # تنظیمات existingProxy را در caseی absenceConfig می گیریم
            with open('/etc/config.txt', 'w') as f:
                f.write(str(config))
    except Exception as e:
        print(e)

def main():
    url = 'http://example.com'
    data = {'key': 'value'}
    block_config()
    send_request(url, data)