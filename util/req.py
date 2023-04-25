import requests

try:
    response = requests.get('http://127.0.0.1:8080/', timeout=5)
    print(response.content)
except requests.exceptions.Timeout:
    print('Timeout error occurred.')
except requests.exceptions.RequestException as e:
    print('An error occurred:', e)
