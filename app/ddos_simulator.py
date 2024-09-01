import requests
import threading

def send_requests(url, num_requests):
    for _ in range(num_requests):
        response = requests.get(url)
        print(f"Status Code: {response.status_code}")

url = 'http://127.0.0.1:5000/'

# Simula múltiplas requisições simultâneas
threads = []
for i in range(100):  # 100 threads simulando múltiplas requisições
    thread = threading.Thread(target=send_requests, args=(url, 100))
    thread.start()
    threads.append(thread)

for thread in threads:
    thread.join()
