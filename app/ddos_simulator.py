import requests
import threading
import time

# Function to simulate normal user traffic
def send_normal_traffic(url, num_requests):
    for _ in range(num_requests):
        response = requests.get(url)
        print(f"Normal Traffic - Status Code: {response.status_code}")
        time.sleep(0.5)  # Simulate normal time interval between requests

# Function to simulate Slowloris attack
def slowloris_attack(url, num_requests):
    for _ in range(num_requests):
        headers = {'User-Agent': 'Mozilla/5.0', 'Connection': 'keep-alive'}
        response = requests.get(url, headers=headers, stream=True)
        print(f"Slowloris Attack - Status Code: {response.status_code}")
        time.sleep(5)  # Simulate slow data transmission

# Function to simulate Hulk attack
def hulk_attack(url, num_requests):
    for _ in range(num_requests):
        response = requests.get(url)
        print(f"Hulk Attack - Status Code: {response.status_code}")

url = 'http://127.0.0.1:5000/'

# Simulate different types of traffic
threads = []

# Simulate normal traffic
for i in range(10):  # 10 threads simulating normal users
    thread = threading.Thread(target=send_normal_traffic, args=(url, 10))
    thread.start()
    threads.append(thread)

# Simulate Slowloris attack
for i in range(5):  # 5 threads simulating a Slowloris attack
    thread = threading.Thread(target=slowloris_attack, args=(url, 1))
    thread.start()
    threads.append(thread)

# Simulate Hulk attack
for i in range(5):  # 5 threads simulating a Hulk attack
    thread = threading.Thread(target=hulk_attack, args=(url, 100))
    thread.start()
    threads.append(thread)

# Wait for all threads to complete
for thread in threads:
    thread.join()
