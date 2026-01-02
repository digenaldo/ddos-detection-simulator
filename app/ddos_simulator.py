"""
DDoS traffic simulator for testing the detection system.
"""
import requests
import threading
import time
import logging
from typing import Callable
from urllib.parse import urljoin

from config.settings import Config

# Logging configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def send_normal_traffic(url: str, num_requests: int, delay: float = 0.5) -> None:
    """
    Simulate normal user traffic.
    
    Args:
        url: Server URL
        num_requests: Number of requests to send
        delay: Delay between requests in seconds
    """
    for i in range(num_requests):
        try:
            response = requests.get(url, timeout=5)
            logger.debug(f"Normal Traffic - Status: {response.status_code}")
        except requests.exceptions.RequestException as e:
            logger.warning(f"Error sending normal request: {e}")
        time.sleep(delay)


def slowloris_attack(url: str, num_requests: int, delay: float = 5.0) -> None:
    """
    Simulate Slowloris attack (keeps connections open).
    
    Args:
        url: Server URL
        num_requests: Number of connections to keep
        delay: Delay between data sends
    """
    for i in range(num_requests):
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0',
                'Connection': 'keep-alive'
            }
            response = requests.get(url, headers=headers, stream=True, timeout=30)
            logger.debug(f"Slowloris Attack - Status: {response.status_code}")
            time.sleep(delay)
        except requests.exceptions.RequestException as e:
            logger.warning(f"Error in Slowloris attack: {e}")


def hulk_attack(url: str, num_requests: int) -> None:
    """
    Simulate Hulk attack (fast and repetitive requests).
    
    Args:
        url: Server URL
        num_requests: Number of requests to send
    """
    for i in range(num_requests):
        try:
            response = requests.get(url, timeout=5)
            logger.debug(f"Hulk Attack - Status: {response.status_code}")
        except requests.exceptions.RequestException as e:
            logger.warning(f"Error in Hulk attack: {e}")


def run_simulation(
    base_url: str,
    normal_threads: int = 10,
    normal_requests: int = 10,
    slowloris_threads: int = 5,
    slowloris_requests: int = 1,
    hulk_threads: int = 5,
    hulk_requests: int = 100
) -> None:
    """
    Run complete traffic simulation.
    
    Args:
        base_url: Base server URL
        normal_threads: Number of normal traffic threads
        normal_requests: Requests per normal thread
        slowloris_threads: Number of Slowloris threads
        slowloris_requests: Requests per Slowloris thread
        hulk_threads: Number of Hulk threads
        hulk_requests: Requests per Hulk thread
    """
    url = urljoin(base_url, '/')
    threads: list[threading.Thread] = []
    
    logger.info("=" * 60)
    logger.info("Starting DDoS traffic simulation")
    logger.info(f"Target URL: {url}")
    logger.info(f"Normal Traffic: {normal_threads} threads, {normal_requests} req/thread")
    logger.info(f"Slowloris: {slowloris_threads} threads, {slowloris_requests} req/thread")
    logger.info(f"Hulk: {hulk_threads} threads, {hulk_requests} req/thread")
    logger.info("=" * 60)
    
    # Normal traffic
    for i in range(normal_threads):
        thread = threading.Thread(
            target=send_normal_traffic,
            args=(url, normal_requests),
            name=f"Normal-{i}"
        )
        thread.start()
        threads.append(thread)
    
    # Slowloris attack
    for i in range(slowloris_threads):
        thread = threading.Thread(
            target=slowloris_attack,
            args=(url, slowloris_requests),
            name=f"Slowloris-{i}"
        )
        thread.start()
        threads.append(thread)
    
    # Hulk attack
    for i in range(hulk_threads):
        thread = threading.Thread(
            target=hulk_attack,
            args=(url, hulk_requests),
            name=f"Hulk-{i}"
        )
        thread.start()
        threads.append(thread)
    
    # Wait for all threads
    logger.info("Waiting for all threads to complete...")
    for thread in threads:
        thread.join()
    
    logger.info("Simulation completed!")


if __name__ == '__main__':
    base_url = f"http://{Config.FLASK_HOST}:{Config.FLASK_PORT}"
    
    run_simulation(
        base_url=base_url,
        normal_threads=10,
        normal_requests=10,
        slowloris_threads=5,
        slowloris_requests=1,
        hulk_threads=5,
        hulk_requests=100
    )
