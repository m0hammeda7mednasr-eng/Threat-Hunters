import os
import random
import httpx
from .utils import log

PACKAGE_DIR = os.path.dirname(os.path.abspath(__file__))
PROXY_FILE = os.getenv("SCANNER_PROXY_FILE", os.path.join(PACKAGE_DIR, "proxies.txt"))
PROXIES = []

def load_proxies():
    global PROXIES
    if os.path.exists(PROXY_FILE):
        with open(PROXY_FILE, "r") as f:
            PROXIES = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        log.info(f"[proxy_manager] Loaded {len(PROXIES)} proxies.")
    else:
        log.debug(f"[proxy_manager] {PROXY_FILE} not found. Running without proxies.")

def get_random_proxy() -> str | None:
    if not PROXIES:
        return None
    return random.choice(PROXIES)

def get_client(**kwargs) -> httpx.AsyncClient:
    proxy = get_random_proxy()
    if proxy:
        if not proxy.startswith("http"):
            proxy = f"http://{proxy}"
        
        kwargs["proxy"] = proxy
    return httpx.AsyncClient(**kwargs)


load_proxies()

