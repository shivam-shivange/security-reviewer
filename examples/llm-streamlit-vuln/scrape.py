import json

import requests


def scrape(url: str) -> None:
    page = requests.get(url, timeout=10).text
    with open("kb.json", "w") as f:
        json.dump([{"text": page}], f)
