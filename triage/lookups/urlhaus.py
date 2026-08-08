import os
import requests
from dotenv import load_dotenv

load_dotenv()

def check_urlhaus(host: str):
    url = "https://urlhaus-api.abuse.ch/v1/host/"

    headers = {
        "Auth-Key": os.getenv("URLHAUS_AUTH_KEY"),
    }

    data = {
        "host": host,
    }

    try:
        response = requests.post(url, headers=headers, data=data, timeout=10)
    except requests.RequestException:
        return None

    result = response.json()

    if result["query_status"] != "ok":
        return None

    urls = result["urls"]
    first = urls[0]

    return {
        "url_count": result["url_count"],
        "threat": first["threat"],
        "tags": first["tags"],
    }
