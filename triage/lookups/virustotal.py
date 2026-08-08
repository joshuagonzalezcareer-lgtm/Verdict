import os
import dotenv
import requests
from dotenv import load_dotenv

load_dotenv()

def check_virustotal(ip: str):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"

    headers = {
        "x-apikey": os.getenv("VIRUSTOTAL_API_KEY"),
    }

    response = requests.get(url, headers=headers, timeout=10)
    return response.json()