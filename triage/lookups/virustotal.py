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


    try:
        response = requests.get(url, headers=headers, timeout=10)
    except requests.RequestException:
        return None

    if response.status_code != 200:
        return None

    
    attributes = response.json()["data"]["attributes"]
    stats = attributes["last_analysis_stats"]

    return{
        "malicious": stats["malicious"],
        "suspicious": stats["suspicious"],
        "harmless": stats["harmless"],
        "reputation": attributes["reputation"],
    }

def check_hash(hash: str):
    url = f"https://www.virustotal.com/api/v3/files/{hash}"

    headers = {
        "x-apikey": os.getenv("VIRUSTOTAL_API_KEY"),
    }

    try:
        response = requests.get(url, headers=headers, timeout=10)
    except requests.RequestException:
        return None

    attributes = response.json()["data"]["attributes"]
    stats = attributes["last_analysis_stats"]

    return {
        "malicious": stats["malicious"],
        "suspicious": stats["suspicious"],
        "harmless": stats["harmless"],
        "reputation": attributes["reputation"],
    }