import os
import requests
from dotenv import load_dotenv

load_dotenv()

def check_abuseipdb(ip: str):
    url =  "https://api.abuseipdb.com/api/v2/check" 

    headers = {
        "Key": os.getenv("ABUSEIPDB_API_KEY"),
        "Accept": "application/json",
    }    

    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90,
    }

    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)
    except requests.RequestException:
        return None

    if response.status_code != 200:
        return None


    data = response.json()["data"]
    return {
        "score": data["abuseConfidenceScore"],
        "reports": data["totalReports"],
        "last_reported": data["lastReportedAt"],
        "country": data["countryCode"],
    }


