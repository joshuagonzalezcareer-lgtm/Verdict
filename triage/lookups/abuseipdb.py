def check_abuseipdb(ip: str):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": os.getenv("ABUSEIPDB_API_KEY"),
        "Accept": "application/json",
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90,
    }

    response = requests.get(url, headers=headers, params=params)
    return response.json()