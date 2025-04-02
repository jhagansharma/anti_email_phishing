import requests
import base64
import whois

def check_google_safe_browsing(api_key, url):
    """
    Checks if a URL is safe using Google Safe Browsing API.

    Args:
        api_key (str): Your Google Safe Browsing API key.
        url (str): The URL to check.

    Returns:
        dict: The result of the Safe Browsing check.
    """
    endpoint = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
    payload = {
        "client": {
            "clientId": "email-analysis-tool",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    try:
        response = requests.post(endpoint, params={"key": api_key}, json=payload)
        if response.status_code == 200:
            data = response.json()
            if "matches" in data:
                return {"url": url, "status": "malicious", "details": data["matches"]}
            else:
                return {"url": url, "status": "safe", "details": "No threats found"}
        else:
            return {"url": url, "status": "error", "details": f"HTTP {response.status_code}: {response.text}"}
    except requests.exceptions.RequestException as e:
        return {"url": url, "status": "error", "details": str(e)}

def check_virustotal(api_key, url):
    """
    Checks if a URL is safe using VirusTotal API.

    Args:
        api_key (str): Your VirusTotal API key.
        url (str): The URL to check.

    Returns:
        dict: The result of the VirusTotal check.
    """
    endpoint = "https://www.virustotal.com/api/v3/urls"
    headers = {"x-apikey": api_key}
    try:
        # Encode the URL in base64 format as required by VirusTotal
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        response = requests.get(f"{endpoint}/{url_id}", headers=headers)
        if response.status_code == 200:
            data = response.json()
            malicious_count = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0)
            if malicious_count > 0:
                return {"url": url, "status": "malicious", "details": data}
            else:
                return {"url": url, "status": "safe", "details": "No threats found"}
        else:
            return {"url": url, "status": "error", "details": f"HTTP {response.status_code}: {response.text}"}
    except requests.exceptions.RequestException as e:
        return {"url": url, "status": "error", "details": str(e)}

def check_whois(domain):
    """
    Checks WHOIS information for a domain.

    Args:
        domain (str): The domain to check.

    Returns:
        dict: The WHOIS information.
    """
    try:
        domain_info = whois.whois(domain)
        return {
            "status": "success",
            "details": {
                "domain_name": domain_info.domain_name,
                "creation_date": domain_info.creation_date,
                "expiration_date": domain_info.expiration_date,
                "registrar": domain_info.registrar,
                "name_servers": domain_info.name_servers
            }
        }
    except Exception as e:
        return {"status": "error", "details": str(e)}

#google_safe_browsing_api_key = "AIzaSyAEbX6GWerpUR1VARYIMgd663dGPtJCI40"  # Replace with your actual Google Safe Browsing API key
 #   virustotal_api_key = "49668fd76de995874d5bae3ed9306db5b571f26bb9f676f4e4c22a30c281ca53"  # Replace with your actual VirusTotal API key

def check_url(url):
    """
    Checks if a URL is safe or malicious using Google Safe Browsing API, VirusTotal API, and WHOIS.

    Args:
        url (str): The URL to check.

    Returns:
        dict: A dictionary containing the URL, its status, and additional details.
    """
    google_safe_browsing_api_key = "AIzaSyAEbX6GWerpUR1VARYIMgd663dGPtJCI40"  # Replace with your actual API key
    virustotal_api_key = "49668fd76de995874d5bae3ed9306db5b571f26bb9f676f4e4c22a30c281ca53"  
    # Initialize the result dictionary
    result = {
        "url": url,
        "google_safe_browsing": {"status": "error", "details": "Not checked"},
        "virustotal": {"status": "error", "details": "Not checked"},
        "whois": {"status": "error", "details": "Not checked"}
    }

    # Check the URL using Google Safe Browsing API
    try:
        google_result = check_google_safe_browsing(google_safe_browsing_api_key, url)
        result["google_safe_browsing"] = google_result
    except Exception as e:
        result["google_safe_browsing"] = {"status": "error", "details": str(e)}

    # Check the URL using VirusTotal API
    try:
        virustotal_result = check_virustotal(virustotal_api_key, url)
        result["virustotal"] = virustotal_result
    except Exception as e:
        result["virustotal"] = {"status": "error", "details": str(e)}

    # Perform WHOIS lookup
    try:
        domain = url.split("//")[-1].split("/")[0]
        whois_result = check_whois(domain)
        result["whois"] = whois_result
    except Exception as e:
        result["whois"] = {"status": "error", "details": str(e)}

    return result