import os
import json
import sqlite3
import time
import re
import dns.resolver
from email_analyzer import analyze_email_headers
from attachment_scanner import scan_attachment
from url_checker import check_url
from legitimacy_checker import calculate_legitimacy_score
from google_auth import authenticate_user
from googleapiclient.discovery import build
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from url_checker import check_url

def setup_database():
    conn = sqlite3.connect("phishing_reports.db")
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS reports (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        email TEXT,
                        score INTEGER,
                        verdict TEXT,
                        details TEXT)''')
    conn.commit()
    conn.close()

def save_report(email, score, verdict, details):
    """
    Saves the phishing report to the database.

    Args:
        email (str): Email ID or unique identifier.
        score (int): Legitimacy score of the email.
        verdict (str): Verdict (Legitimate, Suspicious, Malicious).
        details (dict): Detailed analysis of the email.
    """
    # Convert datetime objects to strings for JSON serialization
    def convert_datetime(obj):
        if isinstance(obj, datetime.datetime):
            return obj.isoformat()
        raise TypeError(f"Type {type(obj)} not serializable")

    conn = sqlite3.connect("phishing_reports.db")
    cursor = conn.cursor()
    cursor.execute("INSERT INTO reports (email, score, verdict, details) VALUES (?, ?, ?, ?)",
                   (email, score, verdict, json.dumps(details, default=convert_datetime)))
    conn.commit()
    conn.close()

def check_spf(domain):
    try:
        answers = dns.resolver.resolve(f"{domain}", "TXT")
        for rdata in answers:
            if "v=spf1" in str(rdata):
                return {"spf": "valid", "details": str(rdata)}
        return {"spf": "missing", "details": None}
    except Exception as e:
        return {"spf": "error", "details": str(e)}

def check_dkim(domain):
    try:
        selector = "default"  # Replace with the DKIM selector if known
        dkim_record = f"{selector}._domainkey.{domain}"
        answers = dns.resolver.resolve(dkim_record, "TXT")
        for rdata in answers:
            return {"dkim": "valid", "details": str(rdata)}
        return {"dkim": "missing", "details": None}
    except Exception as e:
        return {"dkim": "error", "details": str(e)}

def check_dmarc(domain):
    try:
        dmarc_record = f"_dmarc.{domain}"
        answers = dns.resolver.resolve(dmarc_record, "TXT")
        for rdata in answers:
            return {"dmarc": "valid", "details": str(rdata)}
        return {"dmarc": "missing", "details": None}
    except Exception as e:
        return {"dmarc": "error", "details": str(e)}

def check_email_provider(domain):
    disposable_domains = ["mailinator.com", "10minutemail.com", "guerrillamail.com"]
    free_email_providers = ["gmail.com", "yahoo.com", "outlook.com"]

    if domain in disposable_domains:
        return {"provider": "disposable", "details": domain}
    elif domain in free_email_providers:
        return {"provider": "free", "details": domain}
    else:
        return {"provider": "custom", "details": domain}

def get_gmail_service():
    creds = None
    token_path = os.path.join(os.path.dirname(__file__), "token.json")
    print(f"Looking for token.json at: {token_path}")
    if os.path.exists(token_path):
        print(f"token.json found at: {token_path}")
        try:
            creds = Credentials.from_authorized_user_file(token_path, scopes=["https://www.googleapis.com/auth/gmail.readonly"])
        except Exception as e:
            print(f"Error reading token.json: {e}")
            print("Deleting corrupted token.json file. Please re-authenticate.")
            os.remove(token_path)
            return None
    else:
        print("token.json not found. Please authenticate.")
        return None
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            print("Authentication required. Run Google OAuth process.")
            return None
    return build("gmail", "v1", credentials=creds)

def save_report(email, score, verdict, details):
    # Only save emails that are suspicious or malicious
    if verdict in ["Suspicious", "Malicious"]:
        conn = sqlite3.connect("phishing_reports.db")
        cursor = conn.cursor()
        cursor.execute("INSERT INTO reports (email, score, verdict, details) VALUES (?, ?, ?, ?)",
                       (email, score, verdict, json.dumps(details)))
        conn.commit()
        conn.close()

def query_database():
    conn = sqlite3.connect("phishing_reports.db")
    cursor = conn.cursor()
    cursor.execute("SELECT id, email, score, verdict, details FROM reports")
    rows = cursor.fetchall()
    conn.close()

    if rows:
        print("\nStored Reports:")
        print("----------------------------------------")
        for row in rows:
            print(f"ID: {row[0]}")
            print(f"Email: {row[1]}")
            print(f"Score: {row[2]}")
            print(f"Verdict: {row[3]}")
            print(f"Details: {row[4]}")
            print("----------------------------------------")
    else:
        print("\nNo reports found in the database.")

import re  # Import regex for URL extraction

def extract_urls_from_email(email_body):
    """
    Extracts all URLs from the email body using regex.

    Args:
        email_body (str): The body content of the email.

    Returns:
        list: A list of extracted URLs.
    """
    # Regex pattern to match URLs
    url_pattern = r'(https?://[^\s]+)'
    urls = re.findall(url_pattern, email_body)
    return urls


def track_real_time_gmail():
    service = get_gmail_service()
    if not service:
        return
    
    print("Tracking real-time Gmail activity...")
    try:
        while True:
            results = service.users().messages().list(userId="me", labelIds=["INBOX"], maxResults=5).execute()
            messages = results.get("messages", [])
            
            if not messages:
                print("\nNo new emails found.")
            else:
                for msg in messages:
                    msg_details = service.users().messages().get(userId="me", id=msg["id"]).execute()
                    headers = msg_details.get("payload", {}).get("headers", [])
                    body = msg_details.get("snippet", "")  # Extract the email snippet (body preview)
                    
                    # Extract email details
                    email_details = {header["name"]: header["value"] for header in headers if "name" in header and "value" in header}
                    from_email = email_details.get("From", "N/A")
                    subject = email_details.get("Subject", "N/A")
                    date = email_details.get("Date", "N/A")
                    
                    # Clean up the 'From' email address
                    if "<" in from_email and ">" in from_email:
                        from_email = from_email.split("<")[-1].strip(">")
                    
                    domain = from_email.split("@")[-1] if "@" in from_email else "N/A"
                    
                    # Perform checks
                    spf_result = check_spf(domain)
                    dkim_result = check_dkim(domain)
                    dmarc_result = check_dmarc(domain)
                    provider_result = check_email_provider(domain)
                    
                    # Display email details
                    print("\n----------------------------------------")
                    print(f"Subject: {subject}")
                    print(f"From: {from_email}")
                    print(f"Date: {date}")
                    print(f"Domain: {domain}")
                    print("\nSPF/DKIM/DMARC Checks:")
                    print(f"- SPF: {spf_result.get('spf', 'N/A')} ({spf_result.get('details', 'N/A')})")
                    print(f"- DKIM: {dkim_result.get('dkim', 'N/A')} ({dkim_result.get('details', 'N/A')})")
                    print(f"- DMARC: {dmarc_result.get('dmarc', 'N/A')} ({dmarc_result.get('details', 'N/A')})")
                    print(f"Email Provider: {provider_result.get('provider', 'N/A')} ({provider_result.get('details', 'N/A')})")
                    
                    # Extract URLs from the email body
                    # Extract URLs from the email body
                    urls = extract_urls_from_email(body)
                    print("\nURLs:")
                    url_scan_results = []
                    if urls:
                        for url in urls:
                            print(f"- Checking URL: {url}")
                            http_alert = url.startswith("http://")
                            if http_alert:
                                print(f"  ALERT: URL uses unencrypted HTTP protocol: {url}")
                            url_result = check_url(url)
                            url_result["http_alert"] = http_alert  # Add the http_alert flag
                            url_scan_results.append(url_result)
                            print(f"  Google Safe Browsing: {url_result.get('google_safe_browsing', {}).get('status', 'N/A')}")
                            print(f"  VirusTotal: {url_result.get('virustotal', {}).get('status', 'N/A')}")
                            print(f"  WHOIS: {url_result.get('whois', {}).get('status', 'N/A')}")
                    else:
                        print("None")
                    
                    # Process attachments
                    print("\nAttachments:")
                    file_scan_results = scan_attachment(email_details.get("attachments", []))
                    if file_scan_results:
                        for file_result in file_scan_results:
                            print(f"- {file_result.get('file_name', 'Unknown')}: {file_result.get('status', 'Unknown')}")
                    else:
                        print("None")
                    
                    # Calculate legitimacy score
                    score, verdict = calculate_legitimacy_score(email_details, file_scan_results, url_scan_results)
                    print(f"\nLegitimacy Verdict: {verdict} (Score: {score})")
                    print("----------------------------------------")
                    
                    # Save the report
                    save_report(msg["id"], score, verdict, {
                        "headers": email_details,
                        "files": file_scan_results,
                        "urls": url_scan_results,
                        "spf": spf_result,
                        "dkim": dkim_result,
                        "dmarc": dmarc_result,
                        "provider": provider_result
                    })
            
            # Wait for 60 seconds before checking for new emails
            time.sleep(60)
    except KeyboardInterrupt:
        print("\nReal-time Gmail tracking stopped by user.")


def main():
    print("Authenticating user with Google...")
    user = authenticate_user()
    if not user:
        print("Authentication failed. Exiting.")
        return
    
    choice = input("Choose an option:\n1. Scan an email file\n2. Track real-time Gmail\n3. View stored reports\nEnter choice: ")
    
    if choice == "1":
        email_file = input("Enter the path of the email file: ")
        if not os.path.exists(email_file):
            print("File not found. Exiting.")
            return
        print("Analyzing email headers...")
        email_details = analyze_email_headers(email_file)
        print("Checking attached files...")
        file_scan_results = scan_attachment(email_details.get("attachments", []))
        print("Checking URLs...")
        url_scan_results = [check_url(url) for url in email_details.get("urls", [])]
        print("Calculating legitimacy score...")
        score, verdict = calculate_legitimacy_score(email_details, file_scan_results, url_scan_results)
        print(f"Final Verdict: {verdict} (Score: {score})")
        save_report(email_file, score, verdict, {
            "headers": email_details,
            "files": file_scan_results,
            "urls": url_scan_results
        })
    elif choice == "2":
        track_real_time_gmail()
    elif choice == "3":
        query_database()
    else:
        print("Invalid choice. Exiting.")
    
if __name__ == "__main__":
    setup_database()
    main()