from url_checker import check_url

def analyze_email_headers(email_file):
    """
    Analyzes the email file and extracts relevant information such as sender, subject, date, URLs, and attachments.

    Args:
        email_file (str): Path to the email file.

    Returns:
        dict: A dictionary containing the extracted information.
    """
    import email
    from email import policy
    from email.parser import BytesParser
    import re

    # Parse the email file
    with open(email_file, 'rb') as f:
        msg = BytesParser(policy=policy.default).parse(f)

    # Extract relevant information
    sender = msg['from']
    subject = msg['subject']
    date = msg['date']
    urls = []

    # Extract URLs from the plain text body if available
    if msg.get_body(preferencelist=('plain')):
        body_content = msg.get_body(preferencelist=('plain')).get_content()
        urls = re.findall(r'https?://[^\s]+', body_content)

    # Perform URL checks
    url_scan_results = [check_url(url) for url in urls]

    # Create a dictionary to hold the extracted information
    email_details = {
        'sender': sender,
        'subject': subject,
        'date': date,
        'urls': url_scan_results,
        'attachments': []
    }

    return email_details