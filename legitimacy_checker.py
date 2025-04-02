def calculate_legitimacy_score(email_details, file_scan_results, url_scan_results):
    """
    Calculates the legitimacy score of an email based on various checks.

    Args:
        email_details (dict): Email headers and metadata.
        file_scan_results (list): Results of attachment scans.
        url_scan_results (list): Results of URL scans.

    Returns:
        tuple: (score, verdict)
    """
    score = 100  # Start with a perfect score

    # Deduct points for suspicious/malicious URLs
    for url_result in url_scan_results:
        if url_result["google_safe_browsing"]["status"] == "malicious":
            score -= 30
        if url_result["virustotal"]["status"] == "malicious":
            score -= 30
        if url_result["whois"]["status"] == "error":
            score -= 10  # Deduct points if WHOIS lookup fails
        if url_result.get("http_alert", False):  # Deduct points for http URLs
            score -= 5

    # Deduct points for suspicious/malicious attachments
    for file_result in file_scan_results:
        if file_result["status"] == "malicious":
            score -= 40

    # Deduct points for missing SPF/DKIM/DMARC checks
    if email_details.get("spf", {}).get("status") != "valid":
        score -= 10
    if email_details.get("dkim", {}).get("status") != "valid":
        score -= 10
    if email_details.get("dmarc", {}).get("status") != "valid":
        score -= 10

    # Determine the verdict
    if score >= 80:
        verdict = "Legitimate"
    elif score >= 50:
        verdict = "Suspicious"
    else:
        verdict = "Malicious"

    return score, verdict