# anti_email_phishing
Anti-Email Phishing Tool

Overview :

The Anti-Email Phishing Tool is a command-line application designed to analyze emails and detect potential phishing attempts. It validates email security mechanisms, scans attachments, inspects URLs, and tracks real-time Gmail activity using Google APIs.

Features :

Attachment Scanning: Checks for malicious files in email attachments.

URL Analysis: Inspects embedded URLs for phishing threats.

SPF, DKIM, and DMARC Verification: Ensures email authentication mechanisms are properly configured.

Sender Legitimacy Check: Evaluates the trustworthiness of the email sender.

Google Login API Integration: Uses OAuth for secure authentication.

Real-Time Gmail Activity Monitoring: Tracks incoming and outgoing emails for suspicious activity.

Technologies Used :

Python

SQLite (for storing email analysis results)

Google APIs (for Gmail integration and OAuth authentication)

Regex & URL Parsing (for URL inspection)


Usage

Authenticate using Google Login.

Analyze emails using:

real-time scan the email inbox

View detailed phishing analysis and reports.
