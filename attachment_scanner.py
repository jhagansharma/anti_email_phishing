import os
import mimetypes
import hashlib

def scan_attachment(attachments):
    results = []
    for attachment in attachments:
        file_path = attachment.get("file_path")
        if not os.path.exists(file_path):
            results.append({"file_name": attachment.get("file_name"), "status": "File not found"})
            continue
        
        file_type = mimetypes.guess_type(file_path)[0]
        if file_type and file_type.startswith("image/"):
            results.append({"file_name": attachment.get("file_name"), "status": "Safe", "file_type": file_type})
        else:
            file_hash = hash_file(file_path)
            if is_malicious(file_hash):
                results.append({"file_name": attachment.get("file_name"), "status": "Malicious", "file_type": file_type})
            else:
                results.append({"file_name": attachment.get("file_name"), "status": "Safe", "file_type": file_type})
    
    return results

def hash_file(file_path):
    hasher = hashlib.sha256()
    with open(file_path, 'rb') as f:
        while chunk := f.read(8192):
            hasher.update(chunk)
    return hasher.hexdigest()

def is_malicious(file_hash):
    # Placeholder for actual malicious file hash checking logic
    malicious_hashes = set()  # This should be populated with known malicious file hashes
    return file_hash in malicious_hashes