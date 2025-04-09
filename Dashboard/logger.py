import csv
import os
from datetime import datetime

def log_scan_result(scan_result, file_path="scan_history.csv"):
    """
    Appends a new scan result to a CSV file.
    The CSV will have the following fields:
      - timestamp, url, malicious, suspicious, harmless, undetected, categories, report_link, phishing_detected, phish_detail_page
    """
    header = [
        "timestamp", "url", "malicious", "suspicious", "harmless", "undetected", 
        "categories", "report_link", "phishing_detected", "phish_detail_page"
    ]
    
    file_exists = os.path.isfile(file_path)
    with open(file_path, mode="a", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=header)
        if not file_exists:
            writer.writeheader()
            
        # Create a copy of scan_result for CSV storage.
        csv_row = scan_result.copy()  
        # Convert categories into a string for CSV logging, if needed.
        if isinstance(csv_row.get("categories"), list):
            csv_row["categories"] = ", ".join(csv_row["categories"])
        
        # Add a timestamp for the scan.
        csv_row["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        writer.writerow(csv_row)
