import requests
import csv
import io
from helpers import normalize_url  # Import the helper function

PHISHTANK_FEED_URL = "http://data.phishtank.com/data/online-valid.csv"

def check_phishtank(url_to_check):
    try:
        response = requests.get(PHISHTANK_FEED_URL)
        response.raise_for_status()

        csv_data = io.StringIO(response.text)
        reader = csv.DictReader(csv_data)
        
        # Normalize the input URL for accurate comparison
        norm_input = normalize_url(url_to_check)
        
        # Iterate over each row in the CSV feed and check normalized URLs
        for row in reader:
            norm_row_url = normalize_url(row["url"])
            if norm_input == norm_row_url:
                return {
                    "phishing_detected": True,
                    "phish_detail_page": row["phish_detail_url"]
                }
        
        return {"phishing_detected": False}
    except Exception as e:
        return {"phishing_detected": False, "error": str(e)}
