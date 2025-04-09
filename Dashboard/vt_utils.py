# vt_utils.py
# vt_utils.py
import requests
import yaml
import os

# Load YAML config from root project folder
def load_api_key():
    config_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "../config.yaml"))
    with open(config_path, "r") as f:
        config = yaml.safe_load(f)
    return config["virustotal"]["api_key"]

VT_API_KEY = load_api_key()

def scan_url_virustotal(url):
    headers = {
        "x-apikey": VT_API_KEY
    }

    params = {"url": url}
    scan_resp = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data=params)
    scan_resp.raise_for_status()

    scan_id = scan_resp.json()["data"]["id"]
    url_id = scan_id.split('-')[1]

    report_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    report_resp = requests.get(report_url, headers=headers)
    report_resp.raise_for_status()

    report = report_resp.json()

    stats = report["data"]["attributes"]["last_analysis_stats"]
    categories = report["data"]["attributes"].get("categories", {})
    full_report_url = f"https://www.virustotal.com/gui/url/{url_id}"

    return {
        "url": url,
        "malicious": stats["malicious"],
        "suspicious": stats["suspicious"],
        "harmless": stats["harmless"],
        "undetected": stats["undetected"],
        "categories": list(categories.values()),
        "report_link": full_report_url
    }
