import requests
import argparse
import time
import yaml

VT_API_URL = "https://www.virustotal.com/api/v3"

def load_config(path="config.yaml"):
    with open(path, "r") as f:
        return yaml.safe_load(f)

def enrich_ioc(ioc, api_key):
    headers = {
        "x-apikey": api_key
    }
    for ioc_type in ["ip_addresses", "domains", "files", "urls"]:
        url = f"{VT_API_URL}/{ioc_type}/{ioc}"
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            print(f"[+] {ioc} | Type: {ioc_type}")
            print(f"    Reputation: {data['data']['attributes'].get('reputation', 'N/A')}")
            return
    print(f"[-] No result for {ioc}")

def main():
    parser = argparse.ArgumentParser(description="Enrich IOCs using VirusTotal")
    parser.add_argument("-i", "--input", required=True, help="Path to input file with IOCs")
    args = parser.parse_args()

    config = load_config()
    api_key = config.get("virustotal_api_key")

    with open(args.input, "r") as f:
        iocs = [line.strip() for line in f if line.strip()]

    for ioc in iocs:
        enrich_ioc(ioc, api_key)
        time.sleep(15)  # Free API rate limit: 4 req/min

if __name__ == "__main__":
    main()
