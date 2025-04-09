from flask import Flask, request, jsonify, render_template
from vt_utils import scan_url_virustotal
from enrichment import check_phishtank
from logger import log_scan_result

app = Flask(__name__)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json()
    url = data.get("url")

    if not url:
        return jsonify({"error": "URL is required"}), 400

    try:
        # Get VirusTotal scan results
        vt_result = scan_url_virustotal(url)
        
        # Get PhishTank enrichment result
        pt_result = check_phishtank(url)
        
        # Combine both results into one response
        combined_result = {
            **vt_result,  # Contains fields like 'url', 'malicious', 'suspicious', etc.
            "phishing_detected": pt_result.get("phishing_detected", False),
            "phish_detail_page": pt_result.get("phish_detail_page", None)
        }
        
        # Log the combined result to a CSV file using logger.py;
        # This function converts list fields like "categories" to a string for CSV storage only.
        log_scan_result(combined_result)

        return jsonify(combined_result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True)
