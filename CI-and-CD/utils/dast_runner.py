import requests
import time
import pandas as pd

ZAP_API_BASE = "http://localhost:8080/JSON"
ZAP_API_KEY = "f1vftpiihhjdn6na5q28svtk8v"  # Optional: Set if ZAP requires authentication

def run_dast(target_url):
    headers = {"Content-Type": "application/json"}
    params = {"apikey": ZAP_API_KEY} if ZAP_API_KEY else {}

    try:
        # Start spider scan
        spider_resp = requests.get(f"{ZAP_API_BASE}/spider/action/scan/", params={**params, "url": target_url})
        spider_resp.raise_for_status()
        spider_scan_id = spider_resp.json().get("scan")

        if not spider_scan_id:
            return {"error": "Failed to initiate spider scan."}

        # Monitor spider scan progress
        while True:
            status_resp = requests.get(f"{ZAP_API_BASE}/spider/view/status/", params={**params, "scanId": spider_scan_id})
            status_resp.raise_for_status()
            if status_resp.json().get("status") == "100":
                break
            time.sleep(3)

        # Start active scan
        active_resp = requests.get(f"{ZAP_API_BASE}/ascan/action/scan/", params={**params, "url": target_url})
        active_resp.raise_for_status()
        active_scan_id = active_resp.json().get("scan")

        if not active_scan_id:
            return {"error": "Failed to initiate active scan."}

        # Monitor active scan progress
        while True:
            active_status = requests.get(f"{ZAP_API_BASE}/ascan/view/status/", params={**params, "scanId": active_scan_id})
            active_status.raise_for_status()
            if active_status.json().get("status") == "100":
                break
            time.sleep(5)

        # Retrieve alerts
        alerts_resp = requests.get(f"{ZAP_API_BASE}/core/view/alerts/", params={**params, "baseurl": target_url})
        alerts_resp.raise_for_status()
        alerts = alerts_resp.json().get("alerts", [])

        if not alerts:
            return pd.DataFrame([{"Message": "No security alerts found by ZAP."}])

        return pd.DataFrame(alerts)

    except requests.RequestException as e:
        return {"error": f"Request to ZAP API failed: {str(e)}"}
    except Exception as e:
        return {"error": f"Unexpected error: {str(e)}"}