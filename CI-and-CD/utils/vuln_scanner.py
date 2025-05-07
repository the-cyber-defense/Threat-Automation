import subprocess
import pandas as pd
import json
import tempfile
import os

def scan_image(image_name):
    with tempfile.TemporaryDirectory() as temp_dir:
        output_path = os.path.join(temp_dir, "trivy_report.json")

        try:
            subprocess.run([
                "trivy", "image", "--format", "json", "--output", output_path, image_name
            ], check=True)
        except subprocess.CalledProcessError as e:
            return {"error": f"Trivy scan failed: {str(e)}"}

        if not os.path.exists(output_path):
            return {"error": "Trivy did not produce output."}

        try:
            with open(output_path, "r") as f:
                trivy_data = json.load(f)
        except json.JSONDecodeError:
            return {"error": "Failed to parse Trivy JSON output."}

        vulns = []
        for result in trivy_data.get("Results", []):
            target = result.get("Target")
            for vuln in result.get("Vulnerabilities", []):
                vulns.append({
                    "Target": target,
                    "VulnerabilityID": vuln.get("VulnerabilityID"),
                    "PkgName": vuln.get("PkgName"),
                    "InstalledVersion": vuln.get("InstalledVersion"),
                    "FixedVersion": vuln.get("FixedVersion"),
                    "Severity": vuln.get("Severity"),
                    "Title": vuln.get("Title"),
                    "Description": vuln.get("Description")
                })

        if not vulns:
            return pd.DataFrame([{"Message": "No vulnerabilities found."}])

        return pd.DataFrame(vulns)
