import subprocess
import tempfile
import zipfile
import os
import json
import pandas as pd

def check_dependencies(uploaded_file):
    with tempfile.TemporaryDirectory() as temp_dir:
        archive_path = os.path.join(temp_dir, "code.zip")
        with open(archive_path, "wb") as f:
            f.write(uploaded_file.getbuffer())

        with zipfile.ZipFile(archive_path, 'r') as zip_ref:
            zip_ref.extractall(temp_dir)

        requirements_path = os.path.join(temp_dir, "requirements.txt")
        if not os.path.exists(requirements_path):
            return {"error": "No requirements.txt found in archive."}

        output_path = os.path.join(temp_dir, "sca_report.json")
        try:
            subprocess.run([
                "safety", "check", "--full-report", "--file", requirements_path, "--output", "json"
            ], stdout=open(output_path, "w"), check=True)
        except subprocess.CalledProcessError as e:
            return {"error": f"Safety check failed: {str(e)}"}

        if not os.path.exists(output_path):
            return {"error": "Safety did not produce a report."}

        try:
            with open(output_path, "r") as f:
                sca_data = json.load(f)
        except json.JSONDecodeError:
            return {"error": "Failed to parse Safety report."}

        vulns = sca_data.get("vulnerabilities", [])
        if not vulns:
            return pd.DataFrame([{"Message": "No known vulnerabilities found."}])

        return pd.DataFrame(vulns)