import subprocess
import tempfile
import zipfile
import os
import json
import pandas as pd

def run_sast(uploaded_file):
    with tempfile.TemporaryDirectory() as temp_dir:
        archive_path = os.path.join(temp_dir, "uploaded_code.zip")
        with open(archive_path, "wb") as f:
            f.write(uploaded_file.getbuffer())

        with zipfile.ZipFile(archive_path, 'r') as zip_ref:
            zip_ref.extractall(temp_dir)

        report_path = os.path.join(temp_dir, "bandit_report.json")

        result = subprocess.run([
            "bandit", "-q", "-r", temp_dir, "-f", "json", "-o", report_path
        ], capture_output=True)

        if result.returncode != 0:
            return {"error": f"Bandit exited with error:\n{result.stderr.decode()}"}

        if not os.path.exists(report_path):
            return {"error": "Bandit didn't generate a report."}

        with open(report_path, "r") as report_file:
            try:
                bandit_results = json.load(report_file)
                issues = bandit_results.get("results", [])
            except json.JSONDecodeError as e:
                return {"error": f"Error parsing Bandit JSON: {str(e)}"}

        if not issues:
            return pd.DataFrame([{"Message": "No issues found by Bandit."}])

        return pd.json_normalize(issues)
