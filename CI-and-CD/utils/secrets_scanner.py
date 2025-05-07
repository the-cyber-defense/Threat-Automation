import subprocess
import tempfile
import zipfile
import os
import json
import pandas as pd

def scan_codebase(uploaded_file):
    with tempfile.TemporaryDirectory() as temp_dir:
        archive_path = os.path.join(temp_dir, "code.zip")
        with open(archive_path, "wb") as f:
            f.write(uploaded_file.getbuffer())

        with zipfile.ZipFile(archive_path, 'r') as zip_ref:
            zip_ref.extractall(temp_dir)

        secrets_output_path = os.path.join(temp_dir, "secrets.json")
        
        try:
            with open(secrets_output_path, "w") as outfile:
                subprocess.run([
                    "detect-secrets", "scan", "--all-files", "--format", "json", temp_dir
                ], cwd=temp_dir, stdout=outfile, check=True)
        except subprocess.CalledProcessError as e:
            return {"error": f"detect-secrets scan failed: {str(e)}"}

        if not os.path.exists(secrets_output_path):
            return {"error": "detect-secrets did not produce output."}

        try:
            with open(secrets_output_path, "r") as f:
                secrets_json = json.load(f)
        except json.JSONDecodeError:
            return {"error": "Failed to parse secrets JSON output."}

        records = []
        for file, issues in secrets_json.get("results", {}).items():
            for issue in issues:
                record = {
                    "File": file,
                    "Type": issue.get("type"),
                    "Line Number": issue.get("line_number"),
                    "Has Secret": issue.get("hashed_secret") is None
                }
                records.append(record)

        if not records:
            return pd.DataFrame([{"Message": "No secrets detected."}])

        return pd.DataFrame(records)