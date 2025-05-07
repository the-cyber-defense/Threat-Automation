import os
import tempfile
import zipfile
import pandas as pd
import re

POLICIES = [
    {
        "Policy": "No AWS Access Keys",
        "Pattern": r"AKIA[0-9A-Z]{16}",
        "Type": "regex"
    },
    {
        "Policy": "No HTTP endpoints",
        "Pattern": r"http://",
        "Type": "regex"
    },
    {
        "Policy": "No TODOs in code",
        "Pattern": r"TODO",
        "Type": "regex"
    }
]

def check_policies(uploaded_file):
    with tempfile.TemporaryDirectory() as temp_dir:
        archive_path = os.path.join(temp_dir, "uploaded_code.zip")
        with open(archive_path, "wb") as f:
            f.write(uploaded_file.getbuffer())

        with zipfile.ZipFile(archive_path, 'r') as zip_ref:
            zip_ref.extractall(temp_dir)

        results = []

        for policy in POLICIES:
            pattern = re.compile(policy["Pattern"], re.IGNORECASE)
            status = "pass"

            for root, _, files in os.walk(temp_dir):
                for file in files:
                    if file.endswith(('.py', '.js', '.yml', '.yaml', '.json', '.env', '.txt')):
                        file_path = os.path.join(root, file)
                        try:
                            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                content = f.read()
                                if pattern.search(content):
                                    status = "fail"
                                    break
                        except Exception:
                            continue
                if status == "fail":
                    break

            results.append({
                "Policy": policy["Policy"],
                "Status": status
            })

        return pd.DataFrame(results)
