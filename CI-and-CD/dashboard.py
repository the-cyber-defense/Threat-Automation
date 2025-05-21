import streamlit as st
import pandas as pd
from utils import (
    sast_runner, dast_runner, sca_checker, vuln_scanner,
    secrets_scanner, policy_enforcer, compliance_checker
)

st.set_page_config(page_title="CI/CD Security Dashboard", layout="wide")
st.title(" CI/CD Security Scanner Dashboard")

st.sidebar.header("🛠️ Select Security Tasks")
task_options = st.sidebar.multiselect("Run Security Checks For:", [
    "SAST",
    "DAST",
    "SCA",
    "Vulnerability Scan",
    "Secrets Scan",
    "Policy Enforcement",
    "Compliance Check"
])

target_url = None
docker_image_name = None

if "DAST" in task_options:
    target_url = st.text_input("🌐 Enter Target URL for DAST Scan")

if "Vulnerability Scan" in task_options:
    docker_image_name = st.text_input("🐳 Enter Docker Image Name for Vulnerability Scan")

uploaded_file = st.file_uploader("📦 Upload Your Code Archive (ZIP or TAR)", type=["zip", "tar"])

if st.button("🚀 Run Checks"):
    if not uploaded_file and any(t not in ["DAST", "Vulnerability Scan"] for t in task_options):
        st.error("⚠️ Please upload your code archive to proceed.")
    elif "DAST" in task_options and not target_url:
        st.error("⚠️ Please enter a target URL for DAST.")
    elif "Vulnerability Scan" in task_options and not docker_image_name:
        st.error("⚠️ Please enter the Docker image name.")
    else:
        with st.spinner("🔍 Running security checks..."):
            results = {}
            score = 0

            if "SAST" in task_options:
                sast_results = sast_runner.run_sast(uploaded_file)
                if isinstance(sast_results, pd.DataFrame):
                    if 'issue_severity' in sast_results.columns:
                        score += sast_results['issue_severity'].str.upper().map({"HIGH": 3, "MEDIUM": 2, "LOW": 1}).sum()
                results["SAST"] = sast_results

            if "DAST" in task_options:
                dast_results = dast_runner.run_dast(target_url)
                if isinstance(dast_results, pd.DataFrame):
                    score += len(dast_results) * 2
                results["DAST"] = dast_results

            if "SCA" in task_options:
                sca_results = sca_checker.check_dependencies(uploaded_file)
                if isinstance(sca_results, pd.DataFrame):
                    score += len(sca_results) * 2
                results["SCA"] = sca_results

            if "Vulnerability Scan" in task_options:
                vuln_results = vuln_scanner.scan_image(docker_image_name)
                if isinstance(vuln_results, pd.DataFrame) and "Severity" in vuln_results.columns:
                    score += vuln_results['Severity'].str.upper().map({"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}).sum()
                results["Vulnerability Scan"] = vuln_results

            if "Secrets Scan" in task_options:
                secrets_results = secrets_scanner.scan_codebase(uploaded_file)
                if isinstance(secrets_results, pd.DataFrame):
                    score += len(secrets_results) * 3
                results["Secrets Scan"] = secrets_results

            if "Policy Enforcement" in task_options:
                policy_results = policy_enforcer.check_policies(uploaded_file)
                if isinstance(policy_results, pd.DataFrame):
                    score += policy_results['Status'].str.lower().map({"fail": 2}).fillna(0).sum()
                results["Policy Enforcement"] = policy_results

            if "Compliance Check" in task_options:
                compliance_results = compliance_checker.check(uploaded_file)
                if isinstance(compliance_results, pd.DataFrame):
                    score += compliance_results['Compliant'].map({False: 2}).sum()
                results["Compliance Check"] = compliance_results

        st.success("✅ All selected checks completed.")
        st.markdown(f"### 🧮 Security Risk Score: `{int(score)}`")

        if results:
            tabs = st.tabs(list(results.keys()))
            for tab, (task, data) in zip(tabs, results.items()):
                with tab:
                    if isinstance(data, pd.DataFrame):
                        st.dataframe(data)
                        csv = data.to_csv(index=False).encode('utf-8')
                        st.download_button(
                            label=f"⬇️ Download {task} Results (CSV)",
                            data=csv,
                            file_name=f"{task.lower().replace(' ', '_')}_results.csv",
                            mime="text/csv"
                        )
                    else:
                        st.json(data)
        else:
            st.warning("⚠️ No valid scan results to display.")
else:
    st.info("📥 Select tasks, provide inputs, and click 'Run Checks' to begin.")
