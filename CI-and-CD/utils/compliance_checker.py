import pandas as pd

def check(uploaded_file):
    # In a real-world system, this would analyze the codebase or infra-as-code for compliance.
    # For now, we'll simulate commonly audited controls.
    compliance_controls = [
        {"Control": "Secure Configs Applied (no default passwords, SSH keys managed)", "Compliant": True},
        {"Control": "Audit Logging Enabled", "Compliant": True},
        {"Control": "Secrets Not Embedded in Code", "Compliant": False},
        {"Control": "Dependencies Are Pinned", "Compliant": True},
        {"Control": "HTTPS Used Exclusively", "Compliant": False},
    ]

    return pd.DataFrame(compliance_controls)
