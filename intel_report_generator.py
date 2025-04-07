import datetime

def generate_bluf(title, impact, mitigation):
    date = datetime.datetime.now().strftime("%Y-%m-%d")
    report = f"""\
Date: {date}
Title: {title}
---
**BLUF**: {impact}

**Mitigation Steps**:
- {mitigation}
"""
    print(report)

if __name__ == "__main__":
    generate_bluf(
        "New CVE in OpenSSL",
        "Critical RCE vulnerability affecting OpenSSL <1.1.1",
        "Update all instances to OpenSSL 1.1.1 or later immediately"
    )