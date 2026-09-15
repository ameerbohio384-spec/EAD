import os
import re
import json

class AuraSecOpsAgent:
    """
    Aura: Automated Remediation and Audit Agent
    Capstone Implementation for FlyRank AI Internship
    Author: Ameer Ali Bohio
    """
    def __init__(self, target_file="test_vulnerable_app.py"):
        self.target_file = target_file
        self.findings = []

    def inspect_codebase(self):
        print(f"[*] Aura Agent starting security audit on target: {self.target_file}...")
        if not os.path.exists(self.target_file):
            print(f"[!] Error: File {self.target_file} not found.")
            return False

        with open(self.target_file, "r") as f:
            code_content = f.readlines()

        # Audit rule 1: SQL Injection Detection
        for idx, line in enumerate(code_content, 1):
            if "SELECT " in line and ("+" in line or "%" in line or "f\"" in line or "f'" in line):
                self.findings.append({
                    "id": "AURA-SEC-001",
                    "type": "SQL Injection (CWE-89)",
                    "severity": "CRITICAL",
                    "line_num": idx,
                    "vulnerable_code": line.strip(),
                    "recommended_patch": "cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))"
                })

            # Audit rule 2: Reflected XSS
            if "return f\"<h1>" in line or "return f'<h1>" in line:
                self.findings.append({
                    "id": "AURA-SEC-002",
                    "type": "Reflected Cross-Site Scripting (XSS / CWE-79)",
                    "severity": "HIGH",
                    "line_num": idx,
                    "vulnerable_code": line.strip(),
                    "recommended_patch": "from markupsafe import escape; return f'<h1>Hello {escape(name)}</h1>'"
                })

        print(f"[+] Audit completed. Found {len(self.findings)} security issues.")
        return True

    def generate_audit_report(self, output_path="SECOPS_AUDIT_REPORT.md"):
        report_content = "# Aura SecOps Automated Audit & Remediation Report\n\n"
        report_content += f"**Target Codebase:** `{self.target_file}`  \n"
        report_content += "**Auditor Agent:** Aura AI Agent (Ameer Ali Bohio)  \n"
        report_content += "**Status:** Audit Executed Successfully  \n\n"
        report_content += "---  \n\n"
        report_content += "## Summary of Findings\n\n"

        if not self.findings:
            report_content += "No high or critical vulnerabilities detected.\n"
        else:
            for f in self.findings:
                report_content += f"### [{f['severity']}] {f['type']} (ID: {f['id']})\n"
                report_content += f"- **Line Number:** {f['line_num']}\n"
                report_content += f"- **Vulnerable Line:** `{f['vulnerable_code']}`\n"
                report_content += f"- **Recommended Patch:** `{f['recommended_patch']}`\n\n"

        with open(output_path, "w") as f:
            f.write(report_content)
        print(f"[+] Formatted Markdown audit report generated at: {output_path}")

if __name__ == "__main__":
    agent = AuraSecOpsAgent()
    if agent.inspect_codebase():
        agent.generate_audit_report()