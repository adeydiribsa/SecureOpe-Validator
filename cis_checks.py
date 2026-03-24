import subprocess
import os

def run_windows_checks():
    try:
        script_path = os.path.join(os.path.dirname(__file__), "windows_checks.ps1")

        output = subprocess.check_output(
            ["powershell", "-ExecutionPolicy", "Bypass", "-File", script_path],
            text=True
        )
        return output

    except Exception as e:
        return f"ERROR: {str(e)}"


def run_linux_checks():
    try:
        script_path = os.path.join(os.path.dirname(__file__), "linux_checks.sh")

        output = subprocess.check_output(["bash", script_path], text=True)
        return output

    except Exception as e:
        return f"ERROR: {str(e)}"


def analyze_cis_output(output):
    issues = []

    o = output.lower()

    # 🔐 FIREWALL
    if "enabled : false" in o:
        issues.append("Firewall is disabled (CRITICAL)")

    # 🔑 PASSWORD POLICY
    if "minimum password length" in o and ("5" in o or "6" in o):
        issues.append("Weak password length policy (HIGH RISK)")

    # 🔒 LOCKOUT
    if "lockout threshold" in o and "never" in o:
        issues.append("Account lockout not configured (HIGH RISK)")

    # 👤 GUEST
    if "[guest_account]" in o and "true" in o:
        issues.append("Guest account enabled (MEDIUM RISK)")

    # 👑 ADMIN
    if "[admin_account]" in o and "true" in o:
        issues.append("Default Administrator account enabled (MEDIUM RISK)")

    # 🖥️ RDP
    if "[rdp_status]" in o and "0" in o:
        issues.append("RDP enabled (HIGH RISK)")

    # 📡 SMB
    if "enablesmb1protocol : true" in o:
        issues.append("SMBv1 enabled (CRITICAL)")

    # 🛡️ UAC
    if "[uac_status]" in o and "0" in o:
        issues.append("UAC disabled (HIGH RISK)")

    # 📜 POWERSHELL LOGGING
    if "[powershell_logging]" in o and "not_configured" in o:
        issues.append("PowerShell logging not enabled (MEDIUM RISK)")

    # 📊 AUDIT POLICY
    if "no auditing" in o:
        issues.append("Audit logging not properly configured (HIGH RISK)")

    # 📁 EVENT LOG SIZE
    if "maximumkilobytes" in o:
        # basic check (can improve later)
        issues.append("Review event log size configuration (LOW RISK)")

    # 🌐 WINRM
    if "[winrm_status]" in o and "running" in o:
        issues.append("WinRM service exposed (MEDIUM RISK)")

    return issues
 