# =========================
# CIS WINDOWS SECURITY CHECKS (ADVANCED)
# =========================

Write-Output "=== CIS WINDOWS SECURITY CHECK START ==="

# -------------------------
# 1. FIREWALL STATUS (CIS 4 / 12)
# -------------------------
Write-Output "`n[FIREWALL_STATUS]"
Get-NetFirewallProfile | Select-Object Name, Enabled

# -------------------------
# 2. PASSWORD POLICY (CIS 5)
# -------------------------
Write-Output "`n[PASSWORD_POLICY]"
net accounts

# -------------------------
# 3. ACCOUNT LOCKOUT (CIS 5)
# -------------------------
Write-Output "`n[LOCKOUT_POLICY]"
net accounts | findstr /C:"Lockout"

# -------------------------
# 4. PATCH LEVEL (CIS 7)
# -------------------------
Write-Output "`n[PATCH_COUNT]"
(Get-HotFix).Count

# -------------------------
# 5. GUEST ACCOUNT (CIS 5)
# -------------------------
Write-Output "`n[GUEST_ACCOUNT]"
try {
    (Get-LocalUser -Name "Guest").Enabled
} catch {
    "NOT_FOUND"
}

# -------------------------
# 6. ADMIN ACCOUNT (CIS 5)
# -------------------------
Write-Output "`n[ADMIN_ACCOUNT]"
try {
    (Get-LocalUser -Name "Administrator").Enabled
} catch {
    "NOT_FOUND"
}

# -------------------------
# 7. RDP STATUS (CIS 12)
# -------------------------
Write-Output "`n[RDP_STATUS]"
try {
    (Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Terminal Server").fDenyTSConnections
} catch {
    "ERROR"
}

# -------------------------
# 8. SMB CONFIG (CIS 13)
# -------------------------
Write-Output "`n[SMB_STATUS]"
try {
    Get-SmbServerConfiguration | Select EnableSMB1Protocol, EnableSMB2Protocol
} catch {
    "ERROR"
}

# -------------------------
# 9. UAC STATUS (CIS 4)
# -------------------------
Write-Output "`n[UAC_STATUS]"
try {
    (Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System").EnableLUA
} catch {
    "ERROR"
}

# -------------------------
# 10. POWERSHELL LOGGING (CIS 8)
# -------------------------
Write-Output "`n[POWERSHELL_LOGGING]"
try {
    Get-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
} catch {
    "NOT_CONFIGURED"
}

# -------------------------
# 11. AUDIT POLICY (CIS 8)
# -------------------------
Write-Output "`n[AUDIT_POLICY]"
auditpol /get /category:*

# -------------------------
# 12. EVENT LOG SIZE (CIS 8)
# -------------------------
Write-Output "`n[EVENT_LOG_SIZE]"
Get-EventLog -List | Select Log, MaximumKilobytes

# -------------------------
# 13. WINRM STATUS (CIS 12)
# -------------------------
Write-Output "`n[WINRM_STATUS]"
try {
    (Get-Service WinRM).Status
} catch {
    "ERROR"
}

# -------------------------
# END
# -------------------------
Write-Output "`n=== CIS WINDOWS SECURITY CHECK END ==="