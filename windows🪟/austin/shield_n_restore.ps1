# --- CONFIGURATION ---
$BackupPath = "C:\Admin_Backups\UserAudit_$(Get-Date -Format 'yyyyMMdd_HHmm').xml"
if (!(Test-Path "C:\Admin_Backups")) { New-Item -Path "C:\Admin_Backups" -ItemType Directory }

# --- 1. BACKUP & AUDIT ---
Write-Host "[*] Phase 1: Backing up current user state..." -ForegroundColor Cyan
$AllUsers = Get-ADUser -Filter * -Properties Description, Office, Department, HomePage

# Export current state to encrypted XML (This is your "Manual Snapshot")
$AllUsers | Export-CliXml -Path $BackupPath
Write-Host "[+] Snapshot saved to $BackupPath" -ForegroundColor Green
Write-Warning "Please delete this file after completed or move offsite."

# --- 2. VERBOSE REMEDIATION ---
# checks for a common password spray list, gives count back and remediate user pii
Write-Host "[*] Phase 2: Scanning for high-risk PII..." -ForegroundColor Cyan
$RiskyKeywords = @(
    "*pass*", "*123*", "*2025*", "*2026*", "*admin*", 
    "*welcome*", "*changeme*", "*summer*", "*winter*", "*fall*", "*spring*",
    "*qwerty*", "*root*", "*secret*", "*security*", "*temp*"
)
$FoundCount = 0

foreach ($User in $AllUsers) {
    $Match = $false
    foreach ($Word in $RiskyKeywords) {
        if ($User.Description -like $Word) { $Match = $true }
    }

    if ($Match) {
        Write-Host "[!] VULNERABILITY: Weak info found in $($User.SamAccountName)" -ForegroundColor Yellow
        Write-Host "    Current: $($User.Description)" -ForegroundColor Gray
        
        # Correction
        Set-ADUser -Identity $User.SamAccountName -Description "REMEDIATED_BY_SEC"
        Write-Host "    [+] Success: PII Wiped." -ForegroundColor Green
        $FoundCount++
    }
}

Write-Host "`n[*] Remediation Complete. Total issues fixed: $FoundCount" -ForegroundColor White
Write-Host "[?] TO REVERT: Import-CliXml $BackupPath | ForEach-Object { Set-ADUser -Identity `$_.SamAccountName -Description `$_.Description }" -ForegroundColor Magenta 

Write-Host "[*] Auditing Local Admin Group for anomalies..." -ForegroundColor Cyan
$KnownAdmins = "Administrator|TeamAdmin|Domain Admins"

#check local users NOTE: MAY NOT BE WORKING :(
Get-LocalGroupMember -Group "Administrators" | ForEach-Object {
    if ($_.Name -notmatch $KnownAdmins) {
        Write-Host "[!!!] UNEXPECTED LOCAL ADMIN: $($_.Name)" -ForegroundColor Red -BackgroundColor Black
    }
}

# --- NEW: PRIVILEGE AUDIT SECTION ---
Write-Host "[*] Phase 3: Auditing High-Privilege Groups..." -ForegroundColor Cyan
$CriticalGroups = @("Domain Admins", "Enterprise Admins", "Schema Admins")
$ExpectedAdmins = "Administrator|TeamAdmin" # Add your team's real usernames here

foreach ($Group in $CriticalGroups) {
    $Members = Get-ADGroupMember -Identity $Group
    foreach ($Member in $Members) {
        if ($Member.Name -notmatch $ExpectedAdmins) {
            Write-Host "[!!!] PRIVILEGE DRIFT: $($Member.Name) is in $Group!" -ForegroundColor Red -BackgroundColor Black
            # Optional: Add-Content -Path $LogPath -Value "Vulnerable Admin: $($Member.Name)"
        }
    }
}
