#tested~! Works :)
# Get the current domain object automatically
$Domain = (Get-ADDomain).DistinguishedName
$DomainName = (Get-ADDomain).NetBIOSName # e.g., CORP

Write-Host "[*] Working on Domain: $Domain" -ForegroundColor Cyan

#Displays previous Domain password police, sets CCDC preset policy and displays changes
Write-Host "Previous Domain Password Policy." -ForegroundColor DarkMagenta
Get-ADDefaultDomainPasswordPolicy
Set-ADDefaultDomainPasswordPolicy -Identity "$Domain" `
-ComplexityEnabled $true `
-MinPasswordLength 12 `
-LockoutThreshold 5 `
-LockoutDuration 00:50:00 `
-LockoutObservationWindow 00:30:00
Write-Host "[+] Domain Password Policy Hardened." -ForegroundColor Green
Write-Host "Current Domain Password Policy." -ForegroundColor DarkGreen
Get-ADDefaultDomainPasswordPolicy
