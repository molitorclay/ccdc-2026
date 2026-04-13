# --- THE BREAK GLASS BYPASS ---
# If you lock yourself out, run this as a script to unlock EVERYONE instantly.
Function Unlock-AllUsers {
    Get-ADUser -Filter 'LockedOut -eq $true' | Unlock-ADAccount
    Write-Host "[+] All accounts unlocked." -ForegroundColor Green
}