# Disable PowerShell Remoting
Disable-PSRemoting -Force

# Stop and disable WinRM service
Stop-Service -Name WinRM -Force
Set-Service -Name WinRM -StartupType Disabled

Write-Host "WinRM has been disabled."
