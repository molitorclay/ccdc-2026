# Enable PowerShell Remoting (WinRM)
Enable-PSRemoting -Force

# Ensure WinRM service is running and set to automatic
Set-Service -Name WinRM -StartupType Automatic
Start-Service -Name WinRM

# Optional: Allow unencrypted traffic (only if needed in non-secure environments)
# Set-Item -Path WSMan:\localhost\Service\AllowUnencrypted -Value $true

# Optional: Allow basic auth (NOT recommended unless required)
# Set-Item -Path WSMan:\localhost\Service\Auth\Basic -Value $true

Write-Host "WinRM has been enabled."
