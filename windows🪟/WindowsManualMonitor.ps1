Import-Module ActiveDirectory

function Pause {
    Read-Host "Waiting for AD response... Press Enter to return to menu"
}

# Function to generate a random password
function Get-RandomPassword {
    param (
        [int]$length = 12
    )
    
    $charSet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789%^*'
    $password = -join ((1..$length) | ForEach-Object { Get-Random -InputObject $charSet.ToCharArray() })
    return $password
}

# Sourced from BYU AD Hardening Scripts https://github.com/BYU-CCDC/public-ccdc-resources/tree/main/windows/hardening
function Get-WindowsUpdates {
    try {
        # Restart Windows Update service
        Restart-Service -Name wuauserv

        # Clear Windows Update cache
        Stop-Service -Name wuauserv
        Remove-Item -Path C:\Windows\SoftwareDistribution\* -Recurse -Force
        Start-Service -Name wuauserv

        # Check for disk space
        $diskSpace = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='C:'" | Select-Object -ExpandProperty FreeSpace
        if ($diskSpace -lt 1073741824) { # 1 GB in bytes
            Write-Host "Insufficient disk space available on the system drive. Please free up disk space and try again."
            exit
        }

        # Check Windows Update logs for errors
        $updateLogPath = "C:\Windows\WindowsUpdate.log"
        if (Test-Path $updateLogPath) {
            $updateLogContent = Get-Content -Path $updateLogPath -Tail 50 # Read last 50 lines of the log
            if ($updateLogContent -match "error") {
                Write-Host "Error detected in Windows Update log. Please review the log for more details: $updateLogPath"
                exit
            }
        }

        # Check if updates are available
        $wuSession = New-Object -ComObject Microsoft.Update.Session
        $wuSearcher = $wuSession.CreateUpdateSearcher()
        $updates = $wuSearcher.Search("IsInstalled=0")

        # Install available updates
        if ($updates.Updates.Count -gt 0) {
            $totalUpdates = $updates.Updates.Count
            $updateCounter = 0

            # Initialize progress bar
            Write-Progress -Activity "Installing updates" -Status "0% Complete" -PercentComplete 0

            $updates.Updates | ForEach-Object {
                $updateCounter++
                $percentComplete = ($updateCounter / $totalUpdates) * 100
                Write-Progress -Activity "Installing updates" -Status "$percentComplete% Complete" -PercentComplete $percentComplete

                # Install update
                $installResult = $wuSession.CreateUpdateInstaller().Install($_)
                if ($installResult.ResultCode -ne 2) {
                    Write-Host "Failed to install update $($_.Title). Result code: $($installResult.ResultCode)"
                }
            }
            Write-Host "Updates successfully installed."
        } else {
            Write-Host "No updates available."
        }
    } catch {
        Write-Host $_.Exception.Message -ForegroundColor Yellow
        Write-Host "Error Occurred..."
    }
}

# Deploy and test canaries in all user directories and all drive root directories
# Sourced from CyberDrain https://www.cyberdrain.com/monitoring-with-powershell-ad-krbtgt-making-your-own-canaries/
function Test-Canaries {
    $audit = auditpol /get /subcategory:"File System"

    if ($audit -notmatch "Success and Failure") {
        auditpol /set /subcategory:"File System" /success:enable /failure:enable | Out-Null
    }

    $CreateLocations = @(
        "$env:USERPROFILE\Desktop",
        "$env:USERPROFILE\Documents",
        "$env:WINDIR\Temp")
    $FileContent = "This file is a special file created by your managed services provider. For more information contact the IT Support desk."
    $LogFile = ".\canaries.txt"
    $CanaryStatus = @()

    foreach ($Location in $CreateLocations) {
        $Path = Join-Path $Location "CanaryFile.txt"

        if (!(Test-Path $Path)) {
            New-Item -Path $Path -ItemType File -Value $FileContent -Force | Out-Null
            (Get-Item $Path).Attributes = "Hidden"

            Add-Content -Path $LogFile -Value "$Path|$(Get-Date -Format o)"
            $acl = Get-Acl $Path

            $auditRule = New-Object System.Security.AccessControl.FileSystemAuditRule(
                "Everyone",
                "ReadData",
                "Success"
            )

            $acl.AddAuditRule($auditRule)
            Set-Acl $Path $acl
        }
        else {
            $CreationTime = Get-Content $LogFile |
                Where-Object { $_ -like "$Path*" } |
                Select-Object -Last 1 |
                ForEach-Object { ($_ -split '\|')[1] } |
                ForEach-Object { [datetime]$_ }

            $ExistingFile = Get-Item $Path -Force

            if ($CreationTime -and $ExistingFile.LastWriteTime -gt $CreationTime) {
                $CanaryStatus += "$Path modified (possible tampering)"
            }

            $CurrentContent = Get-Content $Path -Raw

            if ($CurrentContent -ne $FileContent) { $CanaryStatus += "$Path is unhealthy. The contents do not match. This is a sign the file has most likely been encrypted" }        
        }
    }

    $events = Get-WinEvent -FilterHashtable @{
        LogName='Security'
        Id=4663
    } | Where-Object {
        $_.Message -like "*CanaryFile.txt*"
    }

    foreach ($e in $events) {
        $xml = [xml]$e.ToXml()

        $file = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "ObjectName" }).'#text'
        $username = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "SubjectUserName" }).'#text'
        $domain   = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "SubjectDomainName" }).'#text'

        Write-Host "===============================" -ForegroundColor Yellow
        Write-Host "!! CANARY TRIGGERED !!" -ForegroundColor Red
        Write-Host "Time: $($e.TimeCreated)"
        Write-Host "EventID: $($e.Id)"
        Write-Host "User: $domain\$username"
        Write-Host "File: $file"
        Write-Host ($e.Message -split "`r?`n|`n")[0]
    }

    if($CanaryStatus.Count -eq 0 -and $events.Count -eq 0){
        Write-Host "Healthy"
    } else {
        Write-Host "Unhealthy"
    }
}

Function Show-Menu {
    Write-Host "******************************"
    Write-Host "* CCDC Manual Monitor Script *"
    Write-Host "******************************"
    Write-Host "1. List Enabled AD Accounts and Last Logon"
    Write-Host "2. Disable AD Account"
    Write-Host "3. List AD Account Permissions"
    Write-Host "4. Reset KRBTGT Account Password"
    Write-Host "5. List Established Connections"
    Write-Host "6. List Listening Connections"
    Write-Host "7. Run Windows Updates"
    Write-Host "8. Check Canaries"
    Write-Host "Q. Quit"
}

Do {
    Show-Menu
    $choice = Read-Host "Please select an option"

    Switch ($choice) {
        1 { 
            Get-ADUser -Filter "Enabled -eq 'True'" -Properties LastLogonDate | Select Name, LastLogonDate 
            Pause
        }
        2 { 
            try {
              Disable-ADAccount $(Read-Host "Enter account name")
              Write-Host "Successfully disabled specified user account"
            }
            catch {
                Write-Host "Unable to disable specified user account"
            }
        }
        3 {
            try {
                (Get-ACL "AD:$((Get-ADUser -Identity $(Read-Host "Enter account username: ")).distinguishedname)").access | Select IdentityReference,AccessControlType   
                Pause
            }
            catch {
                Write-Host "Unable to list permissions for specified user account"
            }
        }
        4 {
            try {
                $newPassword = Get-RandomPassword -length 24
                Set-ADAccountPassword -Identity KRBTGT -Reset -NewPassword (ConvertTo-SecureString -AsPlainText $newPassword -Force)
                
                $newPassword = Get-RandomPassword -length 24
                Set-ADAccountPassword -Identity KRBTGT -Reset -NewPassword (ConvertTo-SecureString -AsPlainText $newPassword -Force)
                
                Write-Output "Password for KRBTGT changed successfully. New Password: $newPassword"
            }
            catch {
                Write-Output "Failed to reset password for KRBTGT: $_"
            }
        }
        5 { Get-NetTCPConnection -State Established | Sort-Object State,LocalPort | Format-Table }
        6 { Get-NetTCPConnection -State Listen | Sort-Object LocalPort | Format-Table LocalPort,LocalAddress,OwningProcess }
        7 { Get-WindowsUpdates }
        8 { Test-Canaries}
        'Q' { Write-Host "Exiting..." }
        Default { Write-Host "Invalid option, please try again." }
    }
} While ($choice -ne 'Q')