Import-Module ActiveDirectory

# Get all users with a Description set
$users = Get-ADUser -Filter * -Properties Description | Where-Object {
    $_.Description -ne $null -and $_.Description -ne ""
}

foreach ($user in $users) {
    Write-Host "Clearing Description for $($user.SamAccountName): $($user.Description)"
    #Set-ADUser -Identity $user -Clear Description -WhatIf
    Set-ADUser -Identity $user -Clear Description
}
