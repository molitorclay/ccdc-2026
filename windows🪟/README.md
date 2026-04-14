#windows

###winrm\_disable.ps1
enables winrm. Make sure this is allowed on the system.

###winrm\_enable.ps1
Turns winrm back on.

###remove\_descriptions.ps1
This script strips every user account of it's description.
Run with -WhatIf to see changes before running. 
Make sure this script complies with company policy before running.

###break\_glass.ps1
Unlocks all users. 
We will use this if we accidentally lock all but one user.

###optimal\_security.ps1
Sets AD password policy. 

###shield\_n\_restore.ps1
Makes a backup of the AD users.
We then check these users for very common passwords.
If personal identifiable information is discovered, it is removed from the user account. 
Check local domain privilages of users.
We will use this script to audit an domain machines. 

###WindowsManualMonitor.ps1
From BYU.
A script to help us update our windows machines.
Also it can set canaries?
This will help us detect if attackers are modifying files. 
It can also roll kerberose passwords if our golden ticket has been stolen.

