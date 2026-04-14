# WWU vi_kings SSH Tool

## About
A rapid response, concurrent SSH management tool for WWU's NCCDC team to administer, monitor, and harden Unix-based machines during competition. 

This application is designed to be a powerful ssh based remote management tool. It will allow team members to quickly make changes to machines to harden them, monitor their status, and perform other necessary tasks during the competition. The tool will focus on stability and efficiency and stealth (for example leaving no bash history on managed machines) while maintaining a user-friendly interface.

## Tech Stack
- **Language:** Python

## Design
- hacker-vibe 
- ascii logo (use the wwu_logo.txt on startup)
- WWU vi_kings (Western Washington University)

## Features
Script will be initialized and individual features and sections can be navigated by pression a number on the keyboard to specify which feature you would like to execute (with command line arguments optional as well)

#### Monitoring Dashboard
- live auto-refreshing terminal dashboard (default every 10 seconds)
- show status of all targets in one screen
- show whether TCP/SSH is reachable
- show whether we can log in non-interactively right now
- prefer key-based authentication when configured, otherwise fall back to stored passwords
- show which authentication method actually worked
- show relevant operator context for competition: key posture, stored password coverage, snapshot count, and current error state

#### SSH Authorized Key Injection
- add functionality to add an authorized key to a specified user on every host
- have a authorized_keys file that can be manually be edited by the script user with potentially multiple keys

#### Password Audit
- check if machines are using a default password for every account in the /etc/shadow file
- for every machine, offer the script user the option to change the password to a phrase based password (4 words, - separator, 1 random number, 1 capital word)
- THIS STEP MUST NOT FAIL, if a password change is done incorrectly we could potentially lose access to the entire system!!!
- after successfull update make sure metadata database is updated so we can use that to continue managing machines

#### Snapshot Management
- if something breaks we need to somehow be able to revert it
- host specific
- restore flow should let the operator choose one host and then restore multiple related files together

## Requirements
#### Snapshotting
- any potentially breaking change (password change, config change, etc) to a system will require snapshotting to occur
- create a local backup store of the state of important files like /etc/passwd and /etc/shadow every time a change is made
- before restoring a snapshot, capture the current remote file again so the restore itself is reversible

#### Stability
- VERY IMPORTANT WHEN MAKING CHANGES ON TARGETS

#### Compatability
- CCDC competitions tend to use very outdated or insecure boxes, this script will have to accomodate this
- able to connect to a wide variety of unix based machines
- must be able to adapt to a wide variety of crypto algorithms that the hosts might be configured with 
- there will likely be very minimal tooling installed on most of these machines, this script must take that into account

#### stealth
- Script will need to leave little to no trace on target system (for example leaves no bash history)
- We don't want red teamers ripping our changed passwords from any left artifacts

#### targets.txt
- Script will reference a local targets.txt to determine which hosts to perform actions on
- This file can be updated by the script itself (for example if there's a host discovery tool)
- will be the scripts source of truth for target hosts
- targets.txt should only support the format label,host,port

#### json metadata database
- relevant host based information will be stored in a single json database file
- include the current passwords used to login to each machine
- include the preferred SSH username for each host
