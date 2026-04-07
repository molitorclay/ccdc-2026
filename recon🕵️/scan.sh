#! /usr/bin/env bash
# This script may be ran as a typical script but is inteneded as a reference.
# Copy and paste each section one at a time to get more readable results. 

# Bold Echo
becho () {
echo -e "\033[1m$*\033[0m"
}


## ETC ##
becho "Scanning /etc"

becho "/etc/shadow - unlocked accounts"
awk -F: '($2 !~ /^!|^\*$/ && $2 != "") {print $1}' /etc/shadow

tput bold
becho "/etc/passwd - users with interactive logins"
cat /etc/passwd | grep -v -E 'nologin$|false$'

becho " UID 0 users (should only be root)"
awk -F: '($3 == 0) {print}' /etc/passwd

becho "/etc/hosts - look for bad redirects"
cat /etc/hosts

becho "/etc/inittab - procs that run at system start"
cat /etc/inittab
#tree /etc/init.d

becho "/etc/cron* - crontab for all users"
crontab -l
for user in $(cut -f1 -d: /etc/passwd); do
    echo $user
    crontab -u $user -l 2>/dev/null
done
ls -al /etc/cron*


## Processes ##
becho "== Processes =="
#becho "ps aux"
#ps aux
becho "ps tree"
pstree

becho "Running Systemd services"
systemctl list-units --type=service --state=running 2>/dev/null
rc-status 2>/dev/null

becho "netstat - look for listening ports"
netstat -antp

becho "Look for ports with ss (better)"
ss -tulnp

becho "network connections"
ss -antp | grep ESTAB

echo "who is logged in - It should only be us!"
w

## Misc ##
becho "SSH authorized keys"
find /home -name "authorized_keys" -exec cat {} \; 2>/dev/null

becho "SUID files (check against gtfobins)"
find / -perm -4000 -type f 2>/dev/null

becho "== Login history =="
last -a | head

becho "== Recently modified files (last 1 day) =="
find / -xdev -type f -mtime -1 2>/dev/null | head -n 50




