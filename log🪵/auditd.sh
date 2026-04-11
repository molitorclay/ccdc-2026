

# Install Deb/RHEL/Alpine
apt update
apt install auditd audispd-plugins
dnf install audit
apk add audit


# Start systemd
systemctl enable auditd
systemctl start auditd

# Start Alpine
rc-service auditd start
rc-update add auditd

#Verify (Should be enabled 1)
echo 'You should see: enabled 1'
auditctl -s

# Add rules 
# log commands executed
auditctl -a always,exit -F arch=b64 -S execve
# Watch files
auditctl -w /etc/passwd -p wa -k passwd_changes


# View logs locally 
# ausearch -k exec_log
# aureport -x
#
