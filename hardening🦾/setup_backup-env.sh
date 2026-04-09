#!/usr/bin/env bash
# Sets up a chroot environmtent identical to the host system. 
# This can be used to hot swap services running betwean "/" and "$BACK_ENVup"
# Files can also be transfered betwean directories, for example to restore a defaced website. 

BACK_ENV=$BACK_ENVup

# Detect if the system is using BusyBox
if mount --version 2>&1 | grep -q "BusyBox"; then
    MOUNT_CMD="mount --bind"
else
    MOUNT_CMD="mount --rbind"
fi

echo "Using mount command: $MOUNT_CMD"

# Rsync host to chroot
rsync -aAX / $BACK_ENV \
    --exclude=/dev/* \
    --exclude=/proc/* \
    --exclude=/sys/* \
    --exclude=/run/* \
    --exclude=/tmp/* \
    --exclude=$BACK_ENV \
    --exclude=/etc/passwd \
    --exclude=/etc/shadow \
    --exclude=/home/* \
    --exclude=/root/* \
    --exclude=/etc/ssh/sshd_config

# Bind necessary filesystems
$MOUNT_CMD /run $BACK_ENV/run
$MOUNT_CMD /sys $BACK_ENV/sys
$MOUNT_CMD /dev $BACK_ENV/dev
mount -t proc proc $BACK_ENV/proc
mount -t devpts devpts $BACK_ENV/dev/pts


