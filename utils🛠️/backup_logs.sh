#!/usr/bin/env bash

# Usage: command [out path] [IPs file]
# This script uses scp to grab directories from remote systems and copies them locally 
# Copies the last backup into a new dir, and sync this new dir over ssh

if ! command -v rsync >/dev/null 2>&1; then
    echo "ERROR: Install rsync or use the simple backup script"
    exit 1
fi

# read ips from file
if [ -n "$2" ]; then
    IPS=$(cat "$2")
elif test -f "ips"; then
    IPS=$(cat ips)
elif test -f "../ips"; then
    IPS=$(cat ../ips)
else
    echo "Can't find \"ips\" file."
fi


NOW=$(date +"%d_%H-%M-%S")
# use ./backup if path is not supplied
if [ -z "$1" ]; then
    BASEDIR=./logs
else
    BASEDIR="$1"
fi


BACKUPPATH=$BASEDIR

# Sync the remote logs to our backup
for i in $IPS; do
    echo "==== $i ===="
    mkdir "$BACKUPPATH/$i" -p 2>/dev/null
    rsync -a --info=progress2\
        --timeout=30 \
        --ignore-errors \
        --one-file-system \
        -e "ssh -T -p 22" \
        "root@$i:/var/log" "$BACKUPPATH/$i"
done




