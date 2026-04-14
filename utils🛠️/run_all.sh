#!/usr/bin/env bash

# Usage: command script.sh [IPs file]
# This script runs a script on all remote systems listed in the ips file

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

for i in $IPS; do
    echo "==== $i ===="
    ssh root@$i 'bash -s' < $1
done
# 



