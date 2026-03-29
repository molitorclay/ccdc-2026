#!/usr/env bash


/usr/sbin/sshd

echo "== ssh-ing localhost, you should be in jail =="
ssh localhost -oStrictHostKeyChecking=no
echo "== ssh exited =="


echo "== launching bash, no longer in jail =="
bash
