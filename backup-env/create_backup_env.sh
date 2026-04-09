#!/usr/env bash

echo "Banner /etc/motd" >> /etc/ssh/sshd_config
echo "ChrootDirectory /jail/" >> /etc/ssh/sshd_config


mkdir /jail/{,bin,dev,home,root,lib,etc}
# copy programs and libs to jail
cp /bin/{bash,sh,id,hostname,ls,cp,rm,cat,vim} /jail/bin/
cp --parents -r /lib{,64}/* /jail


# populate jail's /dev
mknod -m 666 /jail/dev/null c 1 3
mknod -m 666 /jail/dev/zero c 1 5
mknod -m 666 /jail/dev/tty c 5 0
mknod -m 666 /jail/dev/random c 1 9
mknod -m 666 /jail/dev/urandom c 1 9
mknod -m 666 /jail/dev/stdin c 1 0
mknod -m 666 /jail/dev/stdout c 1 1
mknod -m 666 /jail/dev/stderr c 1 2

# make the cell more roomy
cp ~/.bashrc /jail/root/
cp /etc/bash.bashrc /jail/etc/bash.bashrc

