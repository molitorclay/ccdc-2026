FROM debian
SHELL ["/bin/bash", "-c"]

RUN mkdir /app
COPY jail.sh /app

RUN apt-get update
RUN apt-get install -y ssh openssh-server
RUN ssh-keygen -A

RUN echo "Docker test for jail.sh 🐬" >> /etc/motd
RUN echo "PermitRootLogin yes" >> /etc/ssh/sshd_config
RUN ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519 -N "" -q
RUN cat ~/.ssh/id_ed25519.pub >> ~/.ssh/authorized_keys

RUN bash /app/jail.sh

CMD ["/bin/bash", "-c",  "/usr/sbin/sshd; ssh localhost -oStrictHostKeyChecking=no"]
