#!/usr/bin/env bash
set -euo pipefail

HOMENET_NET="10.10.10.0/24"
OUTNET_NET="192.168.50.0/24"
BASTION_IP="10.10.10.254"

ALICE="10.10.10.10"
BOB="10.10.10.20"
CAROL="10.10.10.21"
DAVE="10.10.10.22"
ERIN="10.10.10.23"
FRANK="10.10.10.30"
GRACE="10.10.10.40"
HEIDI="10.10.10.50"

RED_TEAM_IPS=(
  # "192.168.50.66"
  # "192.168.50.67"
)

RED_TEAM_PORTS=(
  # "4444"
  # "31337"
)

ALLOWLIST_IPS=(
  # "192.168.50.10"
)

ALLOWLIST_TCP_PORTS=(
  # "22"
  # "80"
  # "443"
)

ALLOWLIST_UDP_PORTS=(
  # "53"
  # "123"
)

EGRESS_TCP_PORTS=(
  53
  80
  443
 #22
 #25
 #465
 #587
 #110
 #995
 #143
 #993
)

EGRESS_UDP_PORTS=(
  53
  123
)

WEB_HOSTS=(
  "$BOB"
)

JENKINS_HOSTS=(
  "$CAROL"
)

FTP_HOSTS=(
  "$DAVE"
)

MAIL_HOSTS=(
  # "$ERIN"
)

PUBLIC_SSH_HOSTS=(
  # "$FRANK"
)

RDP_HOSTS=(
  # "$GRACE"
)

WINRM_HOSTS=(
  # "$GRACE"
)

AD_HOSTS=(
  # "$ALICE"
)

DB_HOSTS=(
  # "$HEIDI"
)

# add ad hoc open ports here
# format: "$HOSTIP:PORT"
ADHOC_TCP_RULES=(
  # "$BOB:1234"
  # "$CAROL:9000"
)

ADHOC_UDP_RULES=(
  # "$ALICE:161"
)

BACKUP_DIR="/root/fw-backups"
STAMP="$(date +%F-%H%M%S)"
mkdir -p "$BACKUP_DIR"
iptables-save > "$BACKUP_DIR/iptables-$STAMP.save"
ip6tables-save > "$BACKUP_DIR/ip6tables-$STAMP.save" 2>/dev/null || true

iptables -F
iptables -X

iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

iptables -N LOGDROP
iptables -A LOGDROP -m limit --limit 10/min --limit-burst 20 -j LOG --log-prefix "DROP " --log-level 4
iptables -A LOGDROP -j DROP

iptables -N EARLYDROP

for ip in "${RED_TEAM_IPS[@]}"; do
  iptables -A EARLYDROP -s "$ip" -j LOGDROP
  iptables -A EARLYDROP -d "$ip" -j LOGDROP
done

for p in "${RED_TEAM_PORTS[@]}"; do
  iptables -A EARLYDROP -p tcp --sport "$p" -j LOGDROP
  iptables -A EARLYDROP -p tcp --dport "$p" -j LOGDROP
  iptables -A EARLYDROP -p udp --sport "$p" -j LOGDROP
  iptables -A EARLYDROP -p udp --dport "$p" -j LOGDROP
done

iptables -A INPUT -j EARLYDROP
iptables -A OUTPUT -j EARLYDROP
iptables -A FORWARD -j EARLYDROP

iptables -A INPUT -s 127.0.0.0/8 -d 127.0.0.0/8 -j ACCEPT
iptables -A OUTPUT -s 127.0.0.0/8 -d 127.0.0.0/8 -j ACCEPT

iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

iptables -A INPUT -m conntrack --ctstate INVALID -j DROP
iptables -A OUTPUT -m conntrack --ctstate INVALID -j DROP
iptables -A FORWARD -m conntrack --ctstate INVALID -j DROP

iptables -A INPUT -p tcp -s "$BASTION_IP" --dport 22 -m conntrack --ctstate NEW -j ACCEPT
iptables -A INPUT -p tcp --dport 22 -j LOGDROP

# no inbound icmp
iptables -A OUTPUT -p icmp -j ACCEPT
iptables -A FORWARD -s "$HOMENET_NET" ! -d "$HOMENET_NET" ! -d "$OUTNET_NET" -p icmp --icmp-type echo-request -m conntrack --ctstate NEW -j ACCEPT

# uncomment to kill all icmp
# iptables -I OUTPUT 1 -p icmp -j DROP
# iptables -I FORWARD 1 -p icmp -j DROP

for p in "${EGRESS_TCP_PORTS[@]}"; do
  iptables -A FORWARD -s "$HOMENET_NET" ! -d "$HOMENET_NET" ! -d "$OUTNET_NET" -p tcp --dport "$p" -m conntrack --ctstate NEW -j ACCEPT
done

for p in "${EGRESS_UDP_PORTS[@]}"; do
  iptables -A FORWARD -s "$HOMENET_NET" ! -d "$HOMENET_NET" ! -d "$OUTNET_NET" -p udp --dport "$p" -m conntrack --ctstate NEW -j ACCEPT
done

for ip in "${ALLOWLIST_IPS[@]}"; do
  for p in "${ALLOWLIST_TCP_PORTS[@]}"; do
    iptables -A FORWARD -s "$HOMENET_NET" -d "$ip" -p tcp --dport "$p" -m conntrack --ctstate NEW -j ACCEPT
  done
  for p in "${ALLOWLIST_UDP_PORTS[@]}"; do
    iptables -A FORWARD -s "$HOMENET_NET" -d "$ip" -p udp --dport "$p" -m conntrack --ctstate NEW -j ACCEPT
  done
done

for h in "${WEB_HOSTS[@]}"; do
  iptables -A FORWARD -s "$OUTNET_NET" -d "$h" -p tcp --dport 80 -m conntrack --ctstate NEW -j ACCEPT
  iptables -A FORWARD -s "$OUTNET_NET" -d "$h" -p tcp --dport 443 -m conntrack --ctstate NEW -j ACCEPT
done

for h in "${JENKINS_HOSTS[@]}"; do
  iptables -A FORWARD -s "$OUTNET_NET" -d "$h" -p tcp --dport 8080 -m conntrack --ctstate NEW -j ACCEPT
  iptables -A FORWARD -s "$OUTNET_NET" -d "$h" -p tcp --dport 8443 -m conntrack --ctstate NEW -j ACCEPT
done

for h in "${FTP_HOSTS[@]}"; do
  iptables -A FORWARD -s "$OUTNET_NET" -d "$h" -p tcp --dport 21 -m conntrack --ctstate NEW -j ACCEPT
done

for h in "${MAIL_HOSTS[@]}"; do
  iptables -A FORWARD -s "$OUTNET_NET" -d "$h" -p tcp --dport 25 -m conntrack --ctstate NEW -j ACCEPT
  iptables -A FORWARD -s "$OUTNET_NET" -d "$h" -p tcp --dport 465 -m conntrack --ctstate NEW -j ACCEPT
  iptables -A FORWARD -s "$OUTNET_NET" -d "$h" -p tcp --dport 587 -m conntrack --ctstate NEW -j ACCEPT
  iptables -A FORWARD -s "$OUTNET_NET" -d "$h" -p tcp --dport 110 -m conntrack --ctstate NEW -j ACCEPT
  iptables -A FORWARD -s "$OUTNET_NET" -d "$h" -p tcp --dport 995 -m conntrack --ctstate NEW -j ACCEPT
  iptables -A FORWARD -s "$OUTNET_NET" -d "$h" -p tcp --dport 143 -m conntrack --ctstate NEW -j ACCEPT
  iptables -A FORWARD -s "$OUTNET_NET" -d "$h" -p tcp --dport 993 -m conntrack --ctstate NEW -j ACCEPT
done

for h in "${PUBLIC_SSH_HOSTS[@]}"; do
  iptables -A FORWARD -s "$OUTNET_NET" -d "$h" -p tcp --dport 22 -m conntrack --ctstate NEW -m hashlimit --hashlimit-mode srcip --hashlimit-name "ssh_$h" --hashlimit-above 15/minute --hashlimit-burst 10 -j DROP
  iptables -A FORWARD -s "$OUTNET_NET" -d "$h" -p tcp --dport 22 -m conntrack --ctstate NEW -j ACCEPT
done

for h in "${RDP_HOSTS[@]}"; do
  iptables -A FORWARD -s "$OUTNET_NET" -d "$h" -p tcp --dport 3389 -m conntrack --ctstate NEW -j ACCEPT
done

for h in "${WINRM_HOSTS[@]}"; do
  iptables -A FORWARD -s "$OUTNET_NET" -d "$h" -p tcp --dport 5985 -m conntrack --ctstate NEW -j ACCEPT
  iptables -A FORWARD -s "$OUTNET_NET" -d "$h" -p tcp --dport 5986 -m conntrack --ctstate NEW -j ACCEPT
done

for h in "${AD_HOSTS[@]}"; do
  iptables -A FORWARD -s "$OUTNET_NET" -d "$h" -p tcp --dport 53 -m conntrack --ctstate NEW -j ACCEPT
  iptables -A FORWARD -s "$OUTNET_NET" -d "$h" -p tcp --dport 88 -m conntrack --ctstate NEW -j ACCEPT
  iptables -A FORWARD -s "$OUTNET_NET" -d "$h" -p tcp --dport 135 -m conntrack --ctstate NEW -j ACCEPT
  iptables -A FORWARD -s "$OUTNET_NET" -d "$h" -p tcp --dport 139 -m conntrack --ctstate NEW -j ACCEPT
  iptables -A FORWARD -s "$OUTNET_NET" -d "$h" -p tcp --dport 389 -m conntrack --ctstate NEW -j ACCEPT
  iptables -A FORWARD -s "$OUTNET_NET" -d "$h" -p tcp --dport 445 -m conntrack --ctstate NEW -j ACCEPT
  iptables -A FORWARD -s "$OUTNET_NET" -d "$h" -p tcp --dport 464 -m conntrack --ctstate NEW -j ACCEPT
  iptables -A FORWARD -s "$OUTNET_NET" -d "$h" -p tcp --dport 636 -m conntrack --ctstate NEW -j ACCEPT
  iptables -A FORWARD -s "$OUTNET_NET" -d "$h" -p tcp --dport 3268 -m conntrack --ctstate NEW -j ACCEPT
  iptables -A FORWARD -s "$OUTNET_NET" -d "$h" -p tcp --dport 3269 -m conntrack --ctstate NEW -j ACCEPT
  iptables -A FORWARD -s "$OUTNET_NET" -d "$h" -p udp --dport 53 -m conntrack --ctstate NEW -j ACCEPT
  iptables -A FORWARD -s "$OUTNET_NET" -d "$h" -p udp --dport 88 -m conntrack --ctstate NEW -j ACCEPT
  iptables -A FORWARD -s "$OUTNET_NET" -d "$h" -p udp --dport 123 -m conntrack --ctstate NEW -j ACCEPT
  iptables -A FORWARD -s "$OUTNET_NET" -d "$h" -p udp --dport 137 -m conntrack --ctstate NEW -j ACCEPT
  iptables -A FORWARD -s "$OUTNET_NET" -d "$h" -p udp --dport 138 -m conntrack --ctstate NEW -j ACCEPT
  iptables -A FORWARD -s "$OUTNET_NET" -d "$h" -p udp --dport 389 -m conntrack --ctstate NEW -j ACCEPT
  iptables -A FORWARD -s "$OUTNET_NET" -d "$h" -p udp --dport 464 -m conntrack --ctstate NEW -j ACCEPT
done

for h in "${DB_HOSTS[@]}"; do
  iptables -A FORWARD -s "$OUTNET_NET" -d "$h" -p tcp --dport 3306 -m conntrack --ctstate NEW -j ACCEPT
  iptables -A FORWARD -s "$OUTNET_NET" -d "$h" -p tcp --dport 5432 -m conntrack --ctstate NEW -j ACCEPT
  iptables -A FORWARD -s "$OUTNET_NET" -d "$h" -p tcp --dport 1433 -m conntrack --ctstate NEW -j ACCEPT
  iptables -A FORWARD -s "$OUTNET_NET" -d "$h" -p tcp --dport 1521 -m conntrack --ctstate NEW -j ACCEPT
done

# ad hoc tcp opens from OUTNET -> HOMENET
for r in "${ADHOC_TCP_RULES[@]}"; do
  h="${r%%:*}"
  p="${r##*:}"
  iptables -A FORWARD -s "$OUTNET_NET" -d "$h" -p tcp --dport "$p" -m conntrack --ctstate NEW -j ACCEPT
done

# ad hoc udp opens from OUTNET -> HOMENET
for r in "${ADHOC_UDP_RULES[@]}"; do
  h="${r%%:*}"
  p="${r##*:}"
  iptables -A FORWARD -s "$OUTNET_NET" -d "$h" -p udp --dport "$p" -m conntrack --ctstate NEW -j ACCEPT
done

iptables -A FORWARD -s "$HOMENET_NET" -d "$OUTNET_NET" -j LOGDROP
iptables -A FORWARD -s "$OUTNET_NET" -d "$HOMENET_NET" -j LOGDROP
iptables -A FORWARD -s "$OUTNET_NET" ! -d "$HOMENET_NET" -j LOGDROP

iptables -A INPUT -j LOGDROP
iptables -A FORWARD -j LOGDROP

ip6tables -F 2>/dev/null || true
ip6tables -X 2>/dev/null || true
ip6tables -P INPUT DROP 2>/dev/null || true
ip6tables -P FORWARD DROP 2>/dev/null || true
ip6tables -P OUTPUT DROP 2>/dev/null || true

echo "[+] loaded"
iptables -S
echo
iptables -t nat -S


