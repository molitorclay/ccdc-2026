#!/usr/bin/env bash
set -euo pipefail

# =========================================
# SMALL LINUX HOST FIREWALL TEMPLATE
# SSH:
#   - allow from BASTION_IP
#   - block from HOMENET
#   - optional commented rule to allow from OUTNET
# Non-SSH traffic:
#   - allowed inbound
# =========================================

# -------------------------
# NETWORKS / HOSTS
# -------------------------
HOMENET_NET="10.10.10.0/24"
OUTNET_NET="192.168.50.0/24"
BASTION_IP="10.10.10.254"

# -------------------------
# BACKUP CURRENT RULES
# -------------------------
BACKUP_DIR="/root/fw-backups"
STAMP="$(date +%F-%H%M%S)"
BACKUP_FILE="${BACKUP_DIR}/iptables-host-${STAMP}.save"

mkdir -p "$BACKUP_DIR"
iptables-save > "$BACKUP_FILE"

echo "[+] Backup saved to: $BACKUP_FILE"
echo "[+] Restore with: iptables-restore < $BACKUP_FILE"

# -------------------------
# FLUSH FILTER RULES
# -------------------------
iptables -F
iptables -X

# -------------------------
# DEFAULT POLICIES
# -------------------------
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# -------------------------
# LOGGING CHAIN
# -------------------------
iptables -N LOGDROP
iptables -A LOGDROP -m limit --limit 6/min --limit-burst 10 \
    -j LOG --log-prefix "HOST DROP: " --log-level 4
iptables -A LOGDROP -j DROP

# -------------------------
# BASE RULES
# -------------------------
# Loopback
iptables -A INPUT -s 127.0.0.0/8 -d 127.0.0.0/8 -j ACCEPT

# Established / related
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Invalid
iptables -A INPUT -m conntrack --ctstate INVALID -j DROP

# -------------------------
# SSH RULES
# -------------------------

# Allow SSH from bastion only
iptables -A INPUT -p tcp -s "$BASTION_IP" --dport 22 \
    -m conntrack --ctstate NEW -j ACCEPT

# Explicitly block SSH from HOMENET
# Must come after bastion allow since bastion is inside HOMENET.
iptables -A INPUT -p tcp -s "$HOMENET_NET" --dport 22 -j LOGDROP

# Optional: allow SSH from OUTNET
# Uncomment ONLY if required.
# iptables -A INPUT -p tcp -s "$OUTNET_NET" --dport 22 \
#     -m conntrack --ctstate NEW -j ACCEPT

# Optional: rate-limited SSH from OUTNET instead
# Uncomment these instead of the rule above if needed.
# iptables -A INPUT -p tcp -s "$OUTNET_NET" --dport 22 \
#     -m conntrack --ctstate NEW \
#     -m hashlimit --hashlimit-mode srcip \
#     --hashlimit-name host_ssh \
#     --hashlimit-above 15/minute --hashlimit-burst 10 \
#     -j DROP
# iptables -A INPUT -p tcp -s "$OUTNET_NET" --dport 22 \
#     -m conntrack --ctstate NEW -j ACCEPT

# Block all other SSH
iptables -A INPUT -p tcp --dport 22 -j LOGDROP

# -------------------------
# ALLOW ALL NON-SSH INBOUND
# -------------------------

# Allow all other TCP traffic
iptables -A INPUT -p tcp ! --dport 22 -j ACCEPT

# Allow all UDP traffic
iptables -A INPUT -p udp -j ACCEPT

# Allow ICMP
iptables -A INPUT -p icmp -j ACCEPT

# -------------------------
# CATCH-ALL
# -------------------------
iptables -A INPUT -j LOGDROP

echo "[+] Host firewall loaded."
iptables -S
