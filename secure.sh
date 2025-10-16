#!/bin/bash
# ==============================================
# 🔒 Script de sécurisation VPS (Ubuntu/Debian)
# ==============================================

# --- Variables ---
SSH_PORT=28

echo "=== 🔧 Mise à jour du système ==="
apt update -y && apt upgrade -y

# --- Création d’un utilisateur non-root ---
read -p "Entrez le nom du nouvel utilisateur admin (ex: adminvps) : " NEWUSER
adduser $NEWUSER
usermod -aG sudo $NEWUSER

# --- Sécurisation SSH ---
echo "=== 🔐 Configuration SSH ==="
sed -i "s/#Port 22/Port $SSH_PORT/g" /etc/ssh/sshd_config
sed -i "s/Port 22/Port $SSH_PORT/g" /etc/ssh/sshd_config
sed -i "s/#PermitRootLogin yes/PermitRootLogin no/g" /etc/ssh/sshd_config
sed -i "s/PermitRootLogin yes/PermitRootLogin no/g" /etc/ssh/sshd_config
sed -i "s/#PasswordAuthentication yes/PasswordAuthentication yes/g" /etc/ssh/sshd_config

systemctl restart ssh

echo "✅ SSH configuré sur le port $SSH_PORT (root désactivé)"
echo "⚠️ Pense à te reconnecter avec : ssh $NEWUSER@ton_ip -p $SSH_PORT"

# --- UFW Firewall ---
echo "=== 🔥 Configuration du pare-feu UFW ==="
apt install ufw -y
ufw default deny incoming
ufw default allow outgoing
ufw allow $SSH_PORT/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw enable
ufw status

# --- Fail2Ban ---
echo "=== 🧱 Installation de Fail2ban ==="
apt install fail2ban -y
systemctl enable fail2ban
systemctl start fail2ban

# Configuration de base
cat <<EOF >/etc/fail2ban/jail.local
[sshd]
enabled = true
port = $SSH_PORT
filter = sshd
logpath = /var/log/auth.log
maxretry = 5
bantime = 1h
findtime = 10m
EOF

systemctl restart fail2ban

echo "✅ Fail2ban configuré et actif"

# --- iptables Anti-DDoS ---
echo "=== ⚔️ Configuration iptables anti-DDoS ==="

# Nettoyage des anciennes règles
iptables -F
iptables -X

# Bloquer les connexions invalides
iptables -A INPUT -m conntrack --ctstate INVALID -j DROP

# Limiter ICMP (ping)
iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s -j ACCEPT
iptables -A INPUT -p icmp --icmp-type echo-request -j DROP

# Limiter les connexions simultanées par IP
iptables -A INPUT -p tcp --syn --dport 80 -m connlimit --connlimit-above 20 -j DROP

# Limiter le nombre de nouvelles connexions
iptables -A INPUT -p tcp --dport 80 -m limit --limit 25/second --limit-burst 100 -j ACCEPT
iptables -A INPUT -p tcp --dport 80 -j DROP

# Bloquer les scans de port (SYN flood)
iptables -A INPUT -p tcp ! --syn -m state --state NEW -j DROP

# Sauvegarde
apt install iptables-persistent -y
netfilter-persistent save
netfilter-persistent reload

echo "✅ Règles iptables anti-DDoS appliquées"

# --- Netdata ---
echo "=== 📊 Installation de Netdata (monitoring) ==="
bash <(curl -Ss https://my-netdata.io/kickstart.sh) --dont-wait

echo "✅ Netdata installé (accès via http://[ton_ip]:19999)"

# --- Résumé ---
echo "=== ✅ Configuration terminée ==="
echo "🧍 Nouvel utilisateur admin : $NEWUSER"
echo "🔐 SSH port : $SSH_PORT"
echo "🔥 UFW + Fail2ban + iptables activés"
echo "📡 Monitoring : Netdata sur port 19999"
echo "⚠️ Redémarre le VPS après vérification : sudo reboot"
