#!/bin/bash
# ==============================================
# 🔒 Script de sécurisation VPS (Ubuntu/Debian) - Version améliorée
# ==============================================

set -euo pipefail  # Exit on error, undefined var, pipe failure
IFS=$'\n\t'

# --- Configuration ---
readonly SCRIPT_VERSION="2.0"
readonly SSH_PORT=28
readonly LOG_FILE="/var/log/vps-secure-$(date +%Y%m%d-%H%M%S).log"
readonly BACKUP_DIR="/root/config-backup-$(date +%Y%m%d-%H%M%S)"

# --- Couleurs pour l'affichage ---
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly NC='\033[0m' # No Color

# --- Fonctions utilitaires ---
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $*" | tee -a "$LOG_FILE"
}

log_error() {
    echo -e "${RED}[ERREUR]${NC} $*" | tee -a "$LOG_FILE" >&2
}

log_warning() {
    echo -e "${YELLOW}[ATTENTION]${NC} $*" | tee -a "$LOG_FILE"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "Ce script doit être exécuté en tant que root (sudo)"
        exit 1
    fi
}

backup_file() {
    local file="$1"
    if [[ -f "$file" ]]; then
        mkdir -p "$BACKUP_DIR"
        cp -a "$file" "$BACKUP_DIR/" || {
            log_error "Impossible de sauvegarder $file"
            return 1
        }
        log "Backup de $file créé dans $BACKUP_DIR"
    fi
}

validate_username() {
    local username="$1"
    if [[ ! "$username" =~ ^[a-z_][a-z0-9_-]{2,31}$ ]]; then
        log_error "Nom d'utilisateur invalide. Utilisez uniquement des lettres minuscules, chiffres, - et _"
        return 1
    fi
    if id "$username" &>/dev/null; then
        log_error "L'utilisateur $username existe déjà"
        return 1
    fi
    return 0
}

validate_port() {
    local port="$1"
    if [[ ! "$port" =~ ^[0-9]+$ ]] || [[ "$port" -lt 1024 ]] || [[ "$port" -gt 65535 ]]; then
        log_error "Port invalide. Utilisez un port entre 1024 et 65535"
        return 1
    fi
    return 0
}

# --- Vérifications initiales ---
check_root

log "=== 🚀 Début de la sécurisation VPS - Version $SCRIPT_VERSION ==="
log "Les logs seront sauvegardés dans : $LOG_FILE"

# Vérifier la distribution
if ! grep -qE "Ubuntu|Debian" /etc/os-release; then
    log_warning "Ce script est conçu pour Ubuntu/Debian. Continuer ? (y/n)"
    read -r response
    [[ ! "$response" =~ ^[Yy]$ ]] && exit 0
fi

# --- Mise à jour du système ---
log "=== 🔧 Mise à jour du système ==="
apt update -y || { log_error "Échec de apt update"; exit 1; }
DEBIAN_FRONTEND=noninteractive apt upgrade -y || log_warning "Certaines mises à jour ont échoué"

# --- Création d'un utilisateur non-root ---
log "=== 👤 Création d'un utilisateur administrateur ==="
while true; do
    read -rp "Entrez le nom du nouvel utilisateur admin (ex: adminvps) : " NEWUSER
    if validate_username "$NEWUSER"; then
        break
    fi
done

adduser --gecos "" "$NEWUSER" || { log_error "Échec de création de l'utilisateur"; exit 1; }
usermod -aG sudo "$NEWUSER"
log "Utilisateur $NEWUSER créé et ajouté au groupe sudo"

# Configurer SSH key (optionnel mais recommandé)
read -rp "Voulez-vous configurer une clé SSH pour $NEWUSER ? (y/n) : " setup_key
if [[ "$setup_key" =~ ^[Yy]$ ]]; then
    su - "$NEWUSER" -c "mkdir -p ~/.ssh && chmod 700 ~/.ssh"
    log "Entrez votre clé SSH publique (ou laissez vide pour sauter) :"
    read -r ssh_key
    if [[ -n "$ssh_key" ]]; then
        echo "$ssh_key" | su - "$NEWUSER" -c "tee ~/.ssh/authorized_keys > /dev/null"
        su - "$NEWUSER" -c "chmod 600 ~/.ssh/authorized_keys"
        log "Clé SSH configurée pour $NEWUSER"
    fi
fi

# --- Sécurisation SSH ---
log "=== 🔐 Configuration SSH ==="
backup_file "/etc/ssh/sshd_config"

# Utiliser un port personnalisé ?
read -rp "Utiliser le port SSH $SSH_PORT ? (y pour oui, n pour choisir) : " use_default_port
CUSTOM_SSH_PORT="$SSH_PORT"
if [[ ! "$use_default_port" =~ ^[Yy]$ ]]; then
    while true; do
        read -rp "Entrez le nouveau port SSH (1024-65535) : " CUSTOM_SSH_PORT
        if validate_port "$CUSTOM_SSH_PORT"; then
            break
        fi
    done
fi

# Configuration SSH sécurisée
cat >> /etc/ssh/sshd_config.d/99-custom-security.conf <<EOF
# Configuration de sécurité personnalisée
Port $CUSTOM_SSH_PORT
PermitRootLogin no
PasswordAuthentication yes
PubkeyAuthentication yes
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding no
MaxAuthTries 3
MaxSessions 5
ClientAliveInterval 300
ClientAliveCountMax 2
AllowUsers $NEWUSER
Protocol 2
EOF

# Tester la configuration SSH avant de redémarrer
if sshd -t; then
    systemctl restart ssh || systemctl restart sshd
    log "SSH configuré sur le port $CUSTOM_SSH_PORT (root désactivé)"
else
    log_error "Configuration SSH invalide ! Restauration du backup..."
    cp "$BACKUP_DIR/sshd_config" /etc/ssh/sshd_config
    exit 1
fi

log_warning "IMPORTANT : Testez la connexion SSH dans une nouvelle session AVANT de fermer celle-ci !"
log_warning "Commande : ssh $NEWUSER@$(hostname -I | awk '{print $1}') -p $CUSTOM_SSH_PORT"

# --- UFW Firewall ---
log "=== 🔥 Configuration du pare-feu UFW ==="
apt install ufw -y

# Désactiver UFW temporairement pour configuration
ufw --force disable

# Configuration par défaut
ufw default deny incoming
ufw default allow outgoing

# Règles de base
ufw allow "$CUSTOM_SSH_PORT"/tcp comment "SSH"
ufw allow 80/tcp comment "HTTP"
ufw allow 443/tcp comment "HTTPS"

# Limiter les tentatives SSH
ufw limit "$CUSTOM_SSH_PORT"/tcp

# IPv6
if [[ -f /proc/net/if_inet6 ]]; then
    sed -i 's/IPV6=no/IPV6=yes/' /etc/default/ufw
    log "Support IPv6 activé"
fi

# Activer UFW
echo "y" | ufw enable
ufw status numbered

log "Pare-feu UFW configuré et activé"

# --- Fail2Ban ---
log "=== 🧱 Installation de Fail2ban ==="
apt install fail2ban -y

backup_file "/etc/fail2ban/jail.local"

# Configuration avancée de Fail2ban
cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 5
destemail = root@localhost
sendername = Fail2Ban
action = %(action_mwl)s

[sshd]
enabled = true
port = $CUSTOM_SSH_PORT
filter = sshd
logpath = /var/log/auth.log
maxretry = 5
bantime = 1h
findtime = 10m

[sshd-ddos]
enabled = true
port = $CUSTOM_SSH_PORT
filter = sshd-ddos
logpath = /var/log/auth.log
maxretry = 10
bantime = 1h
findtime = 2m
EOF

systemctl enable fail2ban
systemctl restart fail2ban

log "Fail2ban configuré et actif"

# --- Protection système supplémentaire ---
log "=== 🛡️ Durcissement du système ==="

# Désactiver les services inutiles
systemctl disable --now avahi-daemon 2>/dev/null || true
systemctl disable --now cups 2>/dev/null || true

# Sysctl sécurité
backup_file "/etc/sysctl.conf"

cat >> /etc/sysctl.d/99-security.conf <<EOF
# Protection réseau
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5

# IPv6
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Protection mémoire
kernel.randomize_va_space = 2
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
EOF

sysctl -p /etc/sysctl.d/99-security.conf

log "Paramètres de sécurité système appliqués"

# --- Netdata sécurisé ---
log "=== 📊 Installation de Netdata (monitoring) ==="

read -rp "Installer Netdata ? (y/n) : " install_netdata
if [[ "$install_netdata" =~ ^[Yy]$ ]]; then
    # Installation non-interactive
    bash <(curl -Ss https://my-netdata.io/kickstart.sh) --dont-wait --disable-telemetry

    # Sécuriser Netdata - écouter uniquement sur localhost
    cat > /etc/netdata/netdata.conf <<EOF
[web]
    bind to = 127.0.0.1
EOF

    systemctl restart netdata

    log "Netdata installé et configuré pour écouter uniquement sur localhost"
    log "Pour y accéder, créez un tunnel SSH : ssh -L 19999:localhost:19999 $NEWUSER@votre_ip -p $CUSTOM_SSH_PORT"
    log "Puis accédez à http://localhost:19999 sur votre machine locale"
fi

# --- Mises à jour automatiques ---
log "=== 🔄 Configuration des mises à jour automatiques de sécurité ==="
apt install unattended-upgrades apt-listchanges -y

cat > /etc/apt/apt.conf.d/50unattended-upgrades <<EOF
Unattended-Upgrade::Allowed-Origins {
    "\${distro_id}:\${distro_codename}-security";
    "\${distro_id}ESMApps:\${distro_codename}-apps-security";
    "\${distro_id}ESM:\${distro_codename}-infra-security";
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
EOF

echo 'APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";' > /etc/apt/apt.conf.d/20auto-upgrades

log "Mises à jour automatiques de sécurité configurées"

# --- Résumé final ---
log "=== ✅ Configuration terminée avec succès ==="
echo ""
echo "=========================================="
echo "   🔒 RÉSUMÉ DE LA CONFIGURATION"
echo "=========================================="
echo "🧍 Utilisateur admin    : $NEWUSER"
echo "🔐 Port SSH             : $CUSTOM_SSH_PORT"
echo "🔥 Pare-feu UFW         : Activé"
echo "🧱 Fail2ban             : Actif"
echo "🛡️  Sysctl hardening    : Appliqué"
echo "🔄 MAJ auto sécurité    : Activées"
if [[ "$install_netdata" =~ ^[Yy]$ ]]; then
    echo "📊 Netdata              : Installé (localhost uniquement)"
fi
echo "📝 Logs                 : $LOG_FILE"
echo "💾 Backups config       : $BACKUP_DIR"
echo "=========================================="
echo ""
log_warning "IMPORTANT - ACTIONS REQUISES :"
echo "1. Testez la connexion SSH dans un NOUVEL onglet AVANT de fermer celui-ci :"
echo "   ssh $NEWUSER@$(hostname -I | awk '{print $1}') -p $CUSTOM_SSH_PORT"
echo ""
echo "2. Si la connexion fonctionne, vous pouvez redémarrer le serveur :"
echo "   sudo reboot"
echo ""
echo "3. En cas de problème, les backups sont dans : $BACKUP_DIR"
echo ""
log "Script terminé. Consultez les logs pour plus de détails."
