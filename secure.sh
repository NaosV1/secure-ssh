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
    # Nettoyer les espaces
    username="${username// /}"

    # Vérifier si vide
    if [[ -z "$username" ]]; then
        log_error "Le nom d'utilisateur ne peut pas être vide"
        return 1
    fi

    # Vérifier le format (3-32 caractères, commence par lettre ou _, contient lettres, chiffres, - ou _)
    if [[ ! "$username" =~ ^[a-z_][a-z0-9_-]{2,31}$ ]]; then
        log_error "Nom invalide. Format: 3-32 caractères, commence par lettre minuscule ou _, puis lettres, chiffres, - ou _"
        log_error "Exemples valides: admin, adminvps, webmaster, deploy_user"
        return 1
    fi

    # Vérifier si l'utilisateur existe déjà
    if id "$username" &>/dev/null; then
        log_error "L'utilisateur '$username' existe déjà"
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
    read -r response < /dev/tty
    [[ ! "$response" =~ ^[Yy]$ ]] && exit 0
fi

# --- Mise à jour du système ---
log "=== 🔧 Mise à jour du système ==="
apt update -y || { log_error "Échec de apt update"; exit 1; }
DEBIAN_FRONTEND=noninteractive apt upgrade -y || log_warning "Certaines mises à jour ont échoué"

# --- Création d'un utilisateur non-root ---
log "=== 👤 Création d'un utilisateur administrateur ==="

# Permettre de passer le nom d'utilisateur via variable d'environnement
if [[ -n "${VPS_USER:-}" ]]; then
    NEWUSER="$VPS_USER"
    log "Utilisation du nom d'utilisateur depuis VPS_USER: $NEWUSER"
    if ! validate_username "$NEWUSER"; then
        log_error "Le nom d'utilisateur fourni via VPS_USER est invalide"
        exit 1
    fi
else
    echo "Le nom doit : commencer par une lettre minuscule ou _, contenir 3-32 caractères (lettres, chiffres, - ou _)"
    while true; do
        read -rp "Entrez le nom du nouvel utilisateur admin (ex: adminvps) : " NEWUSER < /dev/tty
        # Nettoyer les espaces au début et à la fin (compatible avec pipe)
        NEWUSER="${NEWUSER#"${NEWUSER%%[![:space:]]*}"}"  # Supprimer espaces au début
        NEWUSER="${NEWUSER%"${NEWUSER##*[![:space:]]}"}"  # Supprimer espaces à la fin
        if validate_username "$NEWUSER"; then
            break
        fi
        echo ""
    done
fi

# Créer l'utilisateur sans mot de passe (SSH key uniquement)
adduser --disabled-password --gecos "" "$NEWUSER" || { log_error "Échec de création de l'utilisateur"; exit 1; }
usermod -aG sudo "$NEWUSER"

log "Utilisateur $NEWUSER créé et ajouté au groupe sudo"

# Configuration OBLIGATOIRE de la clé SSH (authentification par clé uniquement)
log "=== 🔑 Configuration de la clé SSH (OBLIGATOIRE) ==="
log_warning "Ce serveur utilisera UNIQUEMENT l'authentification par clé SSH (pas de mot de passe)"

SSH_KEY_CONFIGURED=false

# Permettre de passer la clé SSH via variable d'environnement
if [[ -n "${VPS_SSH_KEY:-}" ]]; then
    log "Utilisation de la clé SSH depuis VPS_SSH_KEY"
    su - "$NEWUSER" -c "mkdir -p ~/.ssh && chmod 700 ~/.ssh"
    echo "$VPS_SSH_KEY" | su - "$NEWUSER" -c "tee ~/.ssh/authorized_keys > /dev/null"
    su - "$NEWUSER" -c "chmod 600 ~/.ssh/authorized_keys"
    log "Clé SSH configurée avec succès depuis VPS_SSH_KEY"
    SSH_KEY_CONFIGURED=true
else
    # Demander la clé SSH interactivement
    echo ""
    log "Vous devez fournir votre clé SSH publique pour pouvoir vous connecter"
    log "Où se trouve votre clé SSH publique ?"
    echo "1) Je vais la coller maintenant"
    echo "2) Elle est dans ~/.ssh/id_rsa.pub (ou id_ed25519.pub) sur ce serveur"
    echo "3) Je veux la générer maintenant"

    read -rp "Choix (1/2/3) : " ssh_key_choice < /dev/tty

    case "$ssh_key_choice" in
        1)
            log "Collez votre clé SSH publique (commence par ssh-rsa ou ssh-ed25519) :"
            read -r ssh_key < /dev/tty
            if [[ -n "$ssh_key" ]]; then
                su - "$NEWUSER" -c "mkdir -p ~/.ssh && chmod 700 ~/.ssh"
                echo "$ssh_key" | su - "$NEWUSER" -c "tee ~/.ssh/authorized_keys > /dev/null"
                su - "$NEWUSER" -c "chmod 600 ~/.ssh/authorized_keys"
                log "Clé SSH configurée avec succès"
                SSH_KEY_CONFIGURED=true
            fi
            ;;
        2)
            # Copier depuis l'utilisateur root actuel
            if [[ -f ~/.ssh/id_rsa.pub ]]; then
                su - "$NEWUSER" -c "mkdir -p ~/.ssh && chmod 700 ~/.ssh"
                cat ~/.ssh/id_rsa.pub | su - "$NEWUSER" -c "tee ~/.ssh/authorized_keys > /dev/null"
                su - "$NEWUSER" -c "chmod 600 ~/.ssh/authorized_keys"
                log "Clé SSH copiée depuis ~/.ssh/id_rsa.pub"
                SSH_KEY_CONFIGURED=true
            elif [[ -f ~/.ssh/id_ed25519.pub ]]; then
                su - "$NEWUSER" -c "mkdir -p ~/.ssh && chmod 700 ~/.ssh"
                cat ~/.ssh/id_ed25519.pub | su - "$NEWUSER" -c "tee ~/.ssh/authorized_keys > /dev/null"
                su - "$NEWUSER" -c "chmod 600 ~/.ssh/authorized_keys"
                log "Clé SSH copiée depuis ~/.ssh/id_ed25519.pub"
                SSH_KEY_CONFIGURED=true
            else
                log_error "Aucune clé SSH trouvée dans ~/.ssh/"
            fi
            ;;
        3)
            log "Génération d'une nouvelle paire de clés SSH..."
            su - "$NEWUSER" -c "ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519 -N '' -C '$NEWUSER@$(hostname)'"
            su - "$NEWUSER" -c "mkdir -p ~/.ssh && chmod 700 ~/.ssh"
            su - "$NEWUSER" -c "cat ~/.ssh/id_ed25519.pub > ~/.ssh/authorized_keys"
            su - "$NEWUSER" -c "chmod 600 ~/.ssh/authorized_keys"
            log "Clé SSH générée avec succès"
            log_warning "IMPORTANT : Copiez la clé privée ci-dessous sur votre machine locale !"
            echo "========== CLÉ PRIVÉE (À SAUVEGARDER) =========="
            su - "$NEWUSER" -c "cat ~/.ssh/id_ed25519"
            echo "=================================================="
            log_warning "Sauvegardez cette clé dans un fichier sur votre machine locale (ex: ~/.ssh/vps_key)"
            log_warning "Puis utilisez : ssh -i ~/.ssh/vps_key $NEWUSER@IP -p PORT"
            read -rp "Appuyez sur Entrée une fois que vous avez sauvegardé la clé..." < /dev/tty
            SSH_KEY_CONFIGURED=true
            ;;
        *)
            log_error "Choix invalide"
            ;;
    esac
fi

# Vérifier que la clé SSH a bien été configurée
if [[ "$SSH_KEY_CONFIGURED" != "true" ]]; then
    log_error "ERREUR CRITIQUE : Aucune clé SSH configurée !"
    log_error "Vous ne pourrez pas vous connecter après la désactivation du mot de passe"
    log_error "Le script va s'arrêter pour éviter de vous bloquer"
    exit 1
fi

log "Clé SSH configurée avec succès pour $NEWUSER"

# --- Sécurisation SSH ---
log "=== 🔐 Configuration SSH ==="
backup_file "/etc/ssh/sshd_config"

# Utiliser un port personnalisé ?
if [[ -n "${VPS_SSH_PORT:-}" ]]; then
    if validate_port "$VPS_SSH_PORT"; then
        CUSTOM_SSH_PORT="$VPS_SSH_PORT"
        log "Port SSH défini via VPS_SSH_PORT : $CUSTOM_SSH_PORT"
    else
        log_error "VPS_SSH_PORT invalide : $VPS_SSH_PORT. Utilisation du port par défaut $SSH_PORT."
        CUSTOM_SSH_PORT="$SSH_PORT"
    fi
else
    read -rp "Utiliser le port SSH $SSH_PORT ? (y pour oui, n pour choisir) : " use_default_port < /dev/tty
    CUSTOM_SSH_PORT="$SSH_PORT"
    if [[ ! "$use_default_port" =~ ^[Yy]$ ]]; then
        while true; do
            read -rp "Entrez le nouveau port SSH (1024-65535) : " CUSTOM_SSH_PORT < /dev/tty
            if validate_port "$CUSTOM_SSH_PORT"; then
                break
            fi
        done
    fi
fi

# Configuration SSH sécurisée - AUTHENTIFICATION PAR CLÉ UNIQUEMENT
cat >> /etc/ssh/sshd_config.d/99-custom-security.conf <<EOF
# Configuration de sécurité personnalisée - SSH Key Only
Port $CUSTOM_SSH_PORT
PermitRootLogin no

# Authentification par clé SSH UNIQUEMENT (pas de mot de passe)
PubkeyAuthentication yes
PasswordAuthentication no
ChallengeResponseAuthentication no
KbdInteractiveAuthentication no
UsePAM yes

# Restrictions de sécurité
X11Forwarding no
MaxAuthTries 3
MaxSessions 5
ClientAliveInterval 300
ClientAliveCountMax 2
AllowUsers $NEWUSER

# Désactiver les méthodes d'authentification faibles
PermitEmptyPasswords no
AuthenticationMethods publickey
EOF

# Tester la configuration SSH avant de redémarrer
if sshd -t; then
    systemctl restart ssh || systemctl restart sshd
    log "SSH configuré sur le port $CUSTOM_SSH_PORT"
    log "Authentification par clé SSH UNIQUEMENT (mot de passe désactivé)"
else
    log_error "Configuration SSH invalide ! Restauration du backup..."
    cp "$BACKUP_DIR/sshd_config" /etc/ssh/sshd_config
    exit 1
fi

echo ""
log_warning "╔════════════════════════════════════════════════════════════════╗"
log_warning "║  ATTENTION : AUTHENTIFICATION PAR CLÉ SSH UNIQUEMENT          ║"
log_warning "╚════════════════════════════════════════════════════════════════╝"
echo ""
log_warning "⚠️  L'authentification par mot de passe est DÉSACTIVÉE"
log_warning "⚠️  Vous DEVEZ utiliser votre clé SSH pour vous connecter"
echo ""
log_warning "🔑 Commande de connexion :"
echo "   ssh $NEWUSER@$(hostname -I | awk '{print $1}') -p $CUSTOM_SSH_PORT"
echo ""
log_warning "📋 AVANT DE FERMER CETTE SESSION :"
echo "   1. Ouvrez un NOUVEL onglet/terminal"
echo "   2. Testez la connexion avec la commande ci-dessus"
echo "   3. SEULEMENT si ça fonctionne, fermez cette session"
echo ""

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

if [[ -n "${VPS_INSTALL_NETDATA:-}" ]]; then
    install_netdata="$VPS_INSTALL_NETDATA"
else
    read -rp "Installer Netdata ? (y/n) : " install_netdata < /dev/tty
fi
if [[ "$install_netdata" =~ ^[Yy]$ ]]; then
    log "Installation de Netdata..."

    # Télécharger et installer Netdata avec l'URL correcte
    if curl -fsSL https://get.netdata.cloud/kickstart.sh | bash -s -- --non-interactive --disable-telemetry; then
        # Attendre que Netdata soit installé
        sleep 5

        # Sécuriser Netdata - écouter uniquement sur localhost
        if [[ -f /etc/netdata/netdata.conf ]]; then
            # Backup de la config par défaut
            backup_file "/etc/netdata/netdata.conf"

            # Créer la configuration personnalisée
            cat > /etc/netdata/netdata.conf <<EOF
[global]
    bind to = 127.0.0.1

[web]
    bind to = 127.0.0.1
EOF

            # Redémarrer Netdata
            systemctl restart netdata 2>/dev/null || service netdata restart 2>/dev/null || true

            log "Netdata installé et configuré pour écouter uniquement sur localhost"
            log "Pour y accéder, créez un tunnel SSH : ssh -L 19999:localhost:19999 $NEWUSER@votre_ip -p $CUSTOM_SSH_PORT"
            log "Puis accédez à http://localhost:19999 sur votre machine locale"
        else
            log_warning "Netdata installé mais fichier de configuration non trouvé"
        fi
    else
        log_error "Échec de l'installation de Netdata"
        log_warning "Vous pouvez l'installer manuellement plus tard avec : bash <(curl -Ss https://get.netdata.cloud/kickstart.sh)"
    fi
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
echo "🔑 Auth SSH             : Clé uniquement (mot de passe DÉSACTIVÉ)"
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
log_warning "╔════════════════════════════════════════════════════════════════╗"
log_warning "║          IMPORTANT - ACTIONS REQUISES IMMÉDIATEMENT           ║"
log_warning "╚════════════════════════════════════════════════════════════════╝"
echo ""
log_warning "⚠️  ATTENTION : Authentification par MOT DE PASSE DÉSACTIVÉE !"
log_warning "⚠️  Seule l'authentification par CLÉ SSH est autorisée"
echo ""
echo "1️⃣  NE FERMEZ PAS cette session SSH maintenant !"
echo ""
echo "2️⃣  Ouvrez un NOUVEL onglet/terminal et testez la connexion :"
echo "    ssh $NEWUSER@$(hostname -I | awk '{print $1}') -p $CUSTOM_SSH_PORT"
echo ""
echo "3️⃣  Si la connexion fonctionne ✅, vous pouvez :"
echo "    - Fermer cette ancienne session"
echo "    - Optionnel : Redémarrer le serveur (sudo reboot)"
echo ""
echo "4️⃣  Si la connexion échoue ❌ :"
echo "    - Gardez cette session ouverte"
echo "    - Restaurez : sudo cp $BACKUP_DIR/sshd_config /etc/ssh/sshd_config"
echo "    - Redémarrez SSH : sudo systemctl restart ssh"
echo ""
log_warning "📌 Si vous êtes bloqué, accédez via la console web de votre hébergeur"
echo ""
log "Script terminé. Consultez les logs pour plus de détails : $LOG_FILE"
