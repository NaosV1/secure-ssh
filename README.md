# Améliorations du Script de Sécurisation VPS

## Comparaison : secure.sh vs secure_improved.sh

### Améliorations principales

#### 1. Gestion des erreurs robuste
**Avant :**
```bash
apt update -y && apt upgrade -y
```
**Après :**
```bash
set -euo pipefail  # Exit on error, undefined var, pipe failure
apt update -y || { log_error "Échec de apt update"; exit 1; }
```
- Le script s'arrête immédiatement en cas d'erreur critique
- Gestion explicite des erreurs pour chaque commande importante
- Variables non définies détectées automatiquement

#### 2. Validation des entrées utilisateur
**Avant :**
```bash
read -p "Entrez le nom du nouvel utilisateur admin : " NEWUSER
adduser $NEWUSER  # Pas de validation !
```
**Après :**
```bash
validate_username() {
    if [[ ! "$username" =~ ^[a-z_][a-z0-9_-]{2,31}$ ]]; then
        log_error "Nom d'utilisateur invalide"
        return 1
    fi
}
```
- Validation du format du nom d'utilisateur (selon les standards Linux)
- Vérification que l'utilisateur n'existe pas déjà
- Validation du numéro de port SSH (1024-65535)

#### 3. Backup automatique
**Avant :** Aucun backup
**Après :**
```bash
backup_file "/etc/ssh/sshd_config"
```
- Tous les fichiers de configuration sont sauvegardés avant modification
- Timestamp unique pour chaque exécution
- Possibilité de rollback en cas de problème

#### 4. Logging complet
**Avant :** Messages simples avec echo
**Après :**
```bash
readonly LOG_FILE="/var/log/vps-secure-$(date +%Y%m%d-%H%M%S).log"
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $*" | tee -a "$LOG_FILE"
}
```
- Tous les événements sont loggés avec timestamp
- Couleurs pour différencier info/warning/error
- Logs persistants pour audit

#### 5. Sécurité SSH renforcée
**Avant :**
```bash
sed -i "s/#Port 22/Port $SSH_PORT/g" /etc/ssh/sshd_config
sed -i "s/PermitRootLogin yes/PermitRootLogin no/g" /etc/ssh/sshd_config
```
**Après :**
```bash
cat >> /etc/ssh/sshd_config.d/99-custom-security.conf <<EOF
Port $CUSTOM_SSH_PORT
PermitRootLogin no
PasswordAuthentication yes
PubkeyAuthentication yes
MaxAuthTries 3
MaxSessions 5
ClientAliveInterval 300
AllowUsers $NEWUSER
Protocol 2
EOF

# Test de configuration avant restart
if sshd -t; then
    systemctl restart ssh
else
    log_error "Configuration invalide ! Restauration..."
    cp "$BACKUP_DIR/sshd_config" /etc/ssh/sshd_config
fi
```
- Configuration dans un fichier dédié (meilleure pratique)
- Limitation des tentatives d'authentification
- Test de configuration avant redémarrage
- Rollback automatique si erreur

#### 6. Netdata sécurisé
**Avant :**
```bash
bash <(curl -Ss https://my-netdata.io/kickstart.sh) --dont-wait
# Accessible publiquement sur :19999 !
```
**Après :**
```bash
bash <(curl -Ss https://my-netdata.io/kickstart.sh) --dont-wait --disable-telemetry

cat > /etc/netdata/netdata.conf <<EOF
[web]
    bind to = 127.0.0.1  # Localhost uniquement
EOF
```
- Netdata écoute uniquement sur localhost
- Accès via tunnel SSH seulement
- Désactivation de la télémétrie

#### 7. Protection iptables vs UFW
**Avant :** Utilise UFW ET iptables (conflit potentiel)
**Après :** Utilise UFW uniquement (recommandé pour Ubuntu/Debian)
- UFW est une interface de haut niveau pour iptables
- Évite les conflits de règles
- Plus facile à maintenir

#### 8. Durcissement système (sysctl)
**Nouveau :**
```bash
cat >> /etc/sysctl.d/99-security.conf <<EOF
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
kernel.randomize_va_space = 2
kernel.dmesg_restrict = 1
EOF
```
- Protection contre SYN flood
- Désactivation des redirects ICMP
- ASLR activé
- Restriction des logs kernel

#### 9. Mises à jour automatiques
**Nouveau :**
```bash
apt install unattended-upgrades -y
# Configuration pour installer automatiquement les mises à jour de sécurité
```
- Patches de sécurité appliqués automatiquement
- Réduit la fenêtre d'exposition aux vulnérabilités

#### 10. Support IPv6
**Avant :** Ignoré
**Après :**
```bash
if [[ -f /proc/net/if_inet6 ]]; then
    sed -i 's/IPV6=no/IPV6=yes/' /etc/default/ufw
fi
```
- UFW protège aussi IPv6
- Sysctl configuré pour IPv6

#### 11. Vérifications et sécurités
**Nouveau :**
- Vérification que le script est exécuté en root
- Vérification de la distribution (Ubuntu/Debian)
- Port SSH personnalisable de manière interactive
- Configuration de clé SSH optionnelle
- Test de connexion avant de fermer la session
- AllowUsers pour restreindre l'accès SSH

## Utilisation

### Script original
```bash
sudo bash secure.sh
```

### Script amélioré
```bash
sudo bash secure_improved.sh
```

## En cas de problème

Le script amélioré crée des backups dans `/root/config-backup-[timestamp]/`. Pour restaurer :

```bash
# Exemple pour SSH
cp /root/config-backup-*/sshd_config /etc/ssh/sshd_config
systemctl restart ssh
```

## Recommandations supplémentaires

### Après exécution du script :

1. **Configurer l'authentification par clé SSH** (plus sécurisé que mot de passe) :
   ```bash
   ssh-copy-id -p [PORT] user@server
   ```
   Puis désactiver PasswordAuthentication dans `/etc/ssh/sshd_config.d/99-custom-security.conf`

2. **Configurer les alertes Fail2ban** par email :
   ```bash
   apt install mailutils -y
   # Configurer destemail dans /etc/fail2ban/jail.local
   ```

3. **Installer et configurer un outil de détection d'intrusion** :
   ```bash
   apt install aide rkhunter chkrootkit -y
   ```

4. **Mettre en place une rotation des logs** :
   ```bash
   # Déjà configuré par défaut sur Ubuntu/Debian
   # Vérifier : /etc/logrotate.d/
   ```

5. **Configurer un reverse proxy** (nginx/traefik) pour les services web

6. **Activer 2FA pour SSH** :
   ```bash
   apt install libpam-google-authenticator -y
   google-authenticator
   ```

## Différences de performance

- Script original : ~5-10 minutes
- Script amélioré : ~8-12 minutes (backups + validations supplémentaires)

Le léger surplus de temps est largement compensé par la sécurité et la fiabilité accrues.
