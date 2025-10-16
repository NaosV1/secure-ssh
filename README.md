# 🔒 Script de Sécurisation VPS - Secure SSH

[![Version](https://img.shields.io/badge/version-2.0-blue.svg)](https://github.com/NaosV1/secure-ssh)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Debian](https://img.shields.io/badge/debian-10%2B-red.svg)](https://www.debian.org/)
[![Ubuntu](https://img.shields.io/badge/ubuntu-18.04%2B-orange.svg)](https://ubuntu.com/)

Script Bash professionnel pour sécuriser automatiquement vos serveurs VPS Ubuntu/Debian en quelques minutes.

## ✨ Fonctionnalités

- ✅ **Mise à jour complète** du système
- 👤 **Création utilisateur admin** non-root avec sudo
- 🔑 **Authentification SSH par clé uniquement** (pas de mot de passe)
- 🔐 **Durcissement SSH** (changement port, désactivation root, limitations)
- 🔥 **Pare-feu UFW** avec règles de base
- 🧱 **Fail2ban** contre les attaques par force brute
- 🛡️ **Hardening système** (sysctl, kernel parameters)
- 📊 **Netdata** pour le monitoring (optionnel, sécurisé sur localhost)
- 🔄 **Mises à jour automatiques** de sécurité
- 💾 **Backups automatiques** des configurations
- 📝 **Logging détaillé** de toutes les opérations
- 🌐 **Support IPv6** complet

## 🚀 Installation rapide

### Méthode 1 : Installation en une commande (Interactive)

```bash
curl -fsSL https://raw.githubusercontent.com/NaosV1/secure-ssh/main/secure.sh | sudo bash
```

### Méthode 2 : Installation semi-automatique

Prédéfinir le nom d'utilisateur :

```bash
curl -fsSL https://raw.githubusercontent.com/NaosV1/secure-ssh/main/secure.sh | sudo VPS_USER=adminvps bash
```

### Méthode 3 : Installation entièrement automatique avec clé SSH

```bash
curl -fsSL https://raw.githubusercontent.com/NaosV1/secure-ssh/main/secure.sh | \
  sudo VPS_USER=adminvps VPS_SSH_KEY="ssh-ed25519 AAAA..." bash
```

Remplacez `ssh-ed25519 AAAA...` par votre clé SSH publique complète.

### Méthode 4 : Téléchargement et inspection

Pour inspecter le script avant de l'exécuter :

```bash
wget https://raw.githubusercontent.com/NaosV1/secure-ssh/main/secure.sh
less secure.sh
chmod +x secure.sh
sudo ./secure.sh
```

## 📋 Prérequis

- **OS** : Ubuntu 18.04+ ou Debian 10+
- **Accès** : Root ou sudo
- **Connexion** : Internet active
- **Temps** : 8-12 minutes d'exécution

## 🔧 Configuration appliquée

### SSH (Port 28 par défaut)
- ✅ **Authentification par clé SSH uniquement** (mot de passe désactivé)
- ✅ Root login désactivé
- ✅ Port personnalisable
- ✅ MaxAuthTries: 3
- ✅ MaxSessions: 5
- ✅ ClientAlive: 300s
- ✅ AllowUsers configuré
- ✅ AuthenticationMethods: publickey

### Pare-feu UFW
- ✅ SSH (port personnalisé)
- ✅ HTTP (80)
- ✅ HTTPS (443)
- ✅ Rate limiting sur SSH
- ✅ IPv4 + IPv6

### Fail2ban
- ✅ Protection SSH
- ✅ Protection SSH-DDoS
- ✅ Ban: 1h après 5 tentatives
- ✅ Findtime: 10 minutes

### Sysctl Hardening
- ✅ SYN cookies (anti SYN flood)
- ✅ IP spoofing protection
- ✅ ICMP redirects désactivés
- ✅ Source routing désactivé
- ✅ ASLR activé
- ✅ Kernel pointer restriction

## 📖 Documentation détaillée

- [Guide d'installation complet](INSTALL.md)
- [Exemples d'automatisation](automation-examples.sh)
- [Comparaison avec version originale](IMPROVEMENTS.md)

## ⚠️ Important - Après l'installation

**NE FERMEZ PAS** votre session SSH actuelle immédiatement !

1. ✅ Ouvrez un **NOUVEL onglet/terminal**
2. ✅ **Testez la connexion** avec le nouveau port et utilisateur
3. ✅ **Seulement si ça marche**, fermez l'ancienne session

```bash
# Tester la nouvelle connexion
ssh nouvel_user@votre_ip -p 28
```

Si vous ne pouvez pas vous reconnecter, retournez à votre ancienne session et restaurez la configuration :

```bash
sudo cp /root/config-backup-*/sshd_config /etc/ssh/sshd_config
sudo systemctl restart ssh
```

## 🔍 Que fait exactement le script ?

<details>
<summary>Cliquez pour voir le détail des opérations</summary>

1. **Vérifications initiales**
   - Vérification root/sudo
   - Vérification distribution (Ubuntu/Debian)
   - Création des répertoires de backup et logs

2. **Mise à jour système**
   - `apt update && apt upgrade`
   - Installation des paquets nécessaires

3. **Création utilisateur**
   - Validation du nom d'utilisateur
   - Création avec `adduser`
   - Ajout au groupe sudo
   - Configuration du mot de passe
   - Configuration clé SSH (optionnel)

4. **Configuration SSH**
   - Backup de `/etc/ssh/sshd_config`
   - Création de `/etc/ssh/sshd_config.d/99-custom-security.conf`
   - Changement de port
   - Désactivation root login
   - Limitation des tentatives
   - Test de configuration avant restart

5. **Pare-feu UFW**
   - Installation UFW
   - Configuration règles par défaut
   - Ouverture ports SSH, HTTP, HTTPS
   - Rate limiting
   - Activation IPv6

6. **Fail2ban**
   - Installation Fail2ban
   - Configuration jail SSH
   - Configuration jail SSH-DDoS
   - Activation service

7. **Hardening système**
   - Désactivation services inutiles
   - Configuration sysctl (/etc/sysctl.d/99-security.conf)
   - Application des paramètres

8. **Netdata (optionnel)**
   - Installation sécurisée
   - Configuration localhost uniquement
   - Désactivation télémétrie

9. **Mises à jour automatiques**
   - Installation unattended-upgrades
   - Configuration mises à jour de sécurité automatiques

10. **Résumé et logs**
    - Affichage configuration finale
    - Sauvegarde logs dans `/var/log/`
    - Instructions de test

</details>

## 🛡️ Sécurité

### Ce que le script NE FAIT PAS
- ❌ Ne modifie pas les données utilisateur
- ❌ Ne crée pas de backdoors
- ❌ N'envoie pas de données externes (sauf Netdata si télémétrie activée)
- ❌ Ne désactive pas l'accès SSH existant avant de configurer le nouveau

### Bonnes pratiques
- ✅ Toujours tester la nouvelle connexion SSH avant de fermer l'ancienne
- ✅ Conserver les backups de configuration
- ✅ Consulter les logs en cas de problème
- ✅ Utiliser des clés SSH plutôt que des mots de passe
- ✅ Changer le mot de passe par défaut si utilisation automatisée

## 🔄 Automatisation avancée

### Avec Ansible

```yaml
- name: Sécuriser VPS
  hosts: all
  tasks:
    - name: Exécuter secure-ssh
      shell: |
        curl -fsSL https://raw.githubusercontent.com/NaosV1/secure-ssh/main/secure.sh | \
        VPS_USER=admin VPS_PASSWORD='{{ vault_password }}' bash
```

### Avec Terraform

```hcl
resource "null_resource" "secure" {
  provisioner "remote-exec" {
    inline = [
      "curl -fsSL https://raw.githubusercontent.com/NaosV1/secure-ssh/main/secure.sh | VPS_USER=admin VPS_PASSWORD='${var.admin_pass}' bash"
    ]
  }
}
```

Plus d'exemples dans [automation-examples.sh](automation-examples.sh).

## 📊 Monitoring post-installation

### Accéder à Netdata (si installé)

Netdata écoute sur localhost pour la sécurité. Créez un tunnel SSH :

```bash
ssh -L 19999:localhost:19999 user@votre_ip -p 28
```

Puis accédez à http://localhost:19999

### Vérifier Fail2ban

```bash
sudo fail2ban-client status sshd
```

### Vérifier UFW

```bash
sudo ufw status verbose
```

## 🐛 Dépannage

### SSH ne fonctionne plus après le script

1. Accédez via console VPS (interface web provider)
2. Restaurez la config :
```bash
cp /root/config-backup-*/sshd_config /etc/ssh/sshd_config
systemctl restart ssh
```

### Port SSH bloqué par le firewall

```bash
sudo ufw allow 28/tcp
sudo ufw reload
```

### Utilisateur ne peut pas sudo

```bash
sudo usermod -aG sudo nom_utilisateur
```

## 📝 Logs

Tous les logs sont sauvegardés dans :
```
/var/log/vps-secure-YYYYMMDD-HHMMSS.log
```

Les backups de configuration dans :
```
/root/config-backup-YYYYMMDD-HHMMSS/
```

## 🤝 Contribution

Les contributions sont les bienvenues ! N'hésitez pas à :
- 🐛 Reporter des bugs
- 💡 Proposer des améliorations
- 📖 Améliorer la documentation
- ⭐ Mettre une étoile si le projet vous est utile

## 📜 Licence

Ce projet est sous licence MIT. Voir le fichier [LICENSE](LICENSE) pour plus de détails.

## ⚠️ Avertissement

Ce script modifie la configuration système de votre serveur. Bien qu'il ait été testé, utilisez-le à vos propres risques. Toujours :
- Faire un backup de vos données importantes
- Tester sur un serveur de développement d'abord
- Garder un accès console au serveur (interface web provider)

## 👨‍💻 Auteur

**NaosV1**
- GitHub: [@NaosV1](https://github.com/NaosV1)
- Repository: [secure-ssh](https://github.com/NaosV1/secure-ssh)

## 🙏 Remerciements

Basé sur les meilleures pratiques de sécurité Linux et les recommandations de :
- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/)
- [ANSSI](https://www.ssi.gouv.fr/)
- [Ubuntu Security Guide](https://ubuntu.com/security)

---

**⭐ Si ce projet vous aide, n'hésitez pas à lui donner une étoile !**
