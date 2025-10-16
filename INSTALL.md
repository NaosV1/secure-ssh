# Installation rapide - Script de sécurisation VPS

## Installation en une seule commande

### Méthode 1 : Installation directe (recommandée)

Connectez-vous à votre VPS en SSH, puis exécutez :

```bash
curl -fsSL https://raw.githubusercontent.com/NaosV1/secure-ssh/main/secure.sh | sudo bash
```

### Méthode 1b : Installation semi-automatisée

Si vous voulez automatiser partiellement (nom d'utilisateur prédéfini) :

```bash
curl -fsSL https://raw.githubusercontent.com/NaosV1/secure-ssh/main/secure.sh | sudo VPS_USER=adminvps bash
```

### Méthode 1c : Installation entièrement automatisée

Pour une automatisation complète (nom d'utilisateur ET mot de passe) :

```bash
curl -fsSL https://raw.githubusercontent.com/NaosV1/secure-ssh/main/secure.sh | sudo VPS_USER=adminvps VPS_PASSWORD='VotreMotDePasse123!' bash
```

⚠️ **Attention** : Cette méthode expose le mot de passe dans l'historique des commandes. Utilisez-la uniquement dans des environnements sécurisés ou avec un script d'automatisation.

### Méthode 2 : Téléchargement puis exécution (plus sûr)

Si vous souhaitez inspecter le script avant de l'exécuter :

```bash
# Télécharger le script
curl -fsSL https://raw.githubusercontent.com/NaosV1/secure-ssh/main/secure.sh -o secure.sh

# Vérifier le contenu
less secure.sh

# Rendre exécutable et lancer
chmod +x secure.sh
sudo ./secure.sh
```

### Méthode 3 : Avec wget

```bash
wget -qO- https://raw.githubusercontent.com/NaosV1/secure-ssh/main/secure.sh | sudo bash
```

## Installation avec téléchargement permanent

Si vous souhaitez garder le script sur votre serveur :

```bash
# Télécharger
wget https://raw.githubusercontent.com/NaosV1/secure-ssh/main/secure.sh

# Permissions
chmod +x secure.sh

# Exécuter
sudo ./secure.sh
```

## Exécution à distance depuis votre machine locale

Depuis votre ordinateur, vous pouvez aussi lancer le script sur un serveur distant :

```bash
ssh root@VOTRE_IP "bash <(curl -fsSL https://raw.githubusercontent.com/NaosV1/secure-ssh/main/secure.sh)"
```

Remplacez `VOTRE_IP` par l'adresse IP de votre VPS.

## Prérequis

- Système : Ubuntu 18.04+ ou Debian 10+
- Accès root ou sudo
- Connexion Internet active

## Ce que fait le script

✅ Mise à jour complète du système
✅ Création d'un utilisateur administrateur non-root
✅ Sécurisation SSH (changement de port, désactivation root)
✅ Configuration du pare-feu UFW
✅ Installation et configuration de Fail2ban
✅ Durcissement système (sysctl hardening)
✅ Mises à jour automatiques de sécurité
✅ Monitoring avec Netdata (optionnel)
✅ Backups automatiques des configurations
✅ Logs détaillés de toutes les opérations

## Durée d'exécution

Entre 8 et 12 minutes selon la vitesse de votre serveur et de votre connexion.

## Important - Après l'exécution

⚠️ **NE FERMEZ PAS** votre session SSH actuelle immédiatement !

1. **Ouvrez un NOUVEL onglet/terminal**
2. **Testez la connexion** avec le nouveau port et utilisateur
3. **Seulement si ça fonctionne**, fermez l'ancienne session

Exemple de test :
```bash
ssh nouveluseradmin@VOTRE_IP -p 28
```

## En cas de problème

Les backups sont automatiquement créés dans `/root/config-backup-[timestamp]/`

Pour restaurer la configuration SSH :
```bash
sudo cp /root/config-backup-*/sshd_config /etc/ssh/sshd_config
sudo systemctl restart ssh
```

## Support et documentation

- Repository : https://github.com/NaosV1/secure-ssh
- README complet : https://github.com/NaosV1/secure-ssh/blob/main/README.md

## Licence

Ce script est fourni "tel quel" sans garantie. Utilisez-le à vos propres risques.
