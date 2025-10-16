# Changelog

Toutes les modifications notables de ce projet seront documentées dans ce fichier.

Le format est basé sur [Keep a Changelog](https://keepachangelog.com/fr/1.0.0/),
et ce projet adhère au [Semantic Versioning](https://semver.org/lang/fr/).

## [2.0.0] - 2025-10-16

### 🎉 Nouvelle version majeure avec améliorations critiques

### Ajouté
- ✅ Gestion d'erreurs robuste avec `set -euo pipefail`
- ✅ Validation complète des entrées utilisateur (nom, port SSH)
- ✅ Backups automatiques de toutes les configurations modifiées
- ✅ Logging détaillé avec timestamps dans `/var/log/`
- ✅ Support des variables d'environnement (`VPS_USER`, `VPS_PASSWORD`)
- ✅ Compatibilité `curl | bash` avec redirection `/dev/tty`
- ✅ Configuration SSH dans fichier dédié `99-custom-security.conf`
- ✅ Test de configuration SSH avant restart
- ✅ Rollback automatique en cas d'erreur SSH
- ✅ Durcissement système complet (sysctl hardening)
- ✅ Support IPv6 pour UFW et sysctl
- ✅ Mises à jour automatiques de sécurité (unattended-upgrades)
- ✅ Netdata sécurisé (localhost uniquement)
- ✅ Fail2ban avec protection SSH-DDoS
- ✅ Rate limiting UFW sur port SSH
- ✅ Configuration clé SSH optionnelle
- ✅ Désactivation services inutiles (avahi, cups)
- ✅ Messages colorés (info/warning/error)
- ✅ Résumé complet en fin d'installation

### Modifié
- 🔄 `adduser` avec `--disabled-password` puis `passwd` séparé
- 🔄 Port SSH personnalisable interactivement
- 🔄 Utilisation d'UFW uniquement (suppression des règles iptables)
- 🔄 AllowUsers configuré automatiquement pour le nouvel utilisateur
- 🔄 MaxAuthTries réduit à 3 (au lieu de 6 par défaut)
- 🔄 Amélioration du nettoyage des espaces dans les entrées utilisateur

### Sécurité
- 🔒 Netdata n'écoute plus publiquement (bind to 127.0.0.1)
- 🔒 Protection contre les injections dans les noms d'utilisateur
- 🔒 Validation stricte du format des noms d'utilisateur
- 🔒 Validation du port SSH (1024-65535)
- 🔒 Test de configuration SSH avant application
- 🔒 Protection mémoire kernel (ASLR, kptr_restrict)
- 🔒 Protection réseau (SYN cookies, IP spoofing protection)

### Corrigé
- 🐛 Problème de `read` avec `curl | bash` (ajout `< /dev/tty`)
- 🐛 Problème de `xargs` dans pipe (remplacement par expansion bash)
- 🐛 Conflit potentiel UFW/iptables (UFW uniquement)
- 🐛 Netdata exposé publiquement (bind localhost)
- 🐛 Pas de backup avant modifications (backups automatiques)
- 🐛 Variables non quotées (risque injection)
- 🐛 Regex username trop permissive (validation stricte)
- 🐛 `adduser` demande mot de passe deux fois (--disabled-password)

### Documentation
- 📖 README complet avec badges et exemples
- 📖 INSTALL.md avec toutes les méthodes d'installation
- 📖 automation-examples.sh avec 9 exemples d'automatisation
- 📖 IMPROVEMENTS.md détaillant toutes les améliorations
- 📖 LICENSE MIT ajoutée
- 📖 CHANGELOG ajouté

## [1.0.0] - 2024-XX-XX

### Version initiale

#### Inclus
- ✅ Mise à jour système
- ✅ Création utilisateur admin
- ✅ Configuration SSH basique (port, root désactivé)
- ✅ Installation UFW
- ✅ Installation Fail2ban basique
- ✅ Installation Netdata
- ✅ Règles iptables anti-DDoS

#### Limitations connues
- ❌ Pas de gestion d'erreurs
- ❌ Pas de validation des entrées
- ❌ Pas de backups
- ❌ Pas de logs
- ❌ Netdata exposé publiquement
- ❌ Conflit UFW/iptables
- ❌ Pas compatible `curl | bash`
- ❌ Variables non quotées

---

## Comment contribuer

Pour proposer des améliorations :
1. Fork le projet
2. Créez une branche (`git checkout -b feature/amelioration`)
3. Committez vos changements (`git commit -m 'Ajout fonctionnalité'`)
4. Push vers la branche (`git push origin feature/amelioration`)
5. Ouvrez une Pull Request

## Types de changements

- `Added` : Nouvelles fonctionnalités
- `Changed` : Modifications de fonctionnalités existantes
- `Deprecated` : Fonctionnalités bientôt supprimées
- `Removed` : Fonctionnalités supprimées
- `Fixed` : Corrections de bugs
- `Security` : Corrections de vulnérabilités
