#!/bin/bash
# ==============================================
# Exemples d'automatisation du script de sécurisation VPS
# ==============================================

# --- Exemple 1 : Installation interactive (défaut) ---
# L'utilisateur répond aux prompts manuellement
curl -fsSL https://raw.githubusercontent.com/NaosV1/secure-ssh/main/secure.sh | sudo bash


# --- Exemple 2 : Installation semi-automatique ---
# Nom d'utilisateur prédéfini, mais demande le mot de passe et autres options
curl -fsSL https://raw.githubusercontent.com/NaosV1/secure-ssh/main/secure.sh | sudo VPS_USER=adminvps bash


# --- Exemple 3 : Installation entièrement automatique ---
# Nom d'utilisateur ET mot de passe prédéfinis
# ⚠️ Attention : Le mot de passe sera visible dans l'historique !
curl -fsSL https://raw.githubusercontent.com/NaosV1/secure-ssh/main/secure.sh | \
  sudo VPS_USER=adminvps VPS_PASSWORD='MonMotDePasse123!' bash


# --- Exemple 4 : Installation automatique sécurisée (sans historique) ---
# Le mot de passe est lu depuis un fichier ou demandé interactivement
read -rsp "Entrez le mot de passe pour le nouvel utilisateur : " VPS_PASSWORD
echo ""
curl -fsSL https://raw.githubusercontent.com/NaosV1/secure-ssh/main/secure.sh | \
  sudo VPS_USER=adminvps VPS_PASSWORD="$VPS_PASSWORD" bash
unset VPS_PASSWORD  # Nettoyer la variable


# --- Exemple 5 : Automatisation depuis un script ---
# Utile pour provisionner plusieurs serveurs
cat > /tmp/secure-vps.sh <<'EOF'
#!/bin/bash
set -euo pipefail

# Configuration
VPS_IP="$1"
VPS_USER="adminvps"
VPS_PASSWORD="$(openssl rand -base64 16)"  # Générer un mot de passe aléatoire

echo "🔒 Sécurisation de $VPS_IP avec utilisateur $VPS_USER"
echo "📝 Mot de passe: $VPS_PASSWORD"

# Exécuter le script sur le serveur distant
ssh root@"$VPS_IP" "bash <(curl -fsSL https://raw.githubusercontent.com/NaosV1/secure-ssh/main/secure.sh)" <<INPUTS
y
$VPS_USER
$VPS_PASSWORD
$VPS_PASSWORD
n
y
y
n
INPUTS

echo "✅ Sécurisation terminée"
echo "🔑 Connexion : ssh $VPS_USER@$VPS_IP -p 28"
echo "🔐 Mot de passe : $VPS_PASSWORD"
EOF

chmod +x /tmp/secure-vps.sh


# --- Exemple 6 : Automatisation avec Ansible ---
# Créer un playbook Ansible pour automatiser sur plusieurs serveurs
cat > /tmp/secure-vps-playbook.yml <<'EOF'
---
- name: Sécuriser les VPS
  hosts: vps_servers
  become: yes
  vars:
    vps_user: adminvps
    vps_password: "{{ lookup('password', '/tmp/vps_password_' + inventory_hostname + ' length=16 chars=ascii_letters,digits') }}"

  tasks:
    - name: Télécharger le script de sécurisation
      get_url:
        url: https://raw.githubusercontent.com/NaosV1/secure-ssh/main/secure.sh
        dest: /tmp/secure.sh
        mode: '0755'

    - name: Exécuter le script de sécurisation
      shell: |
        export VPS_USER="{{ vps_user }}"
        export VPS_PASSWORD="{{ vps_password }}"
        /tmp/secure.sh
      args:
        executable: /bin/bash

    - name: Afficher les informations de connexion
      debug:
        msg: "SSH: ssh {{ vps_user }}@{{ inventory_hostname }} -p 28 | Password: {{ vps_password }}"
EOF


# --- Exemple 7 : Automatisation avec Terraform ---
# Utiliser Terraform pour provisionner et sécuriser un VPS
cat > /tmp/main.tf <<'EOF'
resource "null_resource" "secure_vps" {
  provisioner "remote-exec" {
    inline = [
      "export VPS_USER='adminvps'",
      "export VPS_PASSWORD='${var.admin_password}'",
      "curl -fsSL https://raw.githubusercontent.com/NaosV1/secure-ssh/main/secure.sh | bash"
    ]

    connection {
      type     = "ssh"
      host     = var.vps_ip
      user     = "root"
      password = var.root_password
    }
  }
}

variable "vps_ip" {
  description = "IP du VPS à sécuriser"
}

variable "root_password" {
  description = "Mot de passe root actuel"
  sensitive   = true
}

variable "admin_password" {
  description = "Mot de passe pour le nouvel utilisateur admin"
  sensitive   = true
}
EOF


# --- Exemple 8 : Script d'installation multi-serveurs ---
cat > /tmp/mass-deployment.sh <<'EOF'
#!/bin/bash
# Déploiement en masse sur plusieurs serveurs

SERVERS=(
  "192.168.1.10"
  "192.168.1.11"
  "192.168.1.12"
)

for SERVER in "${SERVERS[@]}"; do
  echo "🔒 Sécurisation de $SERVER..."

  # Générer un mot de passe unique par serveur
  PASSWORD=$(openssl rand -base64 16)

  # Sauvegarder les credentials
  echo "$SERVER | adminvps | $PASSWORD" >> /tmp/vps-credentials.txt

  # Exécuter le script
  ssh root@"$SERVER" "curl -fsSL https://raw.githubusercontent.com/NaosV1/secure-ssh/main/secure.sh | VPS_USER=adminvps VPS_PASSWORD='$PASSWORD' bash" &

  # Attendre un peu entre chaque serveur
  sleep 5
done

wait  # Attendre que tous les déploiements se terminent

echo "✅ Tous les serveurs ont été sécurisés"
echo "📝 Credentials sauvegardés dans /tmp/vps-credentials.txt"
EOF

chmod +x /tmp/mass-deployment.sh


# --- Exemple 9 : Avec Docker pour provisionner des conteneurs ---
cat > /tmp/Dockerfile <<'EOF'
FROM debian:bookworm

# Installer les dépendances
RUN apt-get update && apt-get install -y curl sudo openssh-server

# Télécharger et exécuter le script
RUN curl -fsSL https://raw.githubusercontent.com/NaosV1/secure-ssh/main/secure.sh -o /tmp/secure.sh && \
    chmod +x /tmp/secure.sh

# Variables d'environnement pour l'automatisation
ENV VPS_USER=adminvps
ENV VPS_PASSWORD=ChangeMe123!

CMD ["/tmp/secure.sh"]
EOF


# --- Notes d'utilisation ---
echo "
📚 GUIDE D'UTILISATION

1. Installation interactive (recommandée pour 1 serveur)
   → Utilisez l'Exemple 1

2. Installation automatisée (plusieurs serveurs identiques)
   → Utilisez l'Exemple 3 ou 8

3. Intégration CI/CD
   → Utilisez l'Exemple 6 (Ansible) ou 7 (Terraform)

4. Environnement de développement
   → Utilisez l'Exemple 9 (Docker)

⚠️ SÉCURITÉ
- Ne stockez JAMAIS les mots de passe en clair dans Git
- Utilisez des gestionnaires de secrets (Vault, AWS Secrets Manager, etc.)
- Générez des mots de passe aléatoires forts
- Effacez l'historique après utilisation : history -c

📖 Documentation complète : https://github.com/NaosV1/secure-ssh
"
