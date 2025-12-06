#!/bin/bash
#
# Script pour générer des certificats TLS auto-signés pour ActiveDebianSync
#

set -e

CERT_DIR="${1:-/etc/ActiveDebianSync}"
CERT_FILE="${CERT_DIR}/server.crt"
KEY_FILE="${CERT_DIR}/server.key"
DAYS=3650  # 10 ans

echo "=== Génération de certificats TLS auto-signés ==="
echo ""

# Vérifier les privilèges root
if [ "$EUID" -ne 0 ]; then
    echo "Erreur: Ce script doit être exécuté en tant que root"
    exit 1
fi

# Créer le répertoire si nécessaire
mkdir -p "$CERT_DIR"

# Demander les informations
read -p "Nom de domaine ou IP du serveur [localhost]: " SERVER_NAME
SERVER_NAME=${SERVER_NAME:-localhost}

read -p "Pays (2 lettres) [FR]: " COUNTRY
COUNTRY=${COUNTRY:-FR}

read -p "État/Province [Ile-de-France]: " STATE
STATE=${STATE:-Ile-de-France}

read -p "Ville [Paris]: " CITY
CITY=${CITY:-Paris}

read -p "Organisation [ActiveDebianSync]: " ORG
ORG=${ORG:-ActiveDebianSync}

echo ""
echo "Génération du certificat pour: $SERVER_NAME"
echo "Durée de validité: $DAYS jours"
echo ""

# Générer la clé privée et le certificat
openssl req -x509 -nodes -newkey rsa:4096 \
    -keyout "$KEY_FILE" \
    -out "$CERT_FILE" \
    -days $DAYS \
    -subj "/C=$COUNTRY/ST=$STATE/L=$CITY/O=$ORG/CN=$SERVER_NAME" \
    -addext "subjectAltName=DNS:$SERVER_NAME,DNS:localhost,IP:127.0.0.1"

# Définir les permissions
chmod 600 "$KEY_FILE"
chmod 644 "$CERT_FILE"
chown root:root "$KEY_FILE" "$CERT_FILE"

echo ""
echo "=== Certificats générés avec succès! ==="
echo ""
echo "Fichiers créés:"
echo "  - Certificat: $CERT_FILE"
echo "  - Clé privée: $KEY_FILE"
echo ""
echo "Pour activer HTTPS dans ActiveDebianSync:"
echo "  1. Éditez /etc/ActiveDebianSync/config.json"
echo "  2. Définissez \"https_enabled\": true"
echo "  3. Redémarrez le service: systemctl restart activedebiansync"
echo ""
echo "ATTENTION: Certificat auto-signé!"
echo "Les clients devront accepter le certificat ou ajouter une exception."
echo ""
echo "Pour les clients APT, ignorez la vérification SSL:"
echo "  deb [trusted=yes] https://$SERVER_NAME:8443/dists/bookworm bookworm main"
echo ""
echo "Ou installez le certificat sur les clients:"
echo "  sudo cp server.crt /usr/local/share/ca-certificates/activedebiansync.crt"
echo "  sudo update-ca-certificates"
echo ""
