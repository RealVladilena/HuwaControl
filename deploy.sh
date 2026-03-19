#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════
#  HuwaControl — Script de déploiement automatique
#  Usage : bash deploy.sh
#  - Installe Docker si absent (Debian / Ubuntu)
#  - Génère .env avec des secrets aléatoires si absent
#  - Build et démarre tous les services
#  - Ré-exécuter pour mettre à jour le projet
# ═══════════════════════════════════════════════════════════════════

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'

info()    { echo -e "${BLUE}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERR]${NC}   $*"; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ── 1. Vérification root ───────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
  error "Ce script doit être exécuté en root. Lance : sudo bash deploy.sh"
fi

# ── 2. Détection OS ───────────────────────────────────────────────
detect_os() {
  if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    echo "$ID"
  else
    error "Impossible de détecter l'OS. Seuls Debian/Ubuntu sont supportés."
  fi
}

OS=$(detect_os)
if [[ "$OS" != "debian" && "$OS" != "ubuntu" ]]; then
  error "OS non supporté : $OS. Seuls Debian et Ubuntu sont supportés."
fi

# ── 3. Installation Docker ─────────────────────────────────────────
install_docker() {
  info "Installation de Docker..."

  apt-get update -qq
  apt-get install -y -qq \
    ca-certificates curl gnupg lsb-release git make

  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL "https://download.docker.com/linux/$OS/gpg" \
    | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  chmod a+r /etc/apt/keyrings/docker.gpg

  echo \
    "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
    https://download.docker.com/linux/$OS \
    $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
    | tee /etc/apt/sources.list.d/docker.list > /dev/null

  apt-get update -qq
  apt-get install -y -qq \
    docker-ce docker-ce-cli containerd.io docker-compose-plugin

  systemctl enable --now docker
  success "Docker installé : $(docker --version)"
}

if command -v docker &>/dev/null && docker compose version &>/dev/null; then
  success "Docker déjà présent : $(docker --version)"
else
  install_docker
fi

# ── 4. Génération automatique du .env ─────────────────────────────
generate_env() {
  info "Génération du fichier .env avec des secrets aléatoires..."

  # Générer les secrets avec openssl (disponible partout)
  local PG_PASS
  local SECRET_KEY
  PG_PASS=$(openssl rand -hex 16)
  SECRET_KEY=$(openssl rand -hex 32)

  cat > .env <<EOF
# ════════════════════════════════════════════════════════════
#  HuwaControl — Configuration générée automatiquement
#  Généré le : $(date '+%Y-%m-%d %H:%M:%S')
# ════════════════════════════════════════════════════════════

# ── PostgreSQL ───────────────────────────────────────────────
POSTGRES_DB=huwacontrol
POSTGRES_USER=huwa
POSTGRES_PASSWORD=${PG_PASS}

# ── Flask ────────────────────────────────────────────────────
SECRET_KEY=${SECRET_KEY}

# ── Réseau ───────────────────────────────────────────────────
HTTP_PORT=8080
EOF

  success ".env créé avec des secrets aléatoires"
  warn "Sauvegarde ces secrets si tu as besoin de restaurer une BDD :"
  echo -e "  POSTGRES_PASSWORD = ${PG_PASS}"
  echo -e "  SECRET_KEY        = ${SECRET_KEY}"
  echo ""
}

if [[ -f .env ]]; then
  success ".env déjà présent — secrets conservés"
else
  generate_env
fi

# ── 5. Mise à jour git (si repo) ───────────────────────────────────
if [[ -d .git ]]; then
  info "Mise à jour du code source (git pull)..."
  git pull --ff-only || warn "git pull échoué (conflits ?), on continue avec le code local"
fi

# ── 6. Build et démarrage ─────────────────────────────────────────
info "Build et démarrage des conteneurs..."
docker compose pull --quiet          2>/dev/null || true
docker compose up -d --build --remove-orphans

# ── 7. Attente santé de la BDD ────────────────────────────────────
info "Attente de la base de données..."
MAX=30; i=0
until docker compose exec -T db pg_isready -q 2>/dev/null; do
  sleep 2
  i=$((i+1))
  [[ $i -ge $MAX ]] && error "La base de données ne répond pas après ${MAX} tentatives"
done
success "Base de données prête"

# ── 8. Résumé ─────────────────────────────────────────────────────
PORT=$(grep HTTP_PORT .env | cut -d= -f2 | tr -d ' ' || echo 8080)
LOCAL_IP=$(hostname -I | awk '{print $1}')

echo ""
echo -e "${GREEN}═══════════════════════════════════════════════${NC}"
echo -e "${GREEN}  HuwaControl est en ligne !${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════${NC}"
echo -e "  URL locale   : http://localhost:${PORT}"
echo -e "  URL réseau   : http://${LOCAL_IP}:${PORT}"
echo ""
echo -e "  Commandes utiles :"
echo -e "    docker compose logs -f     # Logs en direct"
echo -e "    docker compose ps          # État des services"
echo -e "    bash deploy.sh             # Mettre à jour"
echo -e "    docker compose down        # Arrêter"
echo ""
