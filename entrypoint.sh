#!/bin/sh
# ─────────────────────────────────────────────────────────────────
#  HuwaControl — Entrypoint
#  Génère automatiquement les secrets au premier démarrage,
#  les persiste dans /app/instance (volume Docker).
# ─────────────────────────────────────────────────────────────────
set -e

INSTANCE="/app/instance"
SECRETS="$INSTANCE/.secrets"

mkdir -p "$INSTANCE"

# ── Génération des secrets au premier démarrage ──────────────────
if [ ! -f "$SECRETS" ]; then
  echo "[HuwaControl] Premier démarrage — génération des secrets..."

  SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
  DB_PASS=$(python3 -c "import secrets; print(secrets.token_hex(16))")

  cat > "$SECRETS" <<ENVEOF
SECRET_KEY=${SECRET_KEY}
GENERATED_DB_PASS=${DB_PASS}
ENVEOF
  chmod 600 "$SECRETS"
  echo "[HuwaControl] Secrets générés et sauvegardés dans $SECRETS"
fi

# ── Chargement des secrets persistés ────────────────────────────
. "$SECRETS"

# SECRET_KEY : utilise la variable .env si définie, sinon celle générée
export SECRET_KEY="${SECRET_KEY:-$SECRET_KEY}"

# Afficher l'état au démarrage
echo "[HuwaControl] Démarrage — DB: ${DB_HOST:-db}:${DB_PORT:-5432}/${POSTGRES_DB:-huwacontrol}"

# ── Attendre que PostgreSQL soit prêt ────────────────────────────
echo "[HuwaControl] Attente de PostgreSQL..."
until python3 -c "
import psycopg2, os
psycopg2.connect(
    host=os.getenv('DB_HOST','db'),
    port=os.getenv('DB_PORT','5432'),
    dbname=os.getenv('POSTGRES_DB','huwacontrol'),
    user=os.getenv('POSTGRES_USER','huwa'),
    password=os.getenv('POSTGRES_PASSWORD','huwacontrol'),
    connect_timeout=3
).close()
" 2>/dev/null; do
  echo "[HuwaControl] PostgreSQL pas encore prêt, attente 2s..."
  sleep 2
done
echo "[HuwaControl] PostgreSQL prêt."

# ── Appliquer les migrations Alembic ─────────────────────────────
python3 -m alembic upgrade head
echo "[HuwaControl] Migrations Alembic appliquées."

exec "$@"
