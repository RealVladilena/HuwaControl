"""
Alembic env.py — HuwaControl.
Utilise SQLAlchemy (bundlé avec Alembic) pour la connexion DB.
Pas de modèles SQLAlchemy — migrations SQL brutes uniquement.
"""
import os
import sys
from logging.config import fileConfig

from alembic import context
from sqlalchemy import create_engine, text

# Rendre config.py importable depuis ce sous-répertoire
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config as app_config  # noqa: E402

alembic_config = context.config

if alembic_config.config_file_name is not None:
    fileConfig(alembic_config.config_file_name)

# Pas de SQLAlchemy metadata — on utilise des migrations SQL brutes
target_metadata = None


def _get_url() -> str:
    return (
        f"postgresql+psycopg2://{app_config.DB_USER}:{app_config.DB_PASS}"
        f"@{app_config.DB_HOST}:{app_config.DB_PORT}/{app_config.DB_NAME}"
    )


def run_migrations_offline() -> None:
    """Mode offline : génère le SQL sans connexion DB."""
    context.configure(
        url=_get_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Mode online : connexion via SQLAlchemy (requis par Alembic ≥ 1.13)."""
    engine = create_engine(_get_url(), connect_args={"connect_timeout": 5})
    with engine.connect() as conn:
        context.configure(connection=conn, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
