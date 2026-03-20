"""Baseline — schéma HuwaControl v2.3.0

Ce fichier est une migration de référence VIDE.

- Installation fraîche  : database.init_db() crée le schéma complet,
  puis `alembic upgrade head` marque la base à cette révision.
- Installation existante: exécuter `alembic stamp head` UNE FOIS
  pour marquer la base sans exécuter de DDL.

Les futures modifications de schéma seront des migrations Alembic
qui utilisent op.execute() ou les helpers op.add_column() etc.

Revision ID: 0001
Revises:
Create Date: 2026-03-20
"""
from typing import Sequence, Union

revision: str = "0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Schéma géré par database.init_db() — rien à faire ici pour l'instant.
    pass


def downgrade() -> None:
    pass
