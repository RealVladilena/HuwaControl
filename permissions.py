"""
Contrôle d'accès fin aux routeurs.

Règle :
  - Les admins ont accès à tous les routeurs en lecture et écriture.
  - Les non-admins ont accès à tous les routeurs en lecture si aucune
    restriction n'est configurée (table user_router_perms vide pour cet user).
  - Si des permissions existent, seuls les routeurs listés sont accessibles.
  - can_write=True est requis pour les opérations de mutation (POST/PUT/DELETE).
"""
import logging
from functools import wraps

from flask import jsonify, request
from flask_login import current_user

import database as db
from utils import _rid

log = logging.getLogger("permissions")


def _get_rid_from_request() -> int | None:
    """Détecte le router_id depuis l'URL, le JSON ou les query params."""
    # 1. Paramètre d'URL (ex: /api/routers/<int:rid>)
    rid = request.view_args.get("rid") if request.view_args else None
    if rid:
        return int(rid)
    # 2. Query param ou session
    rid = request.args.get("router_id", type=int)
    if rid:
        return rid
    # 3. Corps JSON
    if request.is_json:
        body = request.get_json(silent=True) or {}
        rid  = body.get("router_id")
        if rid:
            return int(rid)
    # 4. Session / premier routeur dispo
    return _rid()


def require_router_access(write: bool = False):
    """
    Décorateur de route qui vérifie qu'un utilisateur a accès au routeur cible.

    Usage :
        @api_bp.route("/api/routers/<int:rid>", methods=["DELETE"])
        @login_required
        @require_router_access(write=True)
        def api_routers_delete(rid): ...

    Paramètres :
        write — si True, vérifie également que l'utilisateur a can_write=True.
    """
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            # Les admins passent toujours
            if current_user.is_admin:
                return fn(*args, **kwargs)

            rid = _get_rid_from_request()

            # Pas de routeur ciblé → autoriser (la route gérera le cas None)
            if not rid:
                return fn(*args, **kwargs)

            perms = db.get_user_router_perms(int(current_user.id))

            # Aucune restriction configurée → accès lecture à tout
            if not perms:
                if write:
                    return jsonify({"error": "Accès en écriture non autorisé"}), 403
                return fn(*args, **kwargs)

            # Chercher la permission pour ce routeur
            perm = next((p for p in perms if p["router_id"] == rid), None)
            if perm is None:
                return jsonify({"error": "Accès à ce routeur non autorisé"}), 403
            if write and not perm.get("can_write"):
                return jsonify({"error": "Accès en écriture non autorisé"}), 403

            return fn(*args, **kwargs)
        return wrapper
    return decorator
