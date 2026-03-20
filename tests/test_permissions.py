"""Tests unitaires — permissions.py (require_router_access)."""
import os
import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))


def _make_user(is_admin: bool, uid: int = 1):
    user = MagicMock()
    user.is_admin = is_admin
    user.id       = str(uid)
    user.is_authenticated = True
    return user


def _make_perms(router_ids: list, can_write: bool = False):
    return [{"router_id": rid, "can_write": can_write} for rid in router_ids]


class TestRequireRouterAccess:

    def _call_wrapper(self, write, user, perms, rid):
        """Helper: simule un appel décoré dans un contexte Flask de test."""
        from flask import Flask
        from flask_login import login_user, LoginManager
        from permissions import require_router_access

        mini_app = Flask(__name__)
        mini_app.secret_key = "test"
        lm = LoginManager(mini_app)
        lm.user_loader(lambda _: user)

        results = {}

        db_mock = MagicMock()
        db_mock.get_user_router_perms.return_value = perms

        with patch.dict("sys.modules", {"database": db_mock}):
            import importlib
            import permissions as perm_mod
            importlib.reload(perm_mod)
            dec = perm_mod.require_router_access(write=write)

            @mini_app.route("/test/<int:rid>", methods=["GET", "POST", "DELETE"])
            def view(rid):
                results["called"] = True
                return "ok"

            view_decorated = dec(view)
            mini_app.view_functions["view"] = view_decorated

        with mini_app.test_request_context(f"/test/{rid}"):
            from flask import g
            g._login_user = user  # Manually inject user
            with patch("flask_login.utils._get_user", return_value=user):
                with patch("permissions.db", db_mock):
                    response = view_decorated(rid=rid)

        return results, response

    def test_admin_always_passes(self):
        from flask import Flask
        from permissions import require_router_access

        mini_app = Flask(__name__)
        mini_app.secret_key = "test"

        user = _make_user(is_admin=True)
        db_mock = MagicMock()
        db_mock.get_user_router_perms.return_value = []

        called = []

        with mini_app.test_request_context("/test/1"):
            with patch("flask_login.utils._get_user", return_value=user):
                with patch("permissions.current_user", user):
                    with patch("permissions.db", db_mock):
                        dec = require_router_access(write=True)

                        def inner(rid):
                            called.append(rid)
                            return "ok"

                        result = dec(inner)(rid=1)

        assert called == [1]
        assert result == "ok"

    def test_non_admin_no_perms_read_allowed(self):
        from flask import Flask
        from permissions import require_router_access

        mini_app = Flask(__name__)
        mini_app.secret_key = "test"

        user = _make_user(is_admin=False)
        db_mock = MagicMock()
        db_mock.get_user_router_perms.return_value = []  # no restrictions

        called = []

        with mini_app.test_request_context("/test/5"):
            with patch("flask_login.utils._get_user", return_value=user):
                with patch("permissions.current_user", user):
                    with patch("permissions.db", db_mock):
                        dec = require_router_access(write=False)

                        def inner(rid):
                            called.append(rid)
                            return "ok"

                        result = dec(inner)(rid=5)

        assert called == [5]

    def test_non_admin_no_perms_write_denied(self):
        from flask import Flask, jsonify
        from permissions import require_router_access

        mini_app = Flask(__name__)
        mini_app.secret_key = "test"

        user = _make_user(is_admin=False)
        db_mock = MagicMock()
        db_mock.get_user_router_perms.return_value = []  # no restrictions → write denied

        with mini_app.test_request_context("/test/5"):
            with patch("permissions.current_user", user):
                with patch("permissions.db", db_mock):
                    dec = require_router_access(write=True)

                    def inner(rid):
                        return "ok"

                    response, status = dec(inner)(rid=5)

        assert status == 403

    def test_non_admin_with_perm_write_allowed(self):
        from flask import Flask
        from permissions import require_router_access

        mini_app = Flask(__name__)
        mini_app.secret_key = "test"

        user = _make_user(is_admin=False, uid=2)
        perms = _make_perms([3], can_write=True)
        db_mock = MagicMock()
        db_mock.get_user_router_perms.return_value = perms

        called = []

        with mini_app.test_request_context("/test/3"):
            with patch("permissions.current_user", user):
                with patch("permissions.db", db_mock):
                    dec = require_router_access(write=True)

                    def inner(rid):
                        called.append(rid)
                        return "ok"

                    result = dec(inner)(rid=3)

        assert called == [3]

    def test_non_admin_wrong_router_denied(self):
        from flask import Flask
        from permissions import require_router_access

        mini_app = Flask(__name__)
        mini_app.secret_key = "test"

        user = _make_user(is_admin=False, uid=2)
        perms = _make_perms([3], can_write=True)
        db_mock = MagicMock()
        db_mock.get_user_router_perms.return_value = perms

        with mini_app.test_request_context("/test/9"):
            with patch("permissions.current_user", user):
                with patch("permissions.db", db_mock):
                    dec = require_router_access(write=False)

                    def inner(rid):
                        return "ok"

                    response, status = dec(inner)(rid=9)

        assert status == 403
