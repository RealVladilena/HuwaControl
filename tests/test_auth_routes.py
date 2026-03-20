"""
Tests d'intégration — blueprints/auth.py

Les tests vérifient le comportement HTTP des routes auth sans connexion
PostgreSQL réelle (la couche DB est mockée dans conftest.py).
"""
import pytest
from unittest.mock import patch, MagicMock


# ── /login ────────────────────────────────────────────────────────────────────

class TestLogin:

    def test_get_returns_200(self, client, db_mock):
        db_mock.get_settings.return_value = {}
        resp = client.get("/login")
        assert resp.status_code == 200
        assert b"HuwaControl" in resp.data

    def test_post_wrong_credentials_returns_200_with_error(self, client, db_mock):
        db_mock.verify_password.return_value = None
        db_mock.add_audit.return_value = None
        db_mock.get_settings.return_value = {}
        resp = client.post("/login", data={"username": "bad", "password": "wrong"})
        assert resp.status_code == 200
        assert "Identifiants" in resp.data.decode()

    def test_post_valid_credentials_redirects(self, client, db_mock):
        user_data = {"id": 1, "username": "admin", "is_admin": True, "email": None}
        db_mock.verify_password.return_value = user_data
        db_mock.get_user_by_id.return_value  = user_data
        db_mock.add_audit.return_value = None
        db_mock.get_settings.return_value = {}
        resp = client.post("/login", data={"username": "admin", "password": "password123"})
        # Should redirect to overview after login
        assert resp.status_code in (302, 303)

    def test_already_authenticated_redirects(self, client, db_mock):
        """Un utilisateur déjà connecté est redirigé depuis /login."""
        user_data = {"id": 1, "username": "admin", "is_admin": True, "email": None}
        db_mock.verify_password.return_value = user_data
        db_mock.get_user_by_id.return_value  = user_data
        db_mock.add_audit.return_value = None
        db_mock.get_settings.return_value = {}
        # Log in first
        with client.session_transaction() as sess:
            sess["_user_id"] = "1"
            sess["_fresh"]   = True
        resp = client.get("/login")
        assert resp.status_code == 302


# ── /setup ────────────────────────────────────────────────────────────────────

class TestSetup:

    def test_redirects_if_already_configured(self, client, db_mock):
        db_mock.needs_setup.return_value = False
        resp = client.get("/setup")
        assert resp.status_code == 302

    def test_setup_page_shown_when_needed(self, client, db_mock):
        db_mock.needs_setup.return_value = True
        resp = client.get("/setup")
        assert resp.status_code == 200

    def test_post_missing_fields_shows_error(self, client, db_mock):
        db_mock.needs_setup.return_value = True
        resp = client.post("/setup", data={
            "username": "",
            "password": "",
            "confirm":  "",
            "r_name":   "Router1",
            "r_ip":     "192.168.1.1",
        })
        assert resp.status_code == 200
        assert "requis" in resp.data.decode()

    def test_post_password_mismatch(self, client, db_mock):
        db_mock.needs_setup.return_value = True
        resp = client.post("/setup", data={
            "username": "admin",
            "password": "password1",
            "confirm":  "password2",
            "r_name":   "Router1",
            "r_ip":     "192.168.1.1",
        })
        assert resp.status_code == 200
        assert "correspondent" in resp.data.decode()

    def test_post_short_password(self, client, db_mock):
        db_mock.needs_setup.return_value = True
        resp = client.post("/setup", data={
            "username": "admin",
            "password": "short",
            "confirm":  "short",
            "r_name":   "Router1",
            "r_ip":     "192.168.1.1",
        })
        assert resp.status_code == 200
        assert "8 caract" in resp.data.decode()


# ── /set_lang ─────────────────────────────────────────────────────────────────

class TestSetLang:

    def test_set_lang_fr(self, client):
        resp = client.get("/set_lang/fr")
        assert resp.status_code == 302
        with client.session_transaction() as sess:
            assert sess.get("lang") == "fr"

    def test_set_lang_en(self, client):
        resp = client.get("/set_lang/en")
        assert resp.status_code == 302
        with client.session_transaction() as sess:
            assert sess.get("lang") == "en"

    def test_invalid_lang_ignored(self, client):
        with client.session_transaction() as sess:
            sess["lang"] = "fr"
        resp = client.get("/set_lang/de")
        assert resp.status_code == 302
        with client.session_transaction() as sess:
            # 'de' should not replace 'fr'
            assert sess.get("lang") == "fr"


# ── /logout ───────────────────────────────────────────────────────────────────

class TestLogout:

    def test_logout_requires_login(self, client):
        resp = client.get("/logout")
        # Unauthenticated → redirect to login
        assert resp.status_code == 302
        assert "login" in resp.headers["Location"].lower()
