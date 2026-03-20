"""
Fixtures pytest partagées pour HuwaControl.

Pour les tests d'intégration (routes Flask), un mock complet de la couche DB
est utilisé afin que les tests ne nécessitent pas de PostgreSQL.
"""
import os
import sys
from unittest.mock import MagicMock, patch

import pytest

# ── Assure que la racine du projet est dans sys.path ─────────────────────────
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))


# ── Stubs DB utilisés pour tous les tests ─────────────────────────────────────

def _make_db_mock():
    mock = MagicMock()
    mock.needs_setup.return_value  = False
    mock.get_all_routers.return_value = []
    mock.get_settings.return_value    = {}
    mock.init_pool.return_value       = None
    mock.init_db.return_value         = None
    return mock


# ── App Flask de test ─────────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def app():
    """
    Crée l'application Flask avec la couche DB mockée.
    Scope session : l'app est créée une seule fois pour tous les tests.
    """
    db_mock = _make_db_mock()

    # Patch database avant l'import de app pour éviter les connexions réelles
    with patch.dict("sys.modules", {"database": db_mock}):
        # Patch également les modules qui démarrent des threads/sockets
        syslog_mock = MagicMock()
        syslog_mock.SyslogReceiver.return_value = MagicMock()
        trap_mock   = MagicMock()
        trap_mock.SnmpTrapReceiver.return_value  = MagicMock()
        ping_mock   = MagicMock()
        reports_mock = MagicMock()

        socketio_lib_mock = MagicMock()
        socketio_lib_mock.SocketIO.return_value = MagicMock()
        socket_mgr_mock = MagicMock()
        socket_mgr_mock.socketio = MagicMock()

        with patch.dict("sys.modules", {
            "syslog_receiver":    syslog_mock,
            "snmp_trap_receiver": trap_mock,
            "ping_collector":     ping_mock,
            "reports":            reports_mock,
            "flask_socketio":     socketio_lib_mock,
            "socket_manager":     socket_mgr_mock,
        }):
            import app as flask_app
            flask_app.app.config.update(
                TESTING   = True,
                SECRET_KEY = "test-secret-key",
                WTF_CSRF_ENABLED = False,
            )
            yield flask_app.app


@pytest.fixture()
def client(app):
    """Client de test Flask."""
    return app.test_client()


@pytest.fixture()
def db_mock(app):
    """Expose le mock DB pour que les tests puissent configurer les retours."""
    import database
    return database
