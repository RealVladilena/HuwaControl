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

        apscheduler_mock     = MagicMock()
        apscheduler_bg_mock  = MagicMock()
        apscheduler_bg_mock.BackgroundScheduler.return_value = MagicMock()
        scheduler_utils_mock = MagicMock()
        scheduler_utils_mock.scheduler   = MagicMock()
        scheduler_utils_mock._start_job  = MagicMock()
        scheduler_utils_mock._stop_job   = MagicMock()

        pysnmp_mock           = MagicMock()
        snmp_collector_mock   = MagicMock()

        with patch.dict("sys.modules", {
            "syslog_receiver":                    syslog_mock,
            "snmp_trap_receiver":                 trap_mock,
            "ping_collector":                     ping_mock,
            "reports":                            reports_mock,
            "flask_socketio":                     socketio_lib_mock,
            "socket_manager":                     socket_mgr_mock,
            "apscheduler":                        apscheduler_mock,
            "apscheduler.schedulers":             apscheduler_mock,
            "apscheduler.schedulers.background":  apscheduler_bg_mock,
            "scheduler_utils":                    scheduler_utils_mock,
            "pysnmp":                             pysnmp_mock,
            "pysnmp.hlapi":                       pysnmp_mock,
            "pysnmp.error":                       pysnmp_mock,
            "snmp_collector":                     snmp_collector_mock,
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
    """Expose le mock DB pour que les tests puissent configurer les retours.
    Réinitialise les valeurs critiques avant chaque test pour éviter les
    contaminations entre tests (needs_setup en particulier).
    """
    import database
    database.needs_setup.return_value  = False
    database.get_all_routers.return_value = []
    database.get_settings.return_value    = {}
    return database
