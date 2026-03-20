"""
Couche d'accès PostgreSQL — HuwaControl.
Gère : users, routers, metrics (system + interfaces + bps).
"""
import hashlib
import logging
import secrets
import time
from contextlib import contextmanager

import psycopg2
import psycopg2.extras
from psycopg2.pool import ThreadedConnectionPool
from werkzeug.security import generate_password_hash, check_password_hash

import config

log = logging.getLogger("database")
_pool: ThreadedConnectionPool | None = None
_setup_done: bool | None = None   # cache "setup already completed"


# ─── Pool ─────────────────────────────────────────────────────────────────────

def init_pool(retries: int = 15, delay: int = 3) -> None:
    global _pool
    dsn = (f"host={config.DB_HOST} port={config.DB_PORT} "
           f"dbname={config.DB_NAME} user={config.DB_USER} "
           f"password={config.DB_PASS} connect_timeout=5")
    for attempt in range(1, retries + 1):
        try:
            _pool = ThreadedConnectionPool(minconn=2, maxconn=10, dsn=dsn)
            log.info("Pool PostgreSQL connecté à %s:%s/%s",
                     config.DB_HOST, config.DB_PORT, config.DB_NAME)
            return
        except psycopg2.OperationalError as e:
            log.warning("Postgres pas encore prêt (%d/%d): %s", attempt, retries, e)
            if attempt < retries:
                time.sleep(delay)
    raise RuntimeError("Impossible de se connecter à PostgreSQL")


@contextmanager
def get_db():
    conn = _pool.getconn()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        _pool.putconn(conn)


def _cur(conn):
    return conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)


# ─── Schéma ───────────────────────────────────────────────────────────────────

def init_db() -> None:
    with get_db() as conn:
        _cur(conn).execute("""
            CREATE TABLE IF NOT EXISTS users (
                id            SERIAL PRIMARY KEY,
                username      TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                is_admin      BOOLEAN NOT NULL DEFAULT true,
                created_at    BIGINT  NOT NULL
            );

            CREATE TABLE IF NOT EXISTS routers (
                id             SERIAL PRIMARY KEY,
                name           TEXT    NOT NULL,
                ip             TEXT    NOT NULL,
                snmp_version        INTEGER NOT NULL DEFAULT 2,
                snmp_community      TEXT    NOT NULL DEFAULT 'public',
                snmp_port           INTEGER NOT NULL DEFAULT 161,
                snmp_v3_username    TEXT,
                snmp_v3_auth_protocol TEXT DEFAULT 'SHA',
                snmp_v3_auth_password TEXT,
                snmp_v3_priv_protocol TEXT DEFAULT 'AES',
                snmp_v3_priv_password TEXT,
                snmp_v3_security_level TEXT DEFAULT 'authPriv',
                poll_interval  INTEGER NOT NULL DEFAULT 60,
                retention_days INTEGER NOT NULL DEFAULT 30,
                enabled        BOOLEAN NOT NULL DEFAULT true,
                created_at     BIGINT  NOT NULL,
                min_firmware   TEXT
            );

            CREATE TABLE IF NOT EXISTS system_metrics (
                id          BIGSERIAL PRIMARY KEY,
                router_id   INTEGER NOT NULL REFERENCES routers(id) ON DELETE CASCADE,
                ts          BIGINT  NOT NULL,
                sys_name    TEXT,
                sys_descr   TEXT,
                sys_uptime  BIGINT,
                location    TEXT,
                cpu_usage    DOUBLE PRECISION,
                mem_usage    DOUBLE PRECISION,
                temperature  DOUBLE PRECISION,
                fault_status INTEGER
            );

            CREATE TABLE IF NOT EXISTS interface_stats (
                id              BIGSERIAL PRIMARY KEY,
                router_id       INTEGER NOT NULL REFERENCES routers(id) ON DELETE CASCADE,
                ts              BIGINT  NOT NULL,
                if_index        INTEGER NOT NULL,
                if_name         TEXT,
                if_status       SMALLINT,
                speed_mbps      INTEGER,
                in_octets       BIGINT,
                out_octets      BIGINT,
                in_errors       BIGINT,
                out_errors      BIGINT,
                in_ucast_pkts   BIGINT,
                out_ucast_pkts  BIGINT
            );

            CREATE TABLE IF NOT EXISTS interface_bps (
                id        BIGSERIAL PRIMARY KEY,
                router_id INTEGER NOT NULL REFERENCES routers(id) ON DELETE CASCADE,
                ts        BIGINT  NOT NULL,
                if_index  INTEGER NOT NULL,
                if_name   TEXT,
                in_bps    DOUBLE PRECISION,
                out_bps   DOUBLE PRECISION,
                in_pps    DOUBLE PRECISION,
                out_pps   DOUBLE PRECISION
            );

            CREATE INDEX IF NOT EXISTS idx_sys_router_ts   ON system_metrics(router_id, ts);
            CREATE INDEX IF NOT EXISTS idx_iface_router_ts ON interface_stats(router_id, ts);
            CREATE INDEX IF NOT EXISTS idx_bps_router_ts   ON interface_bps(router_id, ts);
            CREATE INDEX IF NOT EXISTS idx_bps_router_if   ON interface_bps(router_id, if_index, ts);

            CREATE TABLE IF NOT EXISTS events (
                id        BIGSERIAL PRIMARY KEY,
                router_id INTEGER REFERENCES routers(id) ON DELETE CASCADE,
                ts        BIGINT  NOT NULL,
                level     TEXT    NOT NULL DEFAULT 'info',
                category  TEXT    NOT NULL DEFAULT 'system',
                title     TEXT    NOT NULL,
                message   TEXT,
                acked     BOOLEAN NOT NULL DEFAULT false,
                acked_by  TEXT,
                acked_at  BIGINT
            );
            CREATE INDEX IF NOT EXISTS idx_events_router_ts ON events(router_id, ts);

            CREATE TABLE IF NOT EXISTS discord_webhooks (
                id          SERIAL PRIMARY KEY,
                name        TEXT    NOT NULL DEFAULT 'Webhook',
                url         TEXT    NOT NULL,
                enabled     BOOLEAN NOT NULL DEFAULT true,
                on_info     BOOLEAN NOT NULL DEFAULT true,
                on_warning  BOOLEAN NOT NULL DEFAULT true,
                on_error    BOOLEAN NOT NULL DEFAULT true,
                created_at  BIGINT  NOT NULL
            );

            CREATE TABLE IF NOT EXISTS telegram_bots (
                id          SERIAL PRIMARY KEY,
                name        TEXT    NOT NULL DEFAULT 'Telegram',
                bot_token   TEXT    NOT NULL,
                chat_id     TEXT    NOT NULL,
                enabled     BOOLEAN NOT NULL DEFAULT true,
                on_info     BOOLEAN NOT NULL DEFAULT true,
                on_warning  BOOLEAN NOT NULL DEFAULT true,
                on_error    BOOLEAN NOT NULL DEFAULT true,
                created_at  BIGINT  NOT NULL
            );

            CREATE TABLE IF NOT EXISTS audit_log (
                id         BIGSERIAL PRIMARY KEY,
                ts         BIGINT NOT NULL,
                username   TEXT,
                action     TEXT NOT NULL,
                details    TEXT,
                ip         TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts);

            CREATE TABLE IF NOT EXISTS ping_targets (
                id         SERIAL PRIMARY KEY,
                router_id  INTEGER REFERENCES routers(id) ON DELETE CASCADE,
                label      TEXT NOT NULL,
                host       TEXT NOT NULL,
                enabled    BOOLEAN NOT NULL DEFAULT true,
                created_at BIGINT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS ping_results (
                id         BIGSERIAL PRIMARY KEY,
                target_id  INTEGER NOT NULL REFERENCES ping_targets(id) ON DELETE CASCADE,
                ts         BIGINT  NOT NULL,
                rtt_ms     DOUBLE PRECISION,
                success    BOOLEAN NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_ping_target_ts ON ping_results(target_id, ts);

            CREATE TABLE IF NOT EXISTS interface_thresholds (
                id         SERIAL PRIMARY KEY,
                router_id  INTEGER NOT NULL REFERENCES routers(id) ON DELETE CASCADE,
                if_index   INTEGER NOT NULL,
                if_name    TEXT,
                bw_warn_pct INTEGER NOT NULL DEFAULT 80,
                UNIQUE (router_id, if_index)
            );

            CREATE TABLE IF NOT EXISTS interface_aliases (
                id         SERIAL PRIMARY KEY,
                router_id  INTEGER NOT NULL REFERENCES routers(id) ON DELETE CASCADE,
                if_index   INTEGER NOT NULL,
                alias      TEXT NOT NULL,
                UNIQUE (router_id, if_index)
            );

            CREATE TABLE IF NOT EXISTS settings (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS syslogs (
                id        BIGSERIAL PRIMARY KEY,
                ts        BIGINT  NOT NULL,
                received_at BIGINT NOT NULL,
                source_ip TEXT,
                facility  INTEGER,
                severity  INTEGER,
                hostname  TEXT,
                program   TEXT,
                message   TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_syslogs_ts ON syslogs(ts DESC);

            CREATE TABLE IF NOT EXISTS arp_history (
                id         BIGSERIAL PRIMARY KEY,
                router_id  INTEGER NOT NULL REFERENCES routers(id) ON DELETE CASCADE,
                mac        TEXT NOT NULL,
                ip         TEXT NOT NULL,
                first_seen BIGINT NOT NULL,
                last_seen  BIGINT NOT NULL,
                UNIQUE (router_id, mac)
            );
            CREATE INDEX IF NOT EXISTS idx_arp_router ON arp_history(router_id, last_seen DESC);

            CREATE TABLE IF NOT EXISTS user_router_perms (
                id        SERIAL PRIMARY KEY,
                user_id   INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                router_id INTEGER NOT NULL REFERENCES routers(id) ON DELETE CASCADE,
                can_write BOOLEAN NOT NULL DEFAULT false,
                UNIQUE (user_id, router_id)
            );
        """)
        # Migration : colonne received_at sur syslogs
        cur = _cur(conn)
        cur.execute(
            "SELECT 1 FROM information_schema.columns "
            "WHERE table_name='syslogs' AND column_name='received_at'"
        )
        if not cur.fetchone():
            _cur(conn).execute(
                "ALTER TABLE syslogs ADD COLUMN received_at BIGINT NOT NULL DEFAULT 0"
            )
            # Backfill : utilise ts comme valeur de réception pour les anciens logs
            _cur(conn).execute(
                "UPDATE syslogs SET received_at = ts WHERE received_at = 0"
            )
            log.info("Migration syslogs: colonne received_at ajoutée et backfillée")
        else:
            # Corriger les éventuelles lignes avec received_at = 0
            _cur(conn).execute(
                "UPDATE syslogs SET received_at = ts WHERE received_at = 0"
            )

        # Index sur received_at si manquant
        cur = _cur(conn)
        cur.execute(
            "SELECT 1 FROM pg_indexes "
            "WHERE tablename='syslogs' AND indexname='idx_syslogs_received_at'"
        )
        if not cur.fetchone():
            _cur(conn).execute(
                "CREATE INDEX idx_syslogs_received_at ON syslogs(received_at DESC)"
            )

        # Migration : colonnes ack sur events
        for col, defn in [
            ("acked",    "BOOLEAN NOT NULL DEFAULT false"),
            ("acked_by", "TEXT"),
            ("acked_at", "BIGINT"),
        ]:
            cur = _cur(conn)
            cur.execute(
                "SELECT 1 FROM information_schema.columns "
                "WHERE table_name='events' AND column_name=%s", (col,)
            )
            if not cur.fetchone():
                _cur(conn).execute(f"ALTER TABLE events ADD COLUMN {col} {defn}")

        # Migration : colonnes packets + pps
        for tbl, col, defn in [
            ("interface_stats", "in_ucast_pkts",   "BIGINT"),
            ("interface_stats", "out_ucast_pkts",  "BIGINT"),
            ("interface_bps",   "in_pps",          "DOUBLE PRECISION"),
            ("interface_bps",   "out_pps",         "DOUBLE PRECISION"),
            ("system_metrics",  "fault_status",    "INTEGER"),
            ("routers",         "min_firmware",    "TEXT"),
        ]:
            cur = _cur(conn)
            cur.execute(
                "SELECT 1 FROM information_schema.columns "
                "WHERE table_name=%s AND column_name=%s", (tbl, col)
            )
            if not cur.fetchone():
                _cur(conn).execute(f"ALTER TABLE {tbl} ADD COLUMN {col} {defn}")

        # Migration : ajout des colonnes SNMPv3 si la table existait déjà
        for col, definition in [
            ("snmp_version",         "INTEGER NOT NULL DEFAULT 2"),
            ("snmp_v3_username",     "TEXT"),
            ("snmp_v3_auth_protocol","TEXT DEFAULT 'SHA'"),
            ("snmp_v3_auth_password","TEXT"),
            ("snmp_v3_priv_protocol","TEXT DEFAULT 'AES'"),
            ("snmp_v3_priv_password","TEXT"),
            ("snmp_v3_security_level","TEXT DEFAULT 'authPriv'"),
        ]:
            cur = _cur(conn)
            cur.execute(
                "SELECT 1 FROM information_schema.columns "
                "WHERE table_name='routers' AND column_name=%s", (col,)
            )
            if not cur.fetchone():
                _cur(conn).execute(
                    f"ALTER TABLE routers ADD COLUMN {col} {definition}"
                )

        # Migration : colonne email sur users
        cur = _cur(conn)
        cur.execute(
            "SELECT 1 FROM information_schema.columns "
            "WHERE table_name='users' AND column_name='email'"
        )
        if not cur.fetchone():
            _cur(conn).execute("ALTER TABLE users ADD COLUMN email TEXT")
            log.info("Migration users: colonne email ajoutée")

        # Table de tokens de réinitialisation de mot de passe
        _cur(conn).execute("""
            CREATE TABLE IF NOT EXISTS password_reset_tokens (
                id         SERIAL PRIMARY KEY,
                user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                token_hash TEXT    NOT NULL UNIQUE,
                expires_at BIGINT  NOT NULL,
                used       BOOLEAN NOT NULL DEFAULT false
            );
        """)
        # LTE metrics
        _cur(conn).execute("""
            CREATE TABLE IF NOT EXISTS lte_metrics (
                id          SERIAL PRIMARY KEY,
                router_id   INTEGER NOT NULL REFERENCES routers(id) ON DELETE CASCADE,
                ts          BIGINT  NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW()),
                rssi        INTEGER,
                rsrp        INTEGER,
                rsrq        INTEGER,
                sinr        INTEGER,
                operator    TEXT,
                access_mode TEXT,
                sim_status  INTEGER
            );
        """)
        _cur(conn).execute(
            "CREATE INDEX IF NOT EXISTS idx_lte_router_ts ON lte_metrics(router_id, ts DESC)"
        )

        # WiFi radio metrics
        _cur(conn).execute("""
            CREATE TABLE IF NOT EXISTS wifi_radio (
                id           SERIAL PRIMARY KEY,
                router_id    INTEGER NOT NULL REFERENCES routers(id) ON DELETE CASCADE,
                ts           BIGINT  NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW()),
                radio_index  INTEGER NOT NULL,
                channel      INTEGER,
                tx_power_dbm INTEGER,
                mode         TEXT
            );
        """)
        _cur(conn).execute(
            "CREATE INDEX IF NOT EXISTS idx_wifiradio_router ON wifi_radio(router_id, ts DESC)"
        )

        # ── Nouvelles tables ──────────────────────────────────────────────────

        # Fenêtres de maintenance (bypass notifications)
        _cur(conn).execute("""
            CREATE TABLE IF NOT EXISTS maintenance_windows (
                id          SERIAL PRIMARY KEY,
                router_id   INTEGER REFERENCES routers(id) ON DELETE CASCADE,
                start_ts    BIGINT NOT NULL,
                end_ts      BIGINT NOT NULL,
                description TEXT,
                created_at  BIGINT NOT NULL,
                created_by  TEXT
            );
        """)
        _cur(conn).execute(
            "CREATE INDEX IF NOT EXISTS idx_maint_router ON maintenance_windows(router_id, start_ts)"
        )

        # Historique clients WiFi
        _cur(conn).execute("""
            CREATE TABLE IF NOT EXISTS wifi_client_history (
                id        BIGSERIAL PRIMARY KEY,
                router_id INTEGER NOT NULL REFERENCES routers(id) ON DELETE CASCADE,
                ts        BIGINT  NOT NULL,
                mac       TEXT    NOT NULL,
                ssid      TEXT,
                rssi      INTEGER,
                band      TEXT
            );
        """)
        _cur(conn).execute(
            "CREATE INDEX IF NOT EXISTS idx_wificli_router_ts ON wifi_client_history(router_id, ts DESC)"
        )

        # Totaux de bande passante journaliers / mensuels
        _cur(conn).execute("""
            CREATE TABLE IF NOT EXISTS bandwidth_totals (
                id          BIGSERIAL PRIMARY KEY,
                router_id   INTEGER NOT NULL REFERENCES routers(id) ON DELETE CASCADE,
                if_index    INTEGER NOT NULL,
                if_name     TEXT,
                period_type TEXT    NOT NULL,   -- 'daily' | 'monthly'
                period_key  TEXT    NOT NULL,   -- '2026-03-20' | '2026-03'
                in_bytes    BIGINT  NOT NULL DEFAULT 0,
                out_bytes   BIGINT  NOT NULL DEFAULT 0,
                updated_at  BIGINT  NOT NULL,
                UNIQUE (router_id, if_index, period_type, period_key)
            );
        """)
        _cur(conn).execute(
            "CREATE INDEX IF NOT EXISTS idx_bwtotals_router ON bandwidth_totals(router_id, period_type, period_key)"
        )

        # SLA WAN par interface
        _cur(conn).execute("""
            CREATE TABLE IF NOT EXISTS wan_sla (
                id        BIGSERIAL PRIMARY KEY,
                router_id INTEGER NOT NULL REFERENCES routers(id) ON DELETE CASCADE,
                if_index  INTEGER NOT NULL,
                if_name   TEXT,
                ts        BIGINT  NOT NULL,
                was_up    BOOLEAN NOT NULL
            );
        """)
        _cur(conn).execute(
            "CREATE INDEX IF NOT EXISTS idx_wansla_router_ts ON wan_sla(router_id, if_index, ts DESC)"
        )

        # OID personnalisés (polling)
        _cur(conn).execute("""
            CREATE TABLE IF NOT EXISTS custom_oid_polls (
                id        SERIAL PRIMARY KEY,
                router_id INTEGER NOT NULL REFERENCES routers(id) ON DELETE CASCADE,
                oid       TEXT    NOT NULL,
                label     TEXT    NOT NULL,
                unit      TEXT,
                enabled   BOOLEAN NOT NULL DEFAULT true,
                created_at BIGINT NOT NULL
            );
        """)
        _cur(conn).execute("""
            CREATE TABLE IF NOT EXISTS custom_oid_values (
                id         BIGSERIAL PRIMARY KEY,
                poll_id    INTEGER NOT NULL REFERENCES custom_oid_polls(id) ON DELETE CASCADE,
                ts         BIGINT  NOT NULL,
                value_text TEXT,
                value_num  DOUBLE PRECISION
            );
        """)
        _cur(conn).execute(
            "CREATE INDEX IF NOT EXISTS idx_customval_poll_ts ON custom_oid_values(poll_id, ts DESC)"
        )

        # Table de persistance des états d'alerte (cooldown + statuts interfaces)
        _cur(conn).execute("""
            CREATE TABLE IF NOT EXISTS alert_state (
                key        TEXT PRIMARY KEY,
                value      TEXT NOT NULL,
                updated_at BIGINT NOT NULL
            );
        """)

        # Migration arp_history : colonnes is_known + alerted
        for col, defn in [("is_known", "BOOLEAN NOT NULL DEFAULT false"),
                          ("alerted",  "BOOLEAN NOT NULL DEFAULT false")]:
            cur = _cur(conn)
            cur.execute(
                "SELECT 1 FROM information_schema.columns "
                "WHERE table_name='arp_history' AND column_name=%s", (col,)
            )
            if not cur.fetchone():
                _cur(conn).execute(f"ALTER TABLE arp_history ADD COLUMN {col} {defn}")

    log.info("Schéma DB initialisé")


# ─── Setup / Users ────────────────────────────────────────────────────────────

def needs_setup() -> bool:
    global _setup_done
    if _setup_done:
        return False
    with get_db() as conn:
        cur = _cur(conn)
        cur.execute("SELECT COUNT(*) AS n FROM users")
        row = cur.fetchone()
        done = row["n"] > 0
    if done:
        _setup_done = True
    return not done


def create_user(username: str, password: str, is_admin: bool = True) -> dict:
    with get_db() as conn:
        cur = _cur(conn)
        cur.execute(
            "INSERT INTO users (username, password_hash, is_admin, created_at) "
            "VALUES (%s, %s, %s, %s) RETURNING *",
            (username, generate_password_hash(password), is_admin, int(time.time()))
        )
        return dict(cur.fetchone())


def get_user_by_username(username: str) -> dict | None:
    with get_db() as conn:
        cur = _cur(conn)
        cur.execute("SELECT * FROM users WHERE username = %s", (username,))
        row = cur.fetchone()
    return dict(row) if row else None


def get_user_by_id(user_id: int) -> dict | None:
    with get_db() as conn:
        cur = _cur(conn)
        cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))
        row = cur.fetchone()
    return dict(row) if row else None


def verify_password(username: str, password: str) -> dict | None:
    """Retourne le user si les credentials sont valides, sinon None."""
    user = get_user_by_username(username)
    if user and check_password_hash(user["password_hash"], password):
        return user
    return None


def update_password(user_id: int, new_password: str) -> None:
    with get_db() as conn:
        _cur(conn).execute(
            "UPDATE users SET password_hash = %s WHERE id = %s",
            (generate_password_hash(new_password), user_id)
        )


def get_all_users() -> list:
    with get_db() as conn:
        cur = _cur(conn)
        cur.execute("SELECT id, username, is_admin, created_at, email FROM users ORDER BY id")
        return [dict(r) for r in cur.fetchall()]


def delete_user(user_id: int) -> None:
    with get_db() as conn:
        _cur(conn).execute("DELETE FROM users WHERE id = %s", (user_id,))


def get_user_by_email(email: str) -> dict | None:
    with get_db() as conn:
        cur = _cur(conn)
        cur.execute("SELECT * FROM users WHERE lower(email) = lower(%s)", (email,))
        row = cur.fetchone()
    return dict(row) if row else None


def set_user_email(user_id: int, email: str | None) -> None:
    val = email.strip().lower() if email else None
    with get_db() as conn:
        _cur(conn).execute(
            "UPDATE users SET email = %s WHERE id = %s",
            (val, user_id)
        )


def create_reset_token(user_id: int) -> str:
    """Génère un token de réinitialisation (30 min). Retourne le token brut."""
    raw    = secrets.token_urlsafe(32)
    hashed = hashlib.sha256(raw.encode()).hexdigest()
    expires = int(time.time()) + 1800
    with get_db() as conn:
        # Invalider les tokens précédents de cet utilisateur
        _cur(conn).execute(
            "UPDATE password_reset_tokens SET used=true WHERE user_id=%s AND used=false",
            (user_id,)
        )
        _cur(conn).execute(
            "INSERT INTO password_reset_tokens (user_id, token_hash, expires_at) "
            "VALUES (%s, %s, %s)",
            (user_id, hashed, expires)
        )
    return raw


def validate_reset_token(raw_token: str) -> int | None:
    """Vérifie sans consommer. Retourne user_id si valide, None sinon."""
    hashed = hashlib.sha256(raw_token.encode()).hexdigest()
    with get_db() as conn:
        cur = _cur(conn)
        cur.execute(
            "SELECT user_id, expires_at FROM password_reset_tokens "
            "WHERE token_hash=%s AND used=false",
            (hashed,)
        )
        row = cur.fetchone()
    if not row:
        return None
    if int(time.time()) > row["expires_at"]:
        return None
    return row["user_id"]


def consume_reset_token(raw_token: str) -> int | None:
    """Consomme le token. Retourne user_id si succès, None sinon."""
    hashed = hashlib.sha256(raw_token.encode()).hexdigest()
    with get_db() as conn:
        cur = _cur(conn)
        cur.execute(
            "UPDATE password_reset_tokens SET used=true "
            "WHERE token_hash=%s AND used=false AND expires_at > %s "
            "RETURNING user_id",
            (hashed, int(time.time()))
        )
        row = cur.fetchone()
    return row["user_id"] if row else None


# ─── Routeurs ─────────────────────────────────────────────────────────────────

def get_all_routers() -> list:
    with get_db() as conn:
        cur = _cur(conn)
        cur.execute("SELECT * FROM routers ORDER BY id")
        return [dict(r) for r in cur.fetchall()]


def get_enabled_routers() -> list:
    with get_db() as conn:
        cur = _cur(conn)
        cur.execute("SELECT * FROM routers WHERE enabled = true ORDER BY id")
        return [dict(r) for r in cur.fetchall()]


def get_router(router_id: int) -> dict | None:
    with get_db() as conn:
        cur = _cur(conn)
        cur.execute("SELECT * FROM routers WHERE id = %s", (router_id,))
        row = cur.fetchone()
    return dict(row) if row else None


def create_router(name: str, ip: str, community: str = "public",
                  port: int = 161, poll_interval: int = 60,
                  retention_days: int = 30,
                  snmp_version: int = 2,
                  snmp_v3_username: str = None,
                  snmp_v3_auth_protocol: str = "SHA",
                  snmp_v3_auth_password: str = None,
                  snmp_v3_priv_protocol: str = "AES",
                  snmp_v3_priv_password: str = None,
                  snmp_v3_security_level: str = "authPriv") -> dict:
    with get_db() as conn:
        cur = _cur(conn)
        cur.execute(
            "INSERT INTO routers (name, ip, snmp_version, snmp_community, snmp_port, "
            "snmp_v3_username, snmp_v3_auth_protocol, snmp_v3_auth_password, "
            "snmp_v3_priv_protocol, snmp_v3_priv_password, snmp_v3_security_level, "
            "poll_interval, retention_days, enabled, created_at) "
            "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,true,%s) RETURNING *",
            (name, ip, snmp_version, community, port,
             snmp_v3_username, snmp_v3_auth_protocol, snmp_v3_auth_password,
             snmp_v3_priv_protocol, snmp_v3_priv_password, snmp_v3_security_level,
             poll_interval, retention_days, int(time.time()))
        )
        return dict(cur.fetchone())


def update_router(router_id: int, **fields) -> dict | None:
    allowed = {"name", "ip", "snmp_version", "snmp_community", "snmp_port",
               "snmp_v3_username", "snmp_v3_auth_protocol", "snmp_v3_auth_password",
               "snmp_v3_priv_protocol", "snmp_v3_priv_password", "snmp_v3_security_level",
               "poll_interval", "retention_days", "enabled", "min_firmware"}
    updates = {k: v for k, v in fields.items() if k in allowed}
    if not updates:
        return get_router(router_id)
    set_clause = ", ".join(f"{k} = %s" for k in updates)
    with get_db() as conn:
        cur = _cur(conn)
        cur.execute(
            f"UPDATE routers SET {set_clause} WHERE id = %s RETURNING *",
            (*updates.values(), router_id)
        )
        row = cur.fetchone()
    return dict(row) if row else None


def delete_router(router_id: int) -> None:
    with get_db() as conn:
        _cur(conn).execute("DELETE FROM routers WHERE id = %s", (router_id,))


# ─── Écriture métriques ───────────────────────────────────────────────────────

def insert_system(router_id: int, data: dict) -> None:
    with get_db() as conn:
        _cur(conn).execute(
            "INSERT INTO system_metrics "
            "(router_id, ts, sys_name, sys_descr, sys_uptime, location, "
            " cpu_usage, mem_usage, temperature, fault_status) "
            "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
            (router_id, int(time.time()),
             data.get("sys_name"), data.get("sys_descr"), data.get("sys_uptime"),
             data.get("location"), data.get("cpu_usage"),
             data.get("mem_usage"), data.get("temperature"), data.get("fault_status"))
        )


def insert_interfaces(router_id: int, rows: list) -> None:
    if not rows:
        return
    ts = int(time.time())
    with get_db() as conn:
        psycopg2.extras.execute_batch(
            _cur(conn),
            "INSERT INTO interface_stats "
            "(router_id, ts, if_index, if_name, if_status, speed_mbps, "
            " in_octets, out_octets, in_errors, out_errors, "
            " in_ucast_pkts, out_ucast_pkts) "
            "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
            [(router_id, ts, r["if_index"], r.get("if_name"), r.get("if_status"),
              r.get("speed_mbps"), r.get("in_octets"), r.get("out_octets"),
              r.get("in_errors"), r.get("out_errors"),
              r.get("in_ucast_pkts"), r.get("out_ucast_pkts")) for r in rows]
        )


def insert_bps(router_id: int, rows: list) -> None:
    if not rows:
        return
    ts = int(time.time())
    with get_db() as conn:
        psycopg2.extras.execute_batch(
            _cur(conn),
            "INSERT INTO interface_bps "
            "(router_id, ts, if_index, if_name, in_bps, out_bps, in_pps, out_pps) "
            "VALUES (%s,%s,%s,%s,%s,%s,%s,%s)",
            [(router_id, ts, r["if_index"], r.get("if_name"),
              r.get("in_bps"), r.get("out_bps"),
              r.get("in_pps"), r.get("out_pps")) for r in rows]
        )


def purge_old(router_id: int, retention_days: int) -> None:
    cutoff = int(time.time()) - retention_days * 86400
    with get_db() as conn:
        cur = _cur(conn)
        cur.execute("DELETE FROM system_metrics  WHERE router_id=%s AND ts<%s", (router_id, cutoff))
        cur.execute("DELETE FROM interface_stats WHERE router_id=%s AND ts<%s", (router_id, cutoff))
        cur.execute("DELETE FROM interface_bps   WHERE router_id=%s AND ts<%s", (router_id, cutoff))


def purge_lte(router_id: int, days: int) -> None:
    cutoff = int(time.time()) - days * 86400
    with get_db() as conn:
        _cur(conn).execute("DELETE FROM lte_metrics WHERE router_id=%s AND ts<%s", (router_id, cutoff))


def purge_wifi_radio(router_id: int, days: int) -> None:
    cutoff = int(time.time()) - days * 86400
    with get_db() as conn:
        _cur(conn).execute("DELETE FROM wifi_radio WHERE router_id=%s AND ts<%s", (router_id, cutoff))


def purge_wifi_client_history(router_id: int, days: int) -> None:
    cutoff = int(time.time()) - days * 86400
    with get_db() as conn:
        _cur(conn).execute("DELETE FROM wifi_client_history WHERE router_id=%s AND ts<%s", (router_id, cutoff))


def purge_wan_sla(router_id: int, days: int) -> None:
    cutoff = int(time.time()) - days * 86400
    with get_db() as conn:
        _cur(conn).execute("DELETE FROM wan_sla WHERE router_id=%s AND ts<%s", (router_id, cutoff))


# ─── Lecture métriques ────────────────────────────────────────────────────────

def get_latest_system(router_id: int) -> dict:
    with get_db() as conn:
        cur = _cur(conn)
        cur.execute("SELECT * FROM system_metrics WHERE router_id=%s ORDER BY ts DESC LIMIT 1",
                    (router_id,))
        row = cur.fetchone()
    return dict(row) if row else {}


def get_system_history(router_id: int, hours: int = 24) -> list:
    since = int(time.time()) - hours * 3600
    with get_db() as conn:
        cur = _cur(conn)
        cur.execute("SELECT * FROM system_metrics WHERE router_id=%s AND ts>=%s ORDER BY ts ASC",
                    (router_id, since))
        return [dict(r) for r in cur.fetchall()]


def get_system_history_days(router_id: int, days: int = 30) -> list:
    since = int(time.time()) - days * 86400
    with get_db() as conn:
        cur = _cur(conn)
        cur.execute("""
            SELECT
                to_char(to_timestamp(ts) AT TIME ZONE 'Europe/Paris',
                        'YYYY-MM-DD HH24:00') AS hour,
                AVG(cpu_usage)   AS cpu_avg, MAX(cpu_usage)   AS cpu_max,
                AVG(mem_usage)   AS mem_avg, MAX(mem_usage)   AS mem_max,
                AVG(temperature) AS temp_avg
            FROM system_metrics
            WHERE router_id=%s AND ts>=%s
            GROUP BY hour ORDER BY hour ASC
        """, (router_id, since))
        return [dict(r) for r in cur.fetchall()]


def get_interfaces_latest(router_id: int) -> list:
    with get_db() as conn:
        cur = _cur(conn)
        cur.execute("SELECT MAX(ts) AS ts FROM interface_stats WHERE router_id=%s", (router_id,))
        row = cur.fetchone()
        if not row or row["ts"] is None:
            return []
        cur.execute("SELECT * FROM interface_stats WHERE router_id=%s AND ts=%s ORDER BY if_index",
                    (router_id, row["ts"]))
        return [dict(r) for r in cur.fetchall()]


def get_known_interfaces(router_id: int) -> list:
    with get_db() as conn:
        cur = _cur(conn)
        cur.execute("""
            SELECT DISTINCT ON (if_index) if_index, if_name
            FROM interface_stats WHERE router_id=%s
            ORDER BY if_index ASC, ts DESC
        """, (router_id,))
        return [dict(r) for r in cur.fetchall()]


def get_bps_history(router_id: int, if_index: int, hours: int = 24) -> list:
    since = int(time.time()) - hours * 3600
    with get_db() as conn:
        cur = _cur(conn)
        cur.execute("""
            SELECT ts, in_bps, out_bps, in_pps, out_pps FROM interface_bps
            WHERE router_id=%s AND if_index=%s AND ts>=%s ORDER BY ts ASC
        """, (router_id, if_index, since))
        return [dict(r) for r in cur.fetchall()]


def get_bps_history_days(router_id: int, if_index: int, days: int = 30) -> list:
    since = int(time.time()) - days * 86400
    with get_db() as conn:
        cur = _cur(conn)
        cur.execute("""
            SELECT
                to_char(to_timestamp(ts) AT TIME ZONE 'Europe/Paris',
                        'YYYY-MM-DD HH24:00') AS hour,
                AVG(in_bps) AS in_avg, MAX(in_bps) AS in_max,
                AVG(out_bps) AS out_avg, MAX(out_bps) AS out_max
            FROM interface_bps
            WHERE router_id=%s AND if_index=%s AND ts>=%s
            GROUP BY hour ORDER BY hour ASC
        """, (router_id, if_index, since))
        return [dict(r) for r in cur.fetchall()]


# ─── Événements ───────────────────────────────────────────────────────────────

def insert_event(router_id: int, level: str, category: str,
                 title: str, message: str = "") -> None:
    with get_db() as conn:
        _cur(conn).execute(
            "INSERT INTO events (router_id, ts, level, category, title, message) "
            "VALUES (%s,%s,%s,%s,%s,%s)",
            (router_id, int(time.time()), level, category, title, message)
        )


def get_events(router_id: int | None = None, limit: int = 200) -> list:
    with get_db() as conn:
        cur = _cur(conn)
        if router_id:
            cur.execute(
                "SELECT e.*, r.name AS router_name FROM events e "
                "LEFT JOIN routers r ON e.router_id = r.id "
                "WHERE e.router_id=%s ORDER BY e.ts DESC LIMIT %s",
                (router_id, limit)
            )
        else:
            cur.execute(
                "SELECT e.*, r.name AS router_name FROM events e "
                "LEFT JOIN routers r ON e.router_id = r.id "
                "ORDER BY e.ts DESC LIMIT %s", (limit,)
            )
        return [dict(r) for r in cur.fetchall()]


def get_events_daily(router_id: int | None = None, days: int = 60) -> list:
    """Retourne le nombre d'alertes (warning+error) par jour sur les N derniers jours."""
    with get_db() as conn:
        cur = _cur(conn)
        since = int(time.time()) - days * 86400
        if router_id:
            cur.execute(
                "SELECT DATE(to_timestamp(ts)) AS day, COUNT(*) AS cnt "
                "FROM events WHERE ts >= %s AND router_id = %s "
                "AND level IN ('warning','error') "
                "GROUP BY day ORDER BY day",
                (since, router_id)
            )
        else:
            cur.execute(
                "SELECT DATE(to_timestamp(ts)) AS day, COUNT(*) AS cnt "
                "FROM events WHERE ts >= %s "
                "AND level IN ('warning','error') "
                "GROUP BY day ORDER BY day",
                (since,)
            )
        return [{"day": str(r["day"]), "count": int(r["cnt"])} for r in cur.fetchall()]


def purge_events(days: int = 30) -> None:
    cutoff = int(time.time()) - days * 86400
    with get_db() as conn:
        _cur(conn).execute("DELETE FROM events WHERE ts < %s", (cutoff,))


# ─── Discord webhooks ─────────────────────────────────────────────────────────

def get_discord_webhooks(enabled_only: bool = False) -> list:
    with get_db() as conn:
        cur = _cur(conn)
        if enabled_only:
            cur.execute("SELECT * FROM discord_webhooks WHERE enabled=true ORDER BY id")
        else:
            cur.execute("SELECT * FROM discord_webhooks ORDER BY id")
        return [dict(r) for r in cur.fetchall()]


def create_discord_webhook(name: str, url: str,
                            on_info: bool = True, on_warning: bool = True,
                            on_error: bool = True) -> dict:
    with get_db() as conn:
        cur = _cur(conn)
        cur.execute(
            "INSERT INTO discord_webhooks "
            "(name, url, enabled, on_info, on_warning, on_error, created_at) "
            "VALUES (%s,%s,true,%s,%s,%s,%s) RETURNING *",
            (name, url, on_info, on_warning, on_error, int(time.time()))
        )
        return dict(cur.fetchone())


def update_discord_webhook(wh_id: int, **fields) -> dict | None:
    allowed = {"name", "url", "enabled", "on_info", "on_warning", "on_error"}
    updates = {k: v for k, v in fields.items() if k in allowed}
    if not updates:
        return None
    set_clause = ", ".join(f"{k} = %s" for k in updates)
    with get_db() as conn:
        cur = _cur(conn)
        cur.execute(
            f"UPDATE discord_webhooks SET {set_clause} WHERE id=%s RETURNING *",
            (*updates.values(), wh_id)
        )
        row = cur.fetchone()
    return dict(row) if row else None


def delete_discord_webhook(wh_id: int) -> None:
    with get_db() as conn:
        _cur(conn).execute("DELETE FROM discord_webhooks WHERE id=%s", (wh_id,))


# ─── Paramètres globaux (clé/valeur) ─────────────────────────────────────────

def get_settings() -> dict:
    with get_db() as conn:
        cur = _cur(conn)
        cur.execute("SELECT key, value FROM settings")
        return {r["key"]: r["value"] for r in cur.fetchall()}


def set_setting(key: str, value: str) -> None:
    with get_db() as conn:
        _cur(conn).execute(
            "INSERT INTO settings (key, value) VALUES (%s,%s) "
            "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
            (key, str(value))
        )


# ─── Acquittement d'événements ────────────────────────────────────────────────

def ack_event(event_id: int, username: str) -> bool:
    with get_db() as conn:
        cur = _cur(conn)
        cur.execute(
            "UPDATE events SET acked=true, acked_by=%s, acked_at=%s "
            "WHERE id=%s AND acked=false RETURNING id",
            (username, int(time.time()), event_id)
        )
        return cur.fetchone() is not None


# ─── Journal d'audit ──────────────────────────────────────────────────────────

def add_audit(username: str, action: str, details: str = "", ip: str = "") -> None:
    with get_db() as conn:
        _cur(conn).execute(
            "INSERT INTO audit_log (ts, username, action, details, ip) "
            "VALUES (%s,%s,%s,%s,%s)",
            (int(time.time()), username, action, details, ip)
        )


def get_audit(limit: int = 200) -> list:
    with get_db() as conn:
        cur = _cur(conn)
        cur.execute(
            "SELECT * FROM audit_log ORDER BY ts DESC LIMIT %s", (limit,)
        )
        return [dict(r) for r in cur.fetchall()]


def purge_audit(days: int = 90) -> None:
    cutoff = int(time.time()) - days * 86400
    with get_db() as conn:
        _cur(conn).execute("DELETE FROM audit_log WHERE ts < %s", (cutoff,))


# ─── Syslogs ──────────────────────────────────────────────────────────────────

def insert_syslog(ts: int, source_ip: str, facility: int, severity: int,
                  hostname: str, program: str, message: str) -> None:
    with get_db() as conn:
        _cur(conn).execute(
            "INSERT INTO syslogs (ts, received_at, source_ip, facility, severity, hostname, program, message) "
            "VALUES (%s,%s,%s,%s,%s,%s,%s,%s)",
            (ts, int(time.time()), source_ip, facility, severity, hostname, program, message)
        )


def get_syslogs(limit: int = 500, severity_max: int = 7,
                search: str = "", offset: int = 0) -> list:
    with get_db() as conn:
        cur = _cur(conn)
        params: list = [severity_max]
        where = "severity <= %s"
        if search:
            where += " AND message ILIKE %s"
            params.append(f"%{search}%")
        cur.execute(
            f"SELECT * FROM syslogs WHERE {where} "
            f"ORDER BY ts DESC LIMIT %s OFFSET %s",
            params + [limit, offset]
        )
        return [dict(r) for r in cur.fetchall()]


def count_syslogs(severity_max: int = 7, search: str = "") -> int:
    with get_db() as conn:
        cur = _cur(conn)
        params: list = [severity_max]
        where = "severity <= %s"
        if search:
            where += " AND message ILIKE %s"
            params.append(f"%{search}%")
        cur.execute(f"SELECT COUNT(*) AS n FROM syslogs WHERE {where}", params)
        r = cur.fetchone()
        return int(r["n"]) if r else 0


def purge_syslogs(days: int = 30) -> None:
    cutoff = int(time.time()) - days * 86400
    with get_db() as conn:
        _cur(conn).execute("DELETE FROM syslogs WHERE ts < %s", (cutoff,))


def get_syslog_daily_stats(hours: int = 24) -> dict:
    """
    Retourne des statistiques syslog sur les N dernières heures :
    total, erreurs, avertissements, WiFi connect/disconnect, top programmes.
    """
    result = {
        "total": 0, "errors": 0, "warnings": 0, "notices": 0,
        "wifi_connect": 0, "wifi_disconnect": 0, "top_programs": [],
    }
    cutoff = int(time.time()) - hours * 3600
    try:
        with get_db() as conn:
            # Curseur plain (index entier) — évite tout problème RealDictRow
            c = conn.cursor()

            # Une seule requête pour tout agréger
            c.execute(
                "SELECT "
                "COUNT(*), "
                "COALESCE(SUM(CASE WHEN severity <= 3 THEN 1 ELSE 0 END), 0), "
                "COALESCE(SUM(CASE WHEN severity  = 4 THEN 1 ELSE 0 END), 0), "
                "COALESCE(SUM(CASE WHEN severity <= 5 THEN 1 ELSE 0 END), 0), "
                "COALESCE(SUM(CASE WHEN message ILIKE '%%STATION_ONLINE%%'  THEN 1 ELSE 0 END), 0), "
                "COALESCE(SUM(CASE WHEN message ILIKE '%%STATION_OFFLINE%%' THEN 1 ELSE 0 END), 0) "
                "FROM syslogs WHERE received_at >= %s OR ts >= %s",
                (cutoff, cutoff),
            )
            row = c.fetchone()
            if row:
                result["total"]          = int(row[0] or 0)
                result["errors"]         = int(row[1] or 0)
                result["warnings"]       = int(row[2] or 0)
                result["notices"]        = int(row[3] or 0)
                result["wifi_connect"]   = int(row[4] or 0)
                result["wifi_disconnect"]= int(row[5] or 0)

            # Top 5 programmes
            c.execute(
                "SELECT program, COUNT(*) FROM syslogs "
                "WHERE (received_at >= %s OR ts >= %s) "
                "AND program IS NOT NULL AND program != '' "
                "GROUP BY program ORDER BY COUNT(*) DESC LIMIT 5",
                (cutoff, cutoff),
            )
            result["top_programs"] = [
                {"program": r[0], "count": int(r[1])}
                for r in c.fetchall()
            ]
    except Exception as e:
        log.error("get_syslog_daily_stats: %s", e, exc_info=True)
    return result


# ─── Bots Telegram ────────────────────────────────────────────────────────────

def get_telegram_bots(enabled_only: bool = False) -> list:
    with get_db() as conn:
        cur = _cur(conn)
        if enabled_only:
            cur.execute("SELECT * FROM telegram_bots WHERE enabled=true ORDER BY id")
        else:
            cur.execute("SELECT * FROM telegram_bots ORDER BY id")
        return [dict(r) for r in cur.fetchall()]


def create_telegram_bot(name: str, bot_token: str, chat_id: str,
                        on_info: bool = True, on_warning: bool = True,
                        on_error: bool = True) -> dict:
    with get_db() as conn:
        cur = _cur(conn)
        cur.execute(
            "INSERT INTO telegram_bots "
            "(name, bot_token, chat_id, enabled, on_info, on_warning, on_error, created_at) "
            "VALUES (%s,%s,%s,true,%s,%s,%s,%s) RETURNING *",
            (name, bot_token, chat_id, on_info, on_warning, on_error, int(time.time()))
        )
        return dict(cur.fetchone())


def update_telegram_bot(bot_id: int, **fields) -> dict | None:
    allowed = {"name", "bot_token", "chat_id", "enabled", "on_info", "on_warning", "on_error"}
    updates = {k: v for k, v in fields.items() if k in allowed}
    if not updates:
        return None
    set_clause = ", ".join(f"{k} = %s" for k in updates)
    with get_db() as conn:
        cur = _cur(conn)
        cur.execute(
            f"UPDATE telegram_bots SET {set_clause} WHERE id=%s RETURNING *",
            (*updates.values(), bot_id)
        )
        row = cur.fetchone()
    return dict(row) if row else None


def delete_telegram_bot(bot_id: int) -> None:
    with get_db() as conn:
        _cur(conn).execute("DELETE FROM telegram_bots WHERE id=%s", (bot_id,))


# ─── Cibles ping ──────────────────────────────────────────────────────────────

def get_ping_targets(router_id: int | None = None, enabled_only: bool = False) -> list:
    with get_db() as conn:
        cur = _cur(conn)
        conditions = []
        params = []
        if router_id:
            conditions.append("pt.router_id = %s")
            params.append(router_id)
        if enabled_only:
            conditions.append("pt.enabled = true")
        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
        cur.execute(
            f"SELECT pt.*, r.name AS router_name FROM ping_targets pt "
            f"LEFT JOIN routers r ON pt.router_id = r.id "
            f"{where} ORDER BY pt.id",
            params
        )
        return [dict(r) for r in cur.fetchall()]


def create_ping_target(label: str, host: str,
                       router_id: int | None = None) -> dict:
    with get_db() as conn:
        cur = _cur(conn)
        cur.execute(
            "INSERT INTO ping_targets (label, host, router_id, enabled, created_at) "
            "VALUES (%s,%s,%s,true,%s) RETURNING *",
            (label, host, router_id, int(time.time()))
        )
        return dict(cur.fetchone())


def update_ping_target(target_id: int, **fields) -> dict | None:
    allowed = {"label", "host", "router_id", "enabled"}
    updates = {k: v for k, v in fields.items() if k in allowed}
    if not updates:
        return None
    set_clause = ", ".join(f"{k} = %s" for k in updates)
    with get_db() as conn:
        cur = _cur(conn)
        cur.execute(
            f"UPDATE ping_targets SET {set_clause} WHERE id=%s RETURNING *",
            (*updates.values(), target_id)
        )
        row = cur.fetchone()
    return dict(row) if row else None


def delete_ping_target(target_id: int) -> None:
    with get_db() as conn:
        _cur(conn).execute("DELETE FROM ping_targets WHERE id=%s", (target_id,))


def insert_ping_result(target_id: int, rtt_ms: float | None, success: bool) -> None:
    with get_db() as conn:
        _cur(conn).execute(
            "INSERT INTO ping_results (target_id, ts, rtt_ms, success) "
            "VALUES (%s,%s,%s,%s)",
            (target_id, int(time.time()), rtt_ms, success)
        )


def get_ping_history(target_id: int, hours: int = 24) -> list:
    since = int(time.time()) - hours * 3600
    with get_db() as conn:
        cur = _cur(conn)
        cur.execute(
            "SELECT ts, rtt_ms, success FROM ping_results "
            "WHERE target_id=%s AND ts>=%s ORDER BY ts ASC",
            (target_id, since)
        )
        return [dict(r) for r in cur.fetchall()]


def get_sla_stats(target_id: int, hours: int = 24) -> dict:
    since = int(time.time()) - hours * 3600
    with get_db() as conn:
        cur = _cur(conn)
        cur.execute(
            "SELECT COUNT(*) AS total, "
            "SUM(CASE WHEN success THEN 1 ELSE 0 END) AS ok, "
            "AVG(CASE WHEN success THEN rtt_ms END) AS avg_rtt, "
            "MIN(CASE WHEN success THEN rtt_ms END) AS min_rtt, "
            "MAX(CASE WHEN success THEN rtt_ms END) AS max_rtt "
            "FROM ping_results WHERE target_id=%s AND ts>=%s",
            (target_id, since)
        )
        row = cur.fetchone()
    if not row or row["total"] == 0:
        return {"sla": None, "avg_rtt": None, "min_rtt": None, "max_rtt": None, "total": 0}
    total = row["total"]
    ok    = row["ok"] or 0
    return {
        "sla":     round(ok / total * 100, 2),
        "avg_rtt": round(float(row["avg_rtt"]), 2) if row["avg_rtt"] else None,
        "min_rtt": round(float(row["min_rtt"]), 2) if row["min_rtt"] else None,
        "max_rtt": round(float(row["max_rtt"]), 2) if row["max_rtt"] else None,
        "total":   total,
        "ok":      ok,
    }


def purge_ping_results(days: int = 30) -> None:
    cutoff = int(time.time()) - days * 86400
    with get_db() as conn:
        _cur(conn).execute("DELETE FROM ping_results WHERE ts < %s", (cutoff,))


# ─── Seuils par interface ─────────────────────────────────────────────────────

def get_interface_thresholds(router_id: int) -> list:
    with get_db() as conn:
        cur = _cur(conn)
        cur.execute(
            "SELECT * FROM interface_thresholds WHERE router_id=%s ORDER BY if_index",
            (router_id,)
        )
        return [dict(r) for r in cur.fetchall()]


def set_interface_threshold(router_id: int, if_index: int,
                             if_name: str, bw_warn_pct: int) -> dict:
    with get_db() as conn:
        cur = _cur(conn)
        cur.execute(
            "INSERT INTO interface_thresholds (router_id, if_index, if_name, bw_warn_pct) "
            "VALUES (%s,%s,%s,%s) "
            "ON CONFLICT (router_id, if_index) DO UPDATE "
            "SET if_name=%s, bw_warn_pct=%s RETURNING *",
            (router_id, if_index, if_name, bw_warn_pct, if_name, bw_warn_pct)
        )
        return dict(cur.fetchone())


def delete_interface_threshold(router_id: int, if_index: int) -> None:
    with get_db() as conn:
        _cur(conn).execute(
            "DELETE FROM interface_thresholds WHERE router_id=%s AND if_index=%s",
            (router_id, if_index)
        )


# ─── Alias d'interfaces ───────────────────────────────────────────────────────

def get_interface_aliases(router_id: int) -> dict:
    """Retourne {if_index: alias} pour un routeur."""
    with get_db() as conn:
        cur = _cur(conn)
        cur.execute(
            "SELECT if_index, alias FROM interface_aliases WHERE router_id=%s",
            (router_id,)
        )
        return {r["if_index"]: r["alias"] for r in cur.fetchall()}


def set_interface_alias(router_id: int, if_index: int, alias: str) -> None:
    with get_db() as conn:
        _cur(conn).execute(
            "INSERT INTO interface_aliases (router_id, if_index, alias) VALUES (%s,%s,%s) "
            "ON CONFLICT (router_id, if_index) DO UPDATE SET alias = EXCLUDED.alias",
            (router_id, if_index, alias.strip())
        )


def delete_interface_alias(router_id: int, if_index: int) -> None:
    with get_db() as conn:
        _cur(conn).execute(
            "DELETE FROM interface_aliases WHERE router_id=%s AND if_index=%s",
            (router_id, if_index)
        )


# ─── Acquittement en masse ────────────────────────────────────────────────────

def ack_all_events(router_id: int | None, username: str) -> int:
    """Acquitte tous les événements non-acquittés. Retourne le nombre de lignes mises à jour."""
    with get_db() as conn:
        cur = _cur(conn)
        now = int(time.time())
        if router_id:
            cur.execute(
                "UPDATE events SET acked=true, acked_by=%s, acked_at=%s "
                "WHERE acked=false AND router_id=%s",
                (username, now, router_id)
            )
        else:
            cur.execute(
                "UPDATE events SET acked=true, acked_by=%s, acked_at=%s "
                "WHERE acked=false",
                (username, now)
            )
        return cur.rowcount


# ─── ARP historique ───────────────────────────────────────────────────────────

def upsert_lte(router_id: int, data: dict) -> None:
    """Insère les métriques LTE (1 ligne par poll)."""
    now = int(time.time())
    with get_db() as conn:
        _cur(conn).execute("""
            INSERT INTO lte_metrics
                (router_id, ts, rssi, rsrp, rsrq, sinr, operator, access_mode, sim_status)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
        """, (
            router_id, now,
            data.get("rssi"), data.get("rsrp"), data.get("rsrq"), data.get("sinr"),
            data.get("operator"), data.get("access_mode"), data.get("sim_status"),
        ))


def get_lte_latest(router_id: int) -> dict | None:
    """Retourne la dernière mesure LTE pour un routeur."""
    with get_db() as conn:
        cur = _cur(conn)
        cur.execute("""
            SELECT * FROM lte_metrics
            WHERE router_id = %s
            ORDER BY ts DESC LIMIT 1
        """, (router_id,))
        row = cur.fetchone()
        return dict(row) if row else None


def get_lte_history(router_id: int, hours: int = 24) -> list:
    """Retourne l'historique RSSI/RSRP sur N heures."""
    since = int(time.time()) - hours * 3600
    with get_db() as conn:
        cur = _cur(conn)
        cur.execute("""
            SELECT ts, rssi, rsrp, rsrq, sinr, operator, access_mode
            FROM lte_metrics
            WHERE router_id = %s AND ts >= %s
            ORDER BY ts ASC
        """, (router_id, since))
        return [dict(r) for r in cur.fetchall()]


def upsert_wifi_radio(router_id: int, radios: list) -> None:
    """Insère les métriques radio WiFi (canal, puissance)."""
    if not radios:
        return
    now = int(time.time())
    with get_db() as conn:
        for r in radios:
            _cur(conn).execute("""
                INSERT INTO wifi_radio (router_id, ts, radio_index, channel, tx_power_dbm, mode)
                VALUES (%s,%s,%s,%s,%s,%s)
            """, (
                router_id, now,
                r.get("radio_index"), r.get("channel"),
                r.get("tx_power_dbm"), r.get("mode"),
            ))


def get_wifi_radio_latest(router_id: int) -> list:
    """Retourne les dernières infos radio (1 ligne par radio index)."""
    with get_db() as conn:
        cur = _cur(conn)
        cur.execute("""
            SELECT DISTINCT ON (radio_index)
                radio_index, channel, tx_power_dbm, mode, ts
            FROM wifi_radio
            WHERE router_id = %s
            ORDER BY radio_index, ts DESC
        """, (router_id,))
        return [dict(r) for r in cur.fetchall()]


def upsert_arp(router_id: int, entries: list) -> None:
    """Insère ou met à jour l'historique ARP (first_seen conservé, ip + last_seen mis à jour)."""
    if not entries:
        return
    now = int(time.time())
    with get_db() as conn:
        for e in entries:
            mac = (e.get("mac") or "").upper().strip()
            ip  = e.get("ip") or ""
            if not mac or not ip:
                continue
            _cur(conn).execute(
                "INSERT INTO arp_history (router_id, mac, ip, first_seen, last_seen) "
                "VALUES (%s,%s,%s,%s,%s) "
                "ON CONFLICT (router_id, mac) "
                "DO UPDATE SET ip=EXCLUDED.ip, last_seen=EXCLUDED.last_seen",
                (router_id, mac, ip, now, now)
            )


def get_arp_history(router_id: int, limit: int = 500) -> list:
    with get_db() as conn:
        cur = _cur(conn)
        cur.execute(
            "SELECT * FROM arp_history WHERE router_id=%s "
            "ORDER BY last_seen DESC LIMIT %s",
            (router_id, limit)
        )
        return [dict(r) for r in cur.fetchall()]


# ─── Rôles utilisateurs / permissions routeur ─────────────────────────────────

def get_user_router_perms(user_id: int) -> list:
    """Retourne la liste des (router_id, can_write) pour cet utilisateur.
    Si vide → accès à tous les routeurs (comportement par défaut)."""
    with get_db() as conn:
        cur = _cur(conn)
        cur.execute(
            "SELECT router_id, can_write FROM user_router_perms WHERE user_id=%s",
            (user_id,)
        )
        return [dict(r) for r in cur.fetchall()]


def set_user_router_perm(user_id: int, router_id: int, can_write: bool) -> None:
    with get_db() as conn:
        _cur(conn).execute(
            "INSERT INTO user_router_perms (user_id, router_id, can_write) VALUES (%s,%s,%s) "
            "ON CONFLICT (user_id, router_id) DO UPDATE SET can_write=EXCLUDED.can_write",
            (user_id, router_id, can_write)
        )


def delete_user_router_perm(user_id: int, router_id: int) -> None:
    with get_db() as conn:
        _cur(conn).execute(
            "DELETE FROM user_router_perms WHERE user_id=%s AND router_id=%s",
            (user_id, router_id)
        )


def get_all_user_perms() -> dict:
    """Retourne un dict {user_id: [{router_id, can_write}]} pour l'admin."""
    with get_db() as conn:
        cur = _cur(conn)
        cur.execute("SELECT * FROM user_router_perms ORDER BY user_id, router_id")
        result: dict = {}
        for r in cur.fetchall():
            result.setdefault(r["user_id"], []).append(
                {"router_id": r["router_id"], "can_write": r["can_write"]}
            )
        return result


# ─── Fenêtres de maintenance ──────────────────────────────────────────────────

def is_in_maintenance(router_id: int | None) -> bool:
    """Retourne True si le routeur (ou global si router_id=None) est en maintenance."""
    now = int(time.time())
    with get_db() as conn:
        cur = _cur(conn)
        cur.execute(
            "SELECT 1 FROM maintenance_windows "
            "WHERE (router_id=%s OR router_id IS NULL) "
            "AND start_ts <= %s AND end_ts >= %s LIMIT 1",
            (router_id, now, now)
        )
        return cur.fetchone() is not None


def get_maintenance_windows(router_id: int | None = None) -> list:
    with get_db() as conn:
        cur = _cur(conn)
        if router_id:
            cur.execute(
                "SELECT * FROM maintenance_windows "
                "WHERE router_id=%s OR router_id IS NULL ORDER BY start_ts DESC",
                (router_id,)
            )
        else:
            cur.execute("SELECT * FROM maintenance_windows ORDER BY start_ts DESC")
        return [dict(r) for r in cur.fetchall()]


def create_maintenance_window(router_id: int | None, start_ts: int, end_ts: int,
                               description: str = "", created_by: str = "") -> dict:
    with get_db() as conn:
        cur = _cur(conn)
        cur.execute(
            "INSERT INTO maintenance_windows (router_id, start_ts, end_ts, description, created_at, created_by) "
            "VALUES (%s,%s,%s,%s,%s,%s) RETURNING *",
            (router_id, start_ts, end_ts, description, int(time.time()), created_by)
        )
        return dict(cur.fetchone())


def delete_maintenance_window(window_id: int) -> None:
    with get_db() as conn:
        _cur(conn).execute("DELETE FROM maintenance_windows WHERE id=%s", (window_id,))


# ─── Historique clients WiFi ──────────────────────────────────────────────────

def insert_wifi_client_history(router_id: int, clients: list) -> None:
    if not clients:
        return
    ts = int(time.time())
    with get_db() as conn:
        psycopg2.extras.execute_batch(
            _cur(conn),
            "INSERT INTO wifi_client_history (router_id, ts, mac, ssid, rssi, band) "
            "VALUES (%s,%s,%s,%s,%s,%s)",
            [(router_id, ts, c.get("mac"), c.get("ssid"), c.get("rssi"), c.get("band"))
             for c in clients]
        )


def get_wifi_client_history(router_id: int, hours: int = 24) -> list:
    since = int(time.time()) - hours * 3600
    with get_db() as conn:
        cur = _cur(conn)
        cur.execute(
            "SELECT * FROM wifi_client_history WHERE router_id=%s AND ts>=%s ORDER BY ts DESC",
            (router_id, since)
        )
        return [dict(r) for r in cur.fetchall()]


# ─── Totaux bande passante ────────────────────────────────────────────────────

def accumulate_bandwidth(router_id: int, if_index: int, if_name: str,
                         in_bytes_delta: int, out_bytes_delta: int) -> None:
    """Ajoute les octets delta aux totaux du jour et du mois courants."""
    now   = int(time.time())
    day   = time.strftime("%Y-%m-%d", time.gmtime(now))
    month = time.strftime("%Y-%m",    time.gmtime(now))
    with get_db() as conn:
        for ptype, pkey in [("daily", day), ("monthly", month)]:
            _cur(conn).execute(
                "INSERT INTO bandwidth_totals "
                "(router_id, if_index, if_name, period_type, period_key, in_bytes, out_bytes, updated_at) "
                "VALUES (%s,%s,%s,%s,%s,%s,%s,%s) "
                "ON CONFLICT (router_id, if_index, period_type, period_key) DO UPDATE "
                "SET in_bytes=bandwidth_totals.in_bytes+EXCLUDED.in_bytes, "
                "    out_bytes=bandwidth_totals.out_bytes+EXCLUDED.out_bytes, "
                "    updated_at=EXCLUDED.updated_at",
                (router_id, if_index, if_name, ptype, pkey,
                 in_bytes_delta, out_bytes_delta, now)
            )


def get_bandwidth_totals(router_id: int, period_type: str = "daily",
                         limit: int = 30) -> list:
    with get_db() as conn:
        cur = _cur(conn)
        cur.execute(
            "SELECT if_index, if_name, period_key, in_bytes, out_bytes "
            "FROM bandwidth_totals "
            "WHERE router_id=%s AND period_type=%s "
            "ORDER BY period_key DESC, if_index "
            "LIMIT %s",
            (router_id, period_type, limit)
        )
        return [dict(r) for r in cur.fetchall()]


# ─── SLA WAN ──────────────────────────────────────────────────────────────────

def insert_wan_sla(router_id: int, if_index: int, if_name: str, was_up: bool) -> None:
    with get_db() as conn:
        _cur(conn).execute(
            "INSERT INTO wan_sla (router_id, if_index, if_name, ts, was_up) "
            "VALUES (%s,%s,%s,%s,%s)",
            (router_id, if_index, if_name, int(time.time()), was_up)
        )


def get_wan_sla_stats(router_id: int, if_index: int, hours: int = 24) -> dict:
    since = int(time.time()) - hours * 3600
    with get_db() as conn:
        cur = _cur(conn)
        cur.execute(
            "SELECT COUNT(*) AS total, SUM(CASE WHEN was_up THEN 1 ELSE 0 END) AS up_count "
            "FROM wan_sla WHERE router_id=%s AND if_index=%s AND ts>=%s",
            (router_id, if_index, since)
        )
        row = cur.fetchone()
    if not row or row["total"] == 0:
        return {"sla": None, "total": 0, "up": 0}
    total = row["total"]
    up    = row["up_count"] or 0
    return {"sla": round(up / total * 100, 2), "total": total, "up": up}


def get_wan_sla_list(router_id: int, hours: int = 24) -> list:
    """Retourne la liste des interfaces WAN avec leurs stats SLA."""
    since = int(time.time()) - hours * 3600
    with get_db() as conn:
        cur = _cur(conn)
        cur.execute(
            "SELECT if_index, if_name, "
            "COUNT(*) AS total, "
            "SUM(CASE WHEN was_up THEN 1 ELSE 0 END) AS up_count "
            "FROM wan_sla WHERE router_id=%s AND ts>=%s "
            "GROUP BY if_index, if_name ORDER BY if_index",
            (router_id, since)
        )
        rows = cur.fetchall()
    result = []
    for r in rows:
        total = r["total"] or 0
        up    = r["up_count"] or 0
        result.append({
            "if_index": r["if_index"],
            "if_name":  r["if_name"],
            "total":    total,
            "up":       up,
            "sla":      round(up / total * 100, 2) if total > 0 else None,
        })
    return result


# ─── OIDs personnalisés ────────────────────────────────────────────────────────

def get_custom_oid_polls(router_id: int, enabled_only: bool = False) -> list:
    with get_db() as conn:
        cur = _cur(conn)
        if enabled_only:
            cur.execute(
                "SELECT * FROM custom_oid_polls WHERE router_id=%s AND enabled=true ORDER BY id",
                (router_id,)
            )
        else:
            cur.execute(
                "SELECT * FROM custom_oid_polls WHERE router_id=%s ORDER BY id",
                (router_id,)
            )
        return [dict(r) for r in cur.fetchall()]


def create_custom_oid_poll(router_id: int, oid: str, label: str,
                            unit: str = "") -> dict:
    with get_db() as conn:
        cur = _cur(conn)
        cur.execute(
            "INSERT INTO custom_oid_polls (router_id, oid, label, unit, enabled, created_at) "
            "VALUES (%s,%s,%s,%s,true,%s) RETURNING *",
            (router_id, oid.strip(), label.strip(), unit.strip(), int(time.time()))
        )
        return dict(cur.fetchone())


def update_custom_oid_poll(poll_id: int, **fields) -> dict | None:
    allowed = {"oid", "label", "unit", "enabled"}
    updates = {k: v for k, v in fields.items() if k in allowed}
    if not updates:
        return None
    set_clause = ", ".join(f"{k} = %s" for k in updates)
    with get_db() as conn:
        cur = _cur(conn)
        cur.execute(
            f"UPDATE custom_oid_polls SET {set_clause} WHERE id=%s RETURNING *",
            (*updates.values(), poll_id)
        )
        row = cur.fetchone()
    return dict(row) if row else None


def delete_custom_oid_poll(poll_id: int) -> None:
    with get_db() as conn:
        _cur(conn).execute("DELETE FROM custom_oid_polls WHERE id=%s", (poll_id,))


def insert_custom_oid_value(poll_id: int, value_text: str,
                             value_num: float | None = None) -> None:
    with get_db() as conn:
        _cur(conn).execute(
            "INSERT INTO custom_oid_values (poll_id, ts, value_text, value_num) "
            "VALUES (%s,%s,%s,%s)",
            (poll_id, int(time.time()), value_text, value_num)
        )


def get_custom_oid_values(poll_id: int, hours: int = 24) -> list:
    since = int(time.time()) - hours * 3600
    with get_db() as conn:
        cur = _cur(conn)
        cur.execute(
            "SELECT ts, value_text, value_num FROM custom_oid_values "
            "WHERE poll_id=%s AND ts>=%s ORDER BY ts ASC",
            (poll_id, since)
        )
        return [dict(r) for r in cur.fetchall()]


def purge_custom_oid_values(days: int = 30) -> None:
    cutoff = int(time.time()) - days * 86400
    with get_db() as conn:
        _cur(conn).execute("DELETE FROM custom_oid_values WHERE ts<%s", (cutoff,))


# ─── Nouveau MAC (détection) ──────────────────────────────────────────────────

def get_unalerted_new_macs(router_id: int) -> list:
    """Retourne les MACs récents non encore signalés (is_known=false, alerted=false)."""
    with get_db() as conn:
        cur = _cur(conn)
        cur.execute(
            "SELECT mac, ip, first_seen FROM arp_history "
            "WHERE router_id=%s AND is_known=false AND alerted=false "
            "ORDER BY first_seen DESC",
            (router_id,)
        )
        return [dict(r) for r in cur.fetchall()]


def mark_mac_alerted(router_id: int, mac: str) -> None:
    with get_db() as conn:
        _cur(conn).execute(
            "UPDATE arp_history SET alerted=true WHERE router_id=%s AND mac=%s",
            (router_id, mac.upper())
        )


def mark_mac_known(router_id: int, mac: str) -> None:
    """Marque un MAC comme connu (plus d'alertes future)."""
    with get_db() as conn:
        _cur(conn).execute(
            "UPDATE arp_history SET is_known=true, alerted=true "
            "WHERE router_id=%s AND mac=%s",
            (router_id, mac.upper())
        )


# ─── Persistance des états d'alerte ──────────────────────────────────────────

def get_all_alert_states() -> dict:
    """Charge tous les états d'alerte depuis la DB. Retourne {key: value}."""
    with get_db() as conn:
        cur = _cur(conn)
        cur.execute("SELECT key, value FROM alert_state")
        return {r["key"]: r["value"] for r in cur.fetchall()}


def set_alert_state(key: str, value: str) -> None:
    """Persiste un état d'alerte (upsert)."""
    with get_db() as conn:
        _cur(conn).execute(
            "INSERT INTO alert_state (key, value, updated_at) VALUES (%s,%s,%s) "
            "ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value, updated_at=EXCLUDED.updated_at",
            (key, value, int(time.time()))
        )
