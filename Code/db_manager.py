import sqlite3
from datetime import datetime


class DBManager:

    def __init__(self, db_path: str):
        self.db_path = db_path
        self._init_schema()

    # ── اتصال ──────────────────────────────────────────────
    def _connect(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    # ── إنشاء الجداول ──────────────────────────────────────
    def _init_schema(self):
        with self._connect() as conn:
            conn.executescript("""
            -- ── التنبيهات ──
            CREATE TABLE IF NOT EXISTS alerts (
                id              TEXT PRIMARY KEY,
                wazuh_id        TEXT,
                timestamp       TEXT NOT NULL,
                rule_id         INTEGER,
                rule_description TEXT,
                severity_level  INTEGER,
                severity_label  TEXT,
                source_ip       TEXT,
                target_host     TEXT,
                target_host_ip  TEXT,
                target_user     TEXT,
                agent_id        TEXT,
                mitre_technique TEXT,
                mitre_tactic    TEXT,
                raw_json        TEXT,
                status          TEXT DEFAULT 'NEW',
                resolution      TEXT,
                resolved_at     TEXT,
                processed_at    TEXT
            );

            -- ── قرارات الـ Triage ──
            CREATE TABLE IF NOT EXISTS triage_decisions (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id        TEXT NOT NULL,
                fp_probability  REAL,
                fp_verdict      TEXT,
                fp_confidence   REAL,
                fp_reasons      TEXT,
                priority_level  TEXT,
                priority_score  INTEGER,
                priority_breakdown TEXT,
                escalation_decision TEXT,
                escalation_urgency  TEXT,
                escalation_reasons  TEXT,
                timestamp       TEXT,
                FOREIGN KEY (alert_id) REFERENCES alerts(id)
            );

            -- ── سجل التحقيق (كل Thought/Action/Obs) ──
            CREATE TABLE IF NOT EXISTS investigation_logs (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id    TEXT NOT NULL,
                step        TEXT,
                note        TEXT,
                timestamp   TEXT,
                FOREIGN KEY (alert_id) REFERENCES alerts(id)
            );

            -- ── الإجراءات المتخذة ──
            CREATE TABLE IF NOT EXISTS actions_taken (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id         TEXT NOT NULL,
                action_type      TEXT,
                target           TEXT,
                reason           TEXT,
                duration_seconds INTEGER DEFAULT 0,
                success          INTEGER DEFAULT 0,
                timestamp        TEXT,
                FOREIGN KEY (alert_id) REFERENCES alerts(id)
            );

            -- ── تقارير الحوادث ──
            CREATE TABLE IF NOT EXISTS incident_reports (
                id           TEXT PRIMARY KEY,
                alert_id     TEXT NOT NULL,
                content      TEXT,
                severity     TEXT,
                status       TEXT,
                created_at   TEXT,
                FOREIGN KEY (alert_id) REFERENCES alerts(id)
            );

            -- ── الـ Escalations ──
            CREATE TABLE IF NOT EXISTS escalations (
                ticket_id   TEXT PRIMARY KEY,
                alert_id    TEXT NOT NULL,
                priority    TEXT,
                reason      TEXT,
                summary     TEXT,
                timestamp   TEXT,
                status      TEXT DEFAULT 'OPEN',
                FOREIGN KEY (alert_id) REFERENCES alerts(id)
            );

            -- ── سلاسل الهجوم ──
            CREATE TABLE IF NOT EXISTS correlation_chains (id              INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id        TEXT NOT NULL,
                chain_name      TEXT,
                chain_description TEXT,
                stages_json     TEXT,
                severity        TEXT,
                first_seen      TEXT,
                last_seen       TEXT,
                affected_hosts  TEXT,
                mitre_techniques TEXT,
                FOREIGN KEY (alert_id) REFERENCES alerts(id)
            );

            -- ── مخزون الأصول ──
            CREATE TABLE IF NOT EXISTS asset_inventory (
                id                    INTEGER PRIMARY KEY AUTOINCREMENT,
                hostname              TEXT,
                ip                    TEXT UNIQUE,
                criticality           TEXT DEFAULT 'MEDIUM',
                owner                 TEXT,
                services              TEXT,
                is_domain_controller  INTEGER DEFAULT 0,
                os                    TEXT,
                department            TEXT
            );

            -- ── سمعة الـ IPs ──
            CREATE TABLE IF NOT EXISTS ip_reputation (
                ip              TEXT PRIMARY KEY,
                vt_malicious    INTEGER DEFAULT 0,
                vt_suspicious   INTEGER DEFAULT 0,
                abuse_score     INTEGER DEFAULT 0,
                abuse_reports   INTEGER DEFAULT 0,
                is_tor          INTEGER DEFAULT 0,
                is_vpn          INTEGER DEFAULT 0,
                country         TEXT,
                last_updated    TEXT
            );

            -- ── القائمة البيضاء ──
            CREATE TABLE IF NOT EXISTS ip_whitelist (
                ip          TEXT PRIMARY KEY,
                reason      TEXT,
                added_by    TEXT,
                added_at    TEXT
            );

            -- ── قائمة المراقبة ──
            CREATE TABLE IF NOT EXISTS watchlist (
                ip          TEXT PRIMARY KEY,
                reason      TEXT,
                alert_id    TEXT,
                added_at    TEXT,
                active      INTEGER DEFAULT 1
            );

            -- ── Indexes للأداء ──
            CREATE INDEX IF NOT EXISTS idx_alerts_source_ip
                ON alerts(source_ip);
            CREATE INDEX IF NOT EXISTS idx_alerts_timestamp
                ON alerts(timestamp);
            CREATE INDEX IF NOT EXISTS idx_alerts_status
                ON alerts(status);
            """)

        self._seed_demo_data()

    # ── بيانات تجريبية ──────────────────────────────────────
    def _seed_demo_data(self):
        with self._connect() as conn:
            # أصول الشبكة التجريبية
            conn.execute("""
                INSERT OR IGNORE INTO asset_inventory
                    (hostname, ip, criticality, owner, services,
                     is_domain_controller, os, department)
                VALUES
                    ('ubuntu-server', '192.168.56.103',
                     'HIGH', 'IT Team',
                     'SSH,HTTP,Wazuh', 0,
                     'Ubuntu 22.04', 'IT'),
                    ('windows-vm', '192.168.56.104',
                     'MEDIUM', 'IT Team',
                     'RDP,SMB,Wazuh', 0,
                     'Windows 10', 'IT'),
                    ('kali-attacker', '192.168.56.105',
                     'LOW', 'Security Lab',
                     'N/A', 0,
                     'Kali Linux', 'Security')
            """)
            # القائمة البيضاء
            conn.execute("""
                INSERT OR IGNORE INTO ip_whitelist
                    (ip, reason, added_by, added_at)
                VALUES
                    ('192.168.56.1', 'Host machine / Gateway',
                     'admin', datetime('now'))
            """)

    # ── عمليات CRUD ────────────────────────────────────────
    def execute(self, sql: str, params: list = None):
        with self._connect() as conn:
            conn.execute(sql, params or [])
            conn.commit()

    def query(self, sql: str, params: list = None):
        with self._connect() as conn:
            cur = conn.execute(sql, params or [])
            return cur.fetchall()

    def insert_alert(self, alert_data: dict) -> str:
        self.execute("""
            INSERT OR IGNORE INTO alerts
                (id, wazuh_id, timestamp, rule_id, rule_description,
                 severity_level, severity_label, source_ip,
                 target_host, target_host_ip, target_user,
                 agent_id, mitre_technique, mitre_tactic,
                 raw_json, status)
            VALUES
                (:id, :wazuh_id, :timestamp, :rule_id, :rule_description,
                 :severity_level, :severity_label, :source_ip,
                 :target_host, :target_host_ip, :target_user,
                 :agent_id, :mitre_technique, :mitre_tactic,
                 :raw_json, 'NEW')
        """, [alert_data.get(k) for k in [
            "id", "wazuh_id", "timestamp", "rule_id",
            "rule_description", "severity_level", "severity_label",
            "source_ip", "target_host", "target_host_ip",
            "target_user", "agent_id", "mitre_technique",
            "mitre_tactic", "raw_json"
        ]])
        return alert_data["id"]