import json
from datetime import datetime, timedelta


class CorrelationEngine:
    """
    يربط التنبيهات ببعضها ليكشف سلاسل الهجمات الكاملة.
    يبني Attack Timeline ويربطها بـ MITRE ATT&CK.
    """

    # ─── أنماط الهجوم المعروفة ───────────────────────────
    ATTACK_PATTERNS = {

        "ssh_brute_force_to_compromise": {
            "description": "SSH Brute Force leading to successful compromise",
            "severity":    "CRITICAL",
            "stages": [
                {
                    "label":    "Credential Brute Force",
                    "rule_ids": [5760, 5763, 5764],
                    "mitre":    "T1110.001",
                    "min_count": 3,
                },
                {
                    "label":    "Successful Authentication",
                    "rule_ids": [5501, 5502, 5715],
                    "mitre":    "T1078",
                    "min_count": 1,
                },
            ],
            "max_window_minutes":  10,
            "require_same_source": True,
        },

        "lateral_movement": {
            "description": "Attacker pivoting from one host to another",
            "severity":    "CRITICAL",
            "stages": [
                {
                    "label":    "Initial Brute Force",
                    "rule_ids": [5760, 5763],
                    "mitre":    "T1110",
                    "min_count": 1,
                },
                {
                    "label":    "Successful Login — First Host",
                    "rule_ids": [5501, 5502],
                    "mitre":    "T1078",
                    "min_count": 1,
                },
                {
                    "label":    "Brute Force on New Target",
                    "rule_ids": [5760, 5763],
                    "mitre":    "T1110",
                    "min_count": 1,
                },
            ],
            "max_window_minutes":  30,
            "require_same_source": True,
            "require_different_targets": True,
        },

        "recon_to_exploitation": {
            "description": "Port scan followed by targeted attack",
            "severity":    "HIGH",
            "stages": [
                {
                    "label":    "Port Scan / Reconnaissance",
                    "rule_ids": [40101, 40102, 40103],
                    "mitre":    "T1046",
                    "min_count": 1,
                },
                {
                    "label":    "Targeted Exploitation Attempt",
                    "rule_ids": [5760, 31151, 31152],
                    "mitre":    "T1190",
                    "min_count": 1,
                },
            ],
            "max_window_minutes":  60,
            "require_same_source": True,
        },

        "privilege_escalation_chain": {
            "description": "Failed then successful privilege escalation",
            "severity":    "HIGH",
            "stages": [
                {
                    "label":    "Failed Privilege Escalation",
                    "rule_ids": [5400, 5401],
                    "mitre":    "T1548.003",
                    "min_count": 1,
                },
                {
                    "label":    "Successful Privilege Escalation",
                    "rule_ids": [5402],
                    "mitre":    "T1548",
                    "min_count": 1,
                },
            ],
            "max_window_minutes":  5,
            "require_same_source": True,
        },

        "web_attack_chain": {
            "description": "Web application attack sequence",
            "severity":    "HIGH",
            "stages": [
                {
                    "label":    "Web Scan / Enumeration",
                    "rule_ids": [31100, 31101, 31103],
                    "mitre":    "T1595",
                    "min_count": 1,
                },
                {
                    "label":    "Web Application Attack",
                    "rule_ids": [31151, 31152, 31153],
                    "mitre":    "T1190",
                    "min_count": 1,
                },
            ],"max_window_minutes":  30,
            "require_same_source": True,
        },
    }

    def __init__(self, db_manager):
        self.db = db_manager

    # ── الدخول الرئيسي ──────────────────────────────────
    def analyze(self, alert: dict,
                window_minutes: int = 30) -> dict:

        source_ip    = alert.get("source_ip",   "0.0.0.0")
        target_host  = alert.get("target_host", "unknown")
        timestamp    = alert.get("timestamp",
                                 datetime.utcnow().isoformat())

        # جلب التنبيهات المرتبطة في النافذة الزمنية
        related = self._fetch_related(source_ip, target_host,
                                      timestamp, window_minutes)

        detected_chains = []
        for name, pattern in self.ATTACK_PATTERNS.items():
            chain = self._match_pattern(related, pattern)
            if chain:
                detected_chains.append({
                    "name":           name,
                    "description":    pattern["description"],
                    "severity":       pattern["severity"],
                    "stages":         chain["stages"],
                    "first_seen":     chain["first_seen"],
                    "last_seen":      chain["last_seen"],
                    "affected_hosts": chain["affected_hosts"],
                    "mitre_techniques": chain["mitre_techniques"],
                    "timeline":       self._build_timeline(chain["stages"]),
                })

        return {
            "has_attack_chain":     len(detected_chains) > 0,
            "chains":               detected_chains,
            "chains_count":         len(detected_chains),
            "related_alerts_count": len(related),
            "is_isolated_incident": len(detected_chains) == 0,
            "risk_amplification":   self._calc_risk_amp(detected_chains),
        }

    # ── جلب التنبيهات المرتبطة ──────────────────────────
    def _fetch_related(self, source_ip: str, target_host: str,
                        timestamp: str, window: int) -> list:
        try:
            dt = datetime.fromisoformat(
                timestamp.replace("Z", "")
            )
        except Exception:
            dt = datetime.utcnow()

        start = (dt - timedelta(minutes=window)).isoformat()
        end   = (dt + timedelta(minutes=5)).isoformat()

        rows = self.db.query("""
            SELECT id, rule_id, rule_description,
                   severity_level, source_ip,
                   target_host, target_user,
                   timestamp, mitre_technique
            FROM alerts
            WHERE (source_ip = ? OR target_host = ?)
              AND timestamp BETWEEN ? AND ?
            ORDER BY timestamp ASC
        """, [source_ip, target_host, start, end])

        return [dict(r) for r in rows]

    # ── مطابقة نمط هجوم ─────────────────────────────────
    def _match_pattern(self, alerts: list,
                        pattern: dict) -> dict | None:

        stages_def  = pattern["stages"]
        max_window  = pattern["max_window_minutes"]
        same_source = pattern.get("require_same_source", True)
        diff_target = pattern.get("require_different_targets", False)

        found_stages    = []
        mitre_techniques = []
        affected_hosts   = set()

        for stage_def in stages_def:
            # ابحث عن تنبيه يطابق هذه المرحلة
            matched = [
                a for a in alerts
                if a["rule_id"] in stage_def["rule_ids"]
            ]

            if len(matched) < stage_def["min_count"]:
                return None     # المرحلة ناقصة → النمط لا ينطبق

            # خذ أول تطابق لكل مرحلة
            best = matched[0]
            found_stages.append({
                "label":       stage_def["label"],
                "mitre":       stage_def["mitre"],
                "alert_id":    best["id"],
                "rule_id":     best["rule_id"],
                "timestamp":   best["timestamp"],
                "source_ip":   best["source_ip"],
                "target_host": best["target_host"],
            })
            mitre_techniques.append(stage_def["mitre"])
            affected_hosts.add(best["target_host"])

        if len(found_stages) < len(stages_def):
            return None

        # تحقق من الفارق الزمني بين أول وآخر مرحلة
        try:
            t_first = datetime.fromisoformat(
                found_stages[0]["timestamp"].replace("Z", "")
            )
            t_last  = datetime.fromisoformat(
                found_stages[-1]["timestamp"].replace("Z", "")
            )
            delta   = (t_last - t_first).total_seconds() / 60
            if delta > max_window:
                return None
        except Exception:
            pass

        # تحقق من اختلاف الأهداف (Lateral Movement)
        if diff_target and len(affected_hosts) < 2:
            return None

        return {
            "stages":          found_stages,
            "first_seen":      found_stages[0]["timestamp"],
            "last_seen":       found_stages[-1]["timestamp"],
            "affected_hosts":  list(affected_hosts),
            "mitre_techniques": list(set(mitre_techniques)),
        }

    # ── بناء الـ Timeline ────────────────────────────────
    def _build_timeline(self, stages: list) -> str:
        if not stages:
            return "No timeline available"

        try:
            t0    = datetime.fromisoformat(
                stages[0]["timestamp"].replace("Z", "")
            )
            lines = ["ATTACK TIMELINE:"]
            for stage in stages:
                ts     = datetime.fromisoformat(
                    stage["timestamp"].replace("Z", "")
                )
                offset = int((ts - t0).total_seconds() / 60)
                lines.append(
                    f"  T+{offset:02d}min  [{stage['mitre']}]  "
                    f"{stage['label']}  "
                    f"({stage['source_ip']} → {stage['target_host']})"
                )
            return "\n".join(lines)
        except Exception as e:
            return f"Timeline error: {e}"

    # ── معامل تضخيم الخطر ───────────────────────────────
    def _calc_risk_amp(self, chains: list) -> float:
        if not chains:
            return 1.0
        weights = {"CRITICAL": 3.0, "HIGH": 2.0,
                   "MEDIUM": 1.5, "LOW": 1.2}
        amp = 1.0
        for chain in chains:
            amp *= weights.get(chain["severity"], 1.0)
        return round(min(amp, 10.0), 2)