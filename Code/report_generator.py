import json
import threading
from datetime import datetime


class ReportGenerator:
    """
    يولّد تقارير احترافية كاملة —
    ما يكتبه Analyst 1 يدوياً في 30 دقيقة.
    """

    def __init__(self, db_manager):
        self.db = db_manager
        self.lock = threading.Lock()  # ensures unique report IDs

    # ── الدخول الرئيسي ──────────────────────────────────
    def generate(self,
                 alert:       dict,
                 context:     dict,
                 triage:      dict,
                 correlation: dict,
                 agent_output:str,
                 agent_steps: list) -> dict:

        report_id = self._next_report_id()

        fp  = triage.get("fp_assessment", {})
        pri = triage.get("priority",      {})
        esc = triage.get("escalation",    {})

        status = ("ESCALATED"
                  if esc.get("decision") == "ESCALATE"
                  else "CLOSED")

        content = self._build_report(
            report_id, alert, context,
            fp, pri, esc, correlation,
            agent_output, agent_steps
        )

        # حفظ في قاعدة البيانات
        self.db.execute("""
            INSERT OR REPLACE INTO incident_reports
                (id, alert_id, content, severity, status, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """, [
            report_id,
            alert["id"],
            content,
            pri.get("level", "UNKNOWN"),
            status,
            datetime.utcnow().isoformat()
        ])

        return {
            "id":       report_id,
            "alert_id": alert["id"],
            "severity": pri.get("level", "UNKNOWN"),
            "status":   status,
            "content":  content,
        }

    # ── بناء محتوى التقرير ──────────────────────────────
    def _build_report(self,
                       report_id:    str,
                       alert:        dict,
                       context:      dict,
                       fp:           dict,
                       priority:     dict,
                       escalation:   dict,
                       correlation:  dict,
                       agent_output: str,
                       agent_steps:  list) -> str:

        sep   = "─" * 58
        now   = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        level = priority.get("level", "UNKNOWN")

        header = f"""
╔══════════════════════════════════════════════════════════╗
║           INCIDENT REPORT — {report_id:<26}║
╚══════════════════════════════════════════════════════════╝
  CLASSIFICATION : {level}
  STATUS         : {"ESCALATED TO ANALYST 2" if escalation.get("decision") == "ESCALATE" else "HANDLED — CLOSED"}
  GENERATED      : {now}
  ANALYST        : Autonomous SOC Agent v2.0 (Ollama)
""".strip()

        technical = f"""
{sep}
 TECHNICAL DETAILS
{sep}
  Alert ID       : {alert.get('id', 'N/A')}
  Timestamp      : {alert.get('timestamp', 'N/A')}
  Wazuh Rule     : [{alert.get('rule_id', '?')}] {alert.get('rule_description', 'N/A')}
  Severity       : {alert.get('severity_label', 'N/A')} (level {alert.get('severity_level', 0)})
  Source IP      : {alert.get('source_ip', 'N/A')}
  Target Host    : {alert.get('target_host', 'N/A')} ({alert.get('target_host_ip', 'N/A')})
  Target User    : {alert.get('target_user', 'N/A')}
  MITRE          : {alert.get('mitre_technique', 'N/A')} — {alert.get('mitre_tactic', 'N/A')}
  NIST Control   : {self._get_nist_control(alert.get('rule_id', 0))}
""".strip()

        fp_reasons_text = "\n".join(
            f"    • {r}" for r in fp.get("reasons", [])
        ) or "    • No specific indicators"

        triage_section = f"""
{sep}
 TRIAGE ASSESSMENT
{sep}
  FP Verdict     : {fp.get('verdict', 'N/A')}
  FP Probability : {fp.get('fp_probability', 0):.0%}
  Confidence     : {fp.get('confidence', 0):.0%}
  Priority Level : {priority.get('level', 'N/A')} (Score: {priority.get('score', 0)})

  Evidence & Indicators:
{fp_reasons_text}

  Priority Breakdown:
    {priority.get('explanation', 'N/A')}
""".strip()

        threat_intel = f"""
{sep}
 THREAT INTELLIGENCE
{sep}
  VirusTotal     : {context.get('vt_malicious_count', 0)} malicious detections
  AbuseIPDB      : {context.get('abuse_confidence_score', 0)}% confidence score
  TOR Exit Node  : {"YES ⚠" if context.get('ip_is_tor') else "No"}
  VPN Source     : {"YES" if context.get('ip_is_vpn') else "No"}
  Country        : {context.get('ip_country', 'Unknown')}
  Asset          : {context.get('asset_criticality', 'UNKNOWN')} criticality
  DC Target      : {"YES ⚠" if context.get('asset_is_domain_controller') else "No"}
  Business Hours : {"Yes" if context.get('is_business_hours') else "No — after hours activity"}
  IP History 24h : {context.get('ip_total_alerts_24h', 0)} alerts from this source
""".strip()

        if correlation.get("has_attack_chain"):
            chains_text = ""
            for chain in correlation.get("chains", []):
                chains_text += f"""
  Chain Detected : {chain['name']}
  Description    : {chain['description']}
  Severity       : {chain['severity']}
  Affected Hosts : {', '.join(chain.get('affected_hosts', []))}
  MITRE Chain    : {' → '.join(chain.get('mitre_techniques', []))}

  {chain.get('timeline', '')}
""".strip() + "\n"
            correlation_section = f"""
{sep}
 CORRELATED ATTACK CHAINS  ⚠
{sep}
{chains_text}""".strip()
        else:
            correlation_section = f"""
{sep}
 CORRELATED EVENTS
{sep}
  Related alerts : {correlation.get('related_alerts_count', 0)}
  Status         : Isolated incident — no attack chain detected
""".strip()

        steps_text = ""
        for i, (action, observation) in enumerate(agent_steps[:5], 1):
            tool_name = getattr(action, 'tool', 'unknown')
            tool_in   = str(getattr(action, 'tool_input', ''))[:120]
            obs_short = str(observation)[:200]
            steps_text += (
                f"  Step {i}: [{tool_name}]\n"
                f"    Input : {tool_in}\n"
                f"    Result: {obs_short}\n\n"
            )

        agent_section = f"""
{sep}
 AGENT REASONING TRACE
{sep}
{steps_text if steps_text else '  No tool steps recorded'}
  Final Output (last 600 chars):
  {agent_output[-600:] if agent_output else 'No output'}
""".strip()

        esc_reasons_text = "\n".join(
            f"    • {r}" for r in escalation.get("reasons", [])
        )
        escalation_section = f"""
{sep}
 ESCALATION DECISION
{sep}
  Decision  : {escalation.get('decision', 'N/A')}
  Urgency   : {escalation.get('urgency', 'N/A')}
  Tier      : Analyst {escalation.get('tier', 1)}

  Reasons:
{esc_reasons_text}
""".strip()

        recommendations = self._build_recommendations(
            alert, context, correlation
        )
        rec_section = f"""
{sep}
 RECOMMENDATIONS
{sep}
{recommendations}""".strip()

        return "\n\n".join([
            header,
            technical,
            triage_section,
            threat_intel,
            correlation_section,
            agent_section,
            escalation_section,
            rec_section,
        ])

    def _build_recommendations(self, alert: dict,
                                 context: dict,
                                 correlation: dict) -> str:
        recs = []
        n    = 1

        if context.get("has_successful_auth"):
            recs.append(
                f"  {n}. IMMEDIATE: Review all sessions from "
                f"{alert.get('source_ip')} — potential active compromise"
            ); n += 1
            recs.append(
                f"  {n}. Reset credentials for user "
                f"'{alert.get('target_user')}' immediately"); n += 1

        if correlation.get("has_attack_chain"):
            recs.append(
                f"  {n}. Investigate all hosts in the attack chain: "
                f"{', '.join(correlation['chains'][0].get('affected_hosts', []))}"
            ); n += 1

        if context.get("vt_malicious_count", 0) > 10:
            recs.append(
                f"  {n}. Block {alert.get('source_ip')} at perimeter "
                f"firewall — confirmed malicious IP"
            ); n += 1

        if context.get("asset_is_domain_controller"):
            recs.append(
                f"  {n}. Audit Domain Controller logs for any "
                f"unauthorized changes or new accounts"
            ); n += 1

        if not context.get("ip_is_whitelisted"):
            recs.append(
                f"  {n}. Add {alert.get('source_ip')} to threat intel "
                f"feed for future correlation"
            ); n += 1

        recs.append(
            f"  {n}. Review and tune Wazuh rule "
            f"[{alert.get('rule_id')}] to reduce similar false positives"
        )

        return "\n".join(recs) if recs else "  No specific recommendations"

    def _get_nist_control(self, rule_id: int) -> str:
        mapping = {
            range(5760, 5780): "AC-7",
            range(5500, 5520): "AU-2",
            range(40100, 40110): "SI-3",
            range(5400, 5410): "AC-6",
            range(31150, 31160): "SI-10",
        }
        for r, control in mapping.items():
            if rule_id in r:
                return control
        return "IR-4"

    # ── Thread-safe report ID generation ─────────────────
    def _next_report_id(self) -> str:
        today = datetime.utcnow().strftime("%Y%m%d")
        with self.lock:
            rows = self.db.query("""
                SELECT COUNT(*) AS cnt FROM incident_reports
                WHERE id LIKE ?
            """, [f"INC-{today}-%"])
            count = (dict(rows[0]).get("cnt", 0) + 1) if rows else 1
        return f"INC-{today}-{count:04d}"