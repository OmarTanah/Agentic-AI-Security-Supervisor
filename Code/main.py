#!/usr/bin/env python3
"""
Autonomous SOC Tier-1 Analyst Agent
v2.3 – LangGraph native tool calling (no parsing issues)
"""
import os, json, time, hashlib, re, requests, threading, urllib3
import sqlite3 as _sqlite3
from datetime import datetime, timedelta
from collections import defaultdict
from flask import Flask, request, jsonify

from langchain_ollama import ChatOllama
from langchain_core.messages import SystemMessage, HumanMessage, AIMessage, ToolMessage
from langgraph.graph import StateGraph, START, END, MessagesState
from langgraph.prebuilt import ToolNode, tools_condition
from langgraph.checkpoint.memory import MemorySaver
from app_config import load_config
from db_manager import DBManager
from triage_engine import TriageEngine
from context_enricher import ContextEnricher
from correlation_engine import CorrelationEngine
from report_generator import ReportGenerator
from tools import get_all_tools

import logging
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)
urllib3.disable_warnings()

# ── Prompt for the LLM (used as system message) ──────────
ANALYST_SYSTEM_PROMPT = """You are an autonomous SOC Tier‑1 Analyst.
Your task is to investigate security alerts, gather evidence using the available tools,
and decide on the appropriate response.

## HOW TO WORK
- Gather context: use check_whitelist, check_ip_reputation, query_recent_alerts, get_asset_info,
  check_successful_login, check_privilege_escalation, and any other tool that fills gaps.
- If the source IP is missing (0.0.0.0), use query_alerts_by_target to find possible attackers.
- After collecting facts, consult the security operations policies by calling get_policies.
  The policies are based on NIST 800-53 and MITRE ATT&CK and will guide your response.

## RESPONSE ACTIONS
- If an attack is confirmed, block the source IP using block_ip_firewall
  (use duration from the policies: CRITICAL=3600s, HIGH=300s, MEDIUM=60s, LOW=30s).
- After blocking, always escalate to a Tier‑2 analyst with escalate_to_analyst.
- If the evidence clearly shows a false positive, close the alert with close_alert_as_fp.
- When uncertain, escalate with MEDIUM priority and explain what additional investigation is needed.
- Never call the same blocking or escalating tool twice for the same alert.
## IMPORTANT
Save every investigation step with save_investigation_note.
Think like a detective – follow the evidence, consult the policies, and act proportionally.
"""
def normalize_wazuh_alert(raw: dict) -> dict | None:
    try:
        src    = raw.get("_source", raw)
        rule   = src.get("rule", {})
        data   = src.get("data", {})
        agent  = src.get("agent", {})
        mitre  = rule.get("mitre", {})

        source_ip = (
            data.get("srcip") or data.get("src_ip") or data.get("source_ip") or
            data.get("srcaddr") or rule.get("srcip") or ""
        )
        if not source_ip or source_ip == "0.0.0.0":
            win = data.get("win", {}).get("system", {}).get("eventData", {})
            source_ip = (win.get("IpAddress") or win.get("IpAddress6") or
                         win.get("SourceNetworkAddress") or "")
        if not source_ip or source_ip == "0.0.0.0":
            for log_src in [data, src]:
                log_line = log_src.get("full_log", "")
                if log_line:
                    match = re.search(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', log_line)
                    if match:
                        candidate = match.group(1)
                        if candidate != agent.get("ip"):
                            source_ip = candidate
                            break
        if not source_ip:
            source_ip = "0.0.0.0"

        rule_id = int(rule.get("id", 0))
        level   = int(rule.get("level", 0))
        if level < 3:
            return None
        label = ("CRITICAL" if level >= 13 else "HIGH" if level >= 10 else
                 "MEDIUM" if level >= 7 else "LOW")
        ts = src.get("timestamp", datetime.utcnow().isoformat())
        if "T" not in ts:
            ts = datetime.utcnow().isoformat()
        uid = hashlib.md5(f"{ts}{rule_id}{source_ip}{agent.get('name','')}".encode()).hexdigest()[:12]

        return {
            "id":               f"ALT-{datetime.utcnow().strftime('%Y%m%d')}-{uid}",
            "wazuh_id":         raw.get("_id", ""),
            "timestamp":        ts,
            "rule_id":          rule_id,
            "rule_description": rule.get("description", "Unknown"),
            "severity_level":   level,
            "severity_label":   label,
            "source_ip":        source_ip,
            "target_host":      agent.get("name", "unknown"),
            "target_host_ip":   agent.get("ip", "0.0.0.0"),
            "target_user":      (data.get("dstuser") or data.get("user") or "unknown"),
            "agent_id":         agent.get("id", "000"),
            "mitre_technique":  (mitre.get("id",  [""])[0] if isinstance(mitre.get("id"),  list) else mitre.get("id",  "")),
            "mitre_tactic":     (mitre.get("tactic",[""])[0] if isinstance(mitre.get("tactic"),list) else mitre.get("tactic","")),
            "raw_json":         json.dumps(raw, ensure_ascii=False),
        }
    except Exception as e:
        print(f"[NORMALIZER] Error: {e}")
        return None


# ─────────────────────────────────────────────────────────
class AlertAggregator:
    def __init__(self, window_seconds=5):
        self.window   = window_seconds
        self.buckets  = defaultdict(lambda: {
            "alerts": [], "timer": None,
            "lock": threading.RLock(), "released": False
        })
        self.callback = None

    def set_callback(self, callback):
        self.callback = callback

    def add_alert(self, alert):
        source = alert.get("source_ip", "0.0.0.0")
        with self.buckets[source]["lock"]:
            bucket = self.buckets[source]
            bucket["alerts"].append(alert)

            high_sev     = alert["severity_level"] >= 10
            success_text = (
                "success" in alert.get("rule_description", "").lower() or
                "multiple authentication failures followed by a success"
                in alert.get("rule_description", "").lower()
            )
            priv_esc = alert.get("rule_id") in [5402, 5403]
            bypass = high_sev or success_text or priv_esc

            if bypass:
                if not bucket["released"]:
                    bucket["released"] = True
                    if bucket["timer"]:
                        bucket["timer"].cancel()
                        bucket["timer"] = None
                    # Instead of releasing the best alert,
                    # immediately release THIS alert (the one that caused the bypass)
                    alert["aggregated_count"] = 1   # or len(bucket["alerts"])
                    self.callback(alert)
                    bucket["alerts"].clear()
                return

            if bucket["timer"] is None and not bucket["released"]:
                bucket["timer"] = threading.Timer(
                    self.window, self._release_after_window, args=[source]
                )
                bucket["timer"].start()

    def _release_now(self, source):
        best, count = self._extract_best(source)
        if best is not None and self.callback:
            best["aggregated_count"] = count
            self.callback(best)
        # Reset the bucket so later alerts are not lost
        with self.buckets[source]["lock"]:
            self.buckets[source]["released"] = False

    def _release_after_window(self, source):
        with self.buckets[source]["lock"]:
            bucket = self.buckets[source]
            if bucket["released"]:
                return
            bucket["released"] = True
            if bucket["timer"]:
                bucket["timer"].cancel()
                bucket["timer"] = None
        best, count = self._extract_best(source)
        if best is not None and self.callback:
            best["aggregated_count"] = count
            self.callback(best)
        # Reset the bucket for future alerts
        with self.buckets[source]["lock"]:
            self.buckets[source]["released"] = False

    def _extract_best(self, source):
        with self.buckets[source]["lock"]:
            bucket = self.buckets[source]
            if not bucket["alerts"]:
                return None, 0
            best  = max(bucket["alerts"], key=lambda a: a["severity_level"])
            count = len(bucket["alerts"])
            bucket["alerts"].clear()
            return best, count


# ─────────────────────────────────────────────────────────
class SOCAgent:
    def __init__(self):
        self.config   = load_config()
        self.policies = self._load_policies()
        self.db       = DBManager(self.config["database"]["path"])

        self.triage     = TriageEngine(self.policies)
        self.enricher   = ContextEnricher(
            self.db,
            known_malicious_ips=self.config.get("known_malicious_ips", [])
        )
        self.correlator = CorrelationEngine(self.db)
        self.reporter   = ReportGenerator(self.db)

        ollama_cfg = self.config["ollama"]
        self.llm = ChatOllama(
            base_url=ollama_cfg["base_url"],
            model=ollama_cfg["model"],
            temperature=self.policies["agent_config"]["temperature"],
            max_tokens=self.policies["agent_config"]["max_tokens"],   # fixed
        )

        self.tools = get_all_tools(
            self.db, self.config["wazuh"], self.policies,
            vt_api_key= "bef217364f7a04c253a8dbcdea1bd060306a0a63f6a399d5c0afa9a81dc8db0c"
        )

        # ── Build the LangGraph agent ───────────────────
        self.llm_with_tools = self.llm.bind_tools(self.tools)
        self.system_msg = SystemMessage(content=ANALYST_SYSTEM_PROMPT)

        builder = StateGraph(MessagesState)
        builder.add_node("agent", self._call_model)
        builder.add_node("tools", ToolNode(self.tools))
        builder.add_edge(START, "agent")
        builder.add_conditional_edges("agent", tools_condition, {"tools": "tools", "__end__": END})
        builder.add_edge("tools", "agent")

        checkpointer = MemorySaver()
        self.graph = builder.compile(checkpointer=checkpointer)

        self.llm_semaphore = threading.Semaphore(1)
        self.recently_blocked = set()

        self.aggregator = AlertAggregator(
            window_seconds=self.config.get("aggregation_window_seconds", 5)
        )
        self.aggregator.set_callback(self._on_aggregated_alert)
        self.active_investigations = {}
        self.inv_lock = threading.Lock()

        self._check_ollama_connection()
        print("✅ SOC Agent initialized with aggregation window {}s".format(
            self.config.get("aggregation_window_seconds", 5)))

    def _call_model(self, state: MessagesState):
        """Graph node: calls the LLM with tools, prepending system message if needed."""
        messages = state["messages"]
        if not any(isinstance(m, SystemMessage) for m in messages):
            messages = [self.system_msg] + list(messages)
        response = self.llm_with_tools.invoke(messages)
        return {"messages": [response]}

    def _check_ollama_connection(self):
        try:
            url    = self.config["ollama"]["base_url"]
            resp   = requests.get(f"{url}/api/tags", timeout=5)
            models = [m["name"] for m in resp.json().get("models", [])]
            target = self.config["ollama"]["model"]
            if not any(target in m for m in models):
                print(f"⚠️  Model '{target}' not found. Run: ollama pull {target}")
            else:
                print(f"   ✓ Ollama model '{target}' is ready")
        except Exception as e:
            print(f"⚠️  Cannot reach Ollama: {e}")

    def _load_policies(self):
        path = os.path.join(os.path.dirname(__file__), "policies.json")
        with open(path, "r") as f:
            return json.load(f)

    def process_alert(self, raw):
        """
        نسخة شاملة لمنع أخطاء KeyError ودعم التحليل الذاتي بالكامل
        """
        # 1. استخراج الـ IP بذكاء (إصلاح 0.0.0.0)
        source_ip = raw.get("data", {}).get("srcip")
        if not source_ip or source_ip == "0.0.0.0":
            source_ip = raw.get("agent", {}).get("ip", "0.0.0.0")

        # 2. استخراج معلومات MITRE (إذا لم توجد نضع N/A)
        mitre_data = raw.get("rule", {}).get("mitre", {})
        technique = mitre_data.get("id", ["N/A"])[0] if mitre_data.get("id") else "N/A"
        tactic    = mitre_data.get("tactic", ["N/A"])[0] if mitre_data.get("tactic") else "N/A"

        # 3. بناء قاموس البيانات الشامل بكل الحقول المطلوبة
        alert_data = {
            "id":               raw.get("id"),
            "wazuh_id":         raw.get("id"),
            "timestamp":        raw.get("timestamp"),
            "rule_id":          int(raw.get("rule", {}).get("id", 0)),
            "rule_description": raw.get("rule", {}).get("description", "No description"),
            "severity_level":   int(raw.get("rule", {}).get("level", 0)),
            
            # حقول التنسيق والطباعة
            "severity_label":   "HIGH" if int(raw.get("rule", {}).get("level", 0)) >= 10 else "MEDIUM" if int(raw.get("rule", {}).get("level", 0)) >= 5 else "LOW",
            
            # حقول الهوية والهدف
            "source_ip":        source_ip,
            "target_host":      raw.get("agent", {}).get("name", "unknown"),
            "target_host_ip":   raw.get("agent", {}).get("ip", "0.0.0.0"),
            "target_user":      raw.get("data", {}).get("dstuser") or raw.get("data", {}).get("user") or "system",
            "agent_id":         raw.get("agent", {}).get("id", "000"),

            # --- حل مشكلة MITRE المتسببة في الخطأ الأخير ---
            "mitre_technique":  technique,
            "mitre_tactic":     tactic,
            
            "raw_json":         json.dumps(raw)
        }

        # طباعة التأكيد
        print(f"   ➕ Queued alert {alert_data['id']} [{alert_data['rule_id']}] from {alert_data['source_ip']}")

        # الإرسال للمجمع
        if hasattr(self, 'aggregator'):
            self.aggregator.add_alert(alert_data)
        elif hasattr(self, 'alert_queue'):
            self.alert_queue.put(alert_data)

    def _on_aggregated_alert(self, alert):
        print(f"\n{'─'*60}")
        print(f"📨 Aggregated Alert: {alert['id']} "
              f"(aggregated {alert.get('aggregated_count',1)} alerts)")
        print(f"   Rule    : [{alert['rule_id']}] {alert['rule_description']}")
        print(f"   Source  : {alert['source_ip']} → {alert['target_host']}")
        print(f"   Severity: {alert['severity_label']} ({alert['severity_level']})")
        print(f"{'─'*60}")

        # 1. Enrich
        context = self.enricher.enrich(alert)
        print(f"   🔍 is_known_test_threat = {context.get('is_known_test_threat', False)}")

        # 2. Correlation (advisory)
        correlation = self.correlator.analyze(alert)

        # 3. Triage (advisory – only used if confidence is extremely high)
        triage_result = self.triage.run(alert, context)
        fp  = triage_result["fp_assessment"]
        pri = triage_result["priority"]
        fp_val = fp.get('fp_probability', 0.0)
        print(f"    📊 Triage: FP={fp.get('verdict', 'UNKNOWN')} ({fp_val:.0%})  P={pri['level']} (score {pri['score']})")

        # 4. Auto‑close only if FP is virtually certain
        if fp["verdict"] == "FALSE_POSITIVE" and fp["confidence"] > 0.85:
            self.db.execute(
                "UPDATE alerts SET status='CLOSED_FP', resolved_at=? WHERE id=?",
                [datetime.utcnow().isoformat(), alert["id"]]
            )
            print("   ✓ Auto-closed as FALSE POSITIVE (very high confidence)")
            return

        # 5. Auto‑block only if TP + CRITICAL + very high confidence
                # ── 5. TP مؤكد + CRITICAL → block فوري (if source IP is real) ──
        if (fp["verdict"] == "TRUE_POSITIVE" and
                pri["level"] == "CRITICAL" and fp["confidence"] > 0.8 and
                alert.get("source_ip", "0.0.0.0") != "0.0.0.0"):
            self._auto_block_and_escalate(alert, "High-confidence critical True Positive")
            return

        # 6. Everything else → LLM investigation
        self._investigate_with_llm(alert, context, triage_result, correlation)
    def _auto_block_and_escalate(self, alert, reason):
        ip = alert["source_ip"]
        if ip in self.recently_blocked:
            print(f"   ⚠️  IP {ip} already blocked recently, skipping")
            return

        print(f"   🚨 {reason} – auto-blocking IP {ip}")
        try:
            block_tool    = next((t for t in self.tools if t.name == "block_ip_firewall"), None)
            escalate_tool = next((t for t in self.tools if t.name == "escalate_to_analyst"), None)

            if block_tool:
                result = block_tool.func(
                    ip_address=ip, duration_seconds=3600,
                    reason=reason, alert_id=alert["id"],
                    allow_internal=True
                )
                print(f"   Block result: {result}")

            if escalate_tool:
                result = escalate_tool.func(
                    alert_id=alert["id"], priority="CRITICAL",
                    reason=reason,
                    summary=f"Alert {alert['id']} – {ip} auto-blocked. Reason: {reason}"
                )
                print(f"   Escalate result: {result}")

            self.recently_blocked.add(ip)
            threading.Timer(300, lambda: self.recently_blocked.discard(ip)).start()

        except Exception as e:
            print(f"   ⚠️  Auto-block failed: {e}")

        self.db.execute(
            "UPDATE alerts SET status='PROCESSED', processed_at=? WHERE id=?",
            [datetime.utcnow().isoformat(), alert["id"]]
        )
        print(f"   ✅ Auto-blocked and escalated\n")

    def _investigate_with_llm(self, alert, context, triage_result, correlation=None):
        correlation = self.correlator.analyze(alert)
        agent_input = self._build_agent_input(alert, context, triage_result, correlation)

        thread_id = alert["id"]
        config = {"configurable": {"thread_id": thread_id}}

        print("   🤖 Invoking LLM via Graph...")
        start = time.time()
        with self.llm_semaphore:
            tool_calls_log = []   # to collect tool interactions for the report
            final_output = ""
            last_tool_call = None   # <-- track the most recent tool call
            try:
                events = self.graph.stream(
                    {"messages": [HumanMessage(content=agent_input)]},
                    config=config,
                    stream_mode="values"
                )
                for event in events:
                    if "messages" in event:
                        msg = event["messages"][-1]
                        if isinstance(msg, AIMessage):
                            if msg.content:
                                final_output = msg.content
                                print(f"   🤖 Agent: {msg.content[:200]}")
                            if msg.tool_calls:
                                for tc in msg.tool_calls:
                                    print(f"   🔧 Tool call: {tc['name']} -> {tc['args']}")
                                # capture the last tool call for later logging
                                if msg.tool_calls:
                                    last_tool_call = msg.tool_calls[-1]
                        elif isinstance(msg, ToolMessage):
                            print(f"   📦 Tool result ({msg.name}): {msg.content[:200]}")
                            # store a simplified step for the report
                            if last_tool_call:
                                tool_calls_log.append((last_tool_call.get('name', 'unknown'),
                                                    str(last_tool_call.get('args', ''))))
            except Exception as e:
                print(f"   ⚠️  LLM error: {e}")
                final_output = f"Agent error: {str(e)}"

        # Generate report (use collected tool calls as agent_steps)
        steps_for_report = [(None, tc) for tc in tool_calls_log]  # approximate format
        report = self.reporter.generate(alert, context, triage_result, correlation, final_output, steps_for_report)
        self.db.execute("UPDATE alerts SET status='PROCESSED', processed_at=? WHERE id=?",
                        [datetime.utcnow().isoformat(), alert["id"]])
        elapsed = round(time.time() - start, 2)
        print(f"   ✅ LLM done in {elapsed}s | Report: {report['id']}")

        # ── Print final incident report ─────────────────
        print("\n" + "=" * 60)
        print("   FINAL INCIDENT REPORT")
        print("=" * 60)
        print(report["content"])
        print("=" * 60 + "\n")

        # ── Optionally save to a separate file ──────────
        report_dir = "incident_reports"
        os.makedirs(report_dir, exist_ok=True)
        with open(f"{report_dir}/{report['id']}.md", "w") as f:
            f.write(report["content"])

        with open("investigations.log", "a") as f:
            f.write(f"\n{'='*60}\n")
            f.write(f"ALERT ID: {alert['id']}\n")
            f.write(f"RESULT: {final_output}\n")
            f.write(f"{'='*60}\n")

    def _build_agent_input(self, alert, context, triage, correlation):
        chains_text     = ""
        priv_esc_text   = ""
        threat_override = ""

        if correlation.get("has_attack_chain"):
            chains      = correlation.get("chains", [])
            chains_text = f"\n⚠️ ATTACK CHAIN: {chains[0].get('name')}"

        if alert.get("rule_id") in [5400, 5401, 5402, 5403]:
            status = "SUCCESSFUL" if alert.get("rule_id") in [5402, 5403] else "FAILED"
            priv_esc_text = f"\n🔴 PRIVILEGE ESCALATION {status} (rule {alert['rule_id']})"

        if context.get("is_known_test_threat"):
            threat_override = "\n⚠️ KNOWN TEST THREAT — treat as confirmed attacker.\n"

        return f"""
ALERT ID   : {alert['id']} (aggregated {alert.get('aggregated_count',1)} events)
TIMESTAMP  : {alert['timestamp']}
RULE       : [{alert['rule_id']}] {alert['rule_description']}
SEVERITY   : {alert['severity_label']} (level {alert['severity_level']})
SOURCE IP  : {alert['source_ip']}
TARGET     : {alert['target_host']} ({alert['target_host_ip']})
USER       : {alert['target_user']}
MITRE      : {alert['mitre_technique']} | {alert['mitre_tactic']}
{threat_override}{priv_esc_text}{chains_text}

TRIAGE:
  FP Verdict     : {triage['fp_assessment']['verdict']} ({triage['fp_assessment']['fp_probability']:.0%})
  Priority       : {triage['priority']['level']} (score {triage['priority']['score']})
  Escalation Rec : {triage['escalation']['decision']}

CONTEXT:
  Asset Criticality  : {context.get('asset_criticality','UNKNOWN')}
  IP Whitelisted     : {context.get('ip_is_whitelisted', False)}
  Recurring Pattern  : {context.get('is_recurring_pattern', False)}
  Successful Auth    : {context.get('has_successful_auth', False)}
  VT Malicious Count : {context.get('vt_malicious_count', 0)}
  Abuse Score        : {context.get('abuse_confidence_score', 0)}%
  Is Internal IP     : {context.get('is_internal_ip', False)}

Investigate then act. If ESCALATE recommended, call escalate_to_analyst.
If block needed, call block_ip_firewall FIRST then escalate_to_analyst.
""".strip()

    def poll_wazuh(self):
        wazuh_cfg = self.config["wazuh"]
        indexer_cfg = self.config["wazuh_indexer"]
        interval = self.config["polling_interval_seconds"]
        print(f"🔄 Polling Wazuh Indexer every {interval}s ...")

        while True:
            try:
                # Query the Wazuh Indexer (OpenSearch) for recent alerts
                since = (datetime.utcnow() - timedelta(seconds=interval + 10)).strftime("%Y-%m-%dT%H:%M:%S")
                query = {
                    "size": 50,
                    "sort": [{"timestamp": "desc"}],
                    "query": {
                        "bool": {
                            "filter": [
                                {"range": {"timestamp": {"gte": since}}}
                            ]
                        }
                    }
                }
                resp = requests.get(
                    f"{indexer_cfg['url']}/wazuh-alerts-*/_search",
                    auth=(indexer_cfg["user"], indexer_cfg["password"]),
                    headers={"Content-Type": "application/json"},
                    json=query,
                    verify=False,
                    timeout=15
                )
                if resp.status_code != 200:
                    print(f"   ⚠️  Indexer error: {resp.status_code} {resp.text[:200]}")
                    time.sleep(interval)
                    continue

                hits = resp.json().get("hits", {}).get("hits", [])
                items = [h["_source"] for h in hits]
                print(f"   📊 Poll got {len(items)} items: {[it.get('rule',{}).get('id') for it in items]}")
                if items:
                    for raw in items:
                        self.process_alert(raw)
            except Exception as e:
                print(f"   ⚠️  Poll error: {e}")
            time.sleep(interval)


def create_flask_app(agent: SOCAgent) -> Flask:
    app = Flask(__name__)

    @app.route("/health", methods=["GET"])
    def health():
        return jsonify({
            "status": "running",
            "model": agent.config["ollama"]["model"],
            "timestamp": datetime.utcnow().isoformat()
        })

    def handle_webhook():
        raw = request.get_json(force=True)
        if not raw:
            return jsonify({"error": "No JSON body"}), 400
        threading.Thread(target=agent.process_alert, args=(raw,), daemon=True).start()
        return jsonify({"status": "queued"})

    @app.route("/webhook/wazuh", methods=["POST"])
    def webhook_wazuh():
        return handle_webhook()

    @app.route("/webhook", methods=["POST"])
    def webhook():
        return handle_webhook()

    @app.route("/alerts", methods=["GET"])
    def list_alerts():
        limit  = request.args.get("limit", 50, type=int)
        status = request.args.get("status", None)
        if status:
            rows = agent.db.query(
                """SELECT id, timestamp, rule_description, severity_label,
                          source_ip, target_host, status
                   FROM alerts WHERE status=?
                   ORDER BY timestamp DESC LIMIT ?""",
                [status, limit]
            )
        else:
            rows = agent.db.query(
                """SELECT id, timestamp, rule_description, severity_label,
                          source_ip, target_host, status
                   FROM alerts ORDER BY timestamp DESC LIMIT ?""",
                [limit]
            )
        return jsonify([dict(r) for r in rows])

    @app.route("/stats", methods=["GET"])
    def stats():
        rows = agent.db.query("""
            SELECT COUNT(*) as total,
                   SUM(status='PROCESSED')  as processed,
                   SUM(status='CLOSED_FP')  as closed_fp,
                   SUM(severity_label='CRITICAL') as critical,
                   SUM(severity_label='HIGH')     as high
            FROM alerts
        """)
        return jsonify(dict(rows[0]))

    @app.route("/process", methods=["POST"])
    def manual_process():
        raw    = request.get_json(force=True)
        result = agent.process_alert(raw)
        return jsonify(result)

    return app


if __name__ == "__main__":
    print("="*60)
    print("  Autonomous SOC Tier-1 Analyst Agent v2.3 – LangGraph")
    print("="*60)
    agent = SOCAgent()
    cfg   = agent.config
    threading.Thread(target=agent.poll_wazuh, daemon=True).start()
    app = create_flask_app(agent)
    print(f"\n🚀 Flask API → http://0.0.0.0:{cfg['flask']['port']}")
    app.run(
        host=cfg["flask"]["host"],
        port=cfg["flask"]["port"],
        debug=cfg["flask"]["debug"],
        use_reloader=False
    )