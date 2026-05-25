import requests
import json
from datetime import datetime, timedelta
from langchain.tools import tool
import urllib3
urllib3.disable_warnings()


def get_wazuh_tools(db_manager, wazuh_config, vt_api_key=None):

    wazuh_url  = wazuh_config["url"]
    wazuh_user = wazuh_config["user"]
    wazuh_pass = wazuh_config["password"]

    def _get_token():
        resp = requests.post(
            f"{wazuh_url}/security/user/authenticate",
            auth=(wazuh_user, wazuh_pass),
            verify=False, timeout=10
        )
        return resp.json()["data"]["token"]

    @tool
    def query_recent_alerts(source_ip: str, hours: int = 24) -> str:
        """Query the local database for all alerts from a source IP in the last N hours.
        Args:
            source_ip: The attacker IP address
            hours: How many hours to look back (default 24)
        Returns:
            JSON with alerts and summary stats
        """
        try:
            cutoff = datetime.utcnow() - timedelta(hours=hours)
            rows   = db_manager.query("""
                SELECT rule_id, rule_description, severity_level,
                       target_host, target_user, timestamp, mitre_technique
                FROM alerts
                WHERE source_ip = ? AND timestamp >= ?
                ORDER BY timestamp DESC LIMIT 100
            """, [source_ip, cutoff.isoformat()])

            alerts = [dict(r) for r in rows]
            return json.dumps({
                "total_count":      len(alerts),
                "unique_rules":     len(set(a["rule_id"] for a in alerts)),
                "unique_targets":   len(set(a["target_host"] for a in alerts)),
                "highest_severity": max((a["severity_level"] for a in alerts), default=0),
                "first_seen":       alerts[-1]["timestamp"] if alerts else None,
                "last_seen":        alerts[0]["timestamp"]  if alerts else None,
                "alerts":           alerts[:20]
            }, ensure_ascii=False, indent=2)
        except Exception as e:
            return json.dumps({"error": str(e)})

    @tool
    def check_successful_login(source_ip: str, target_host: str,
                                minutes_after: int = 30,
                                rule_description: str = "",
                                alert_rule_id: int = 0) -> str:
        """Check if there was a SUCCESSFUL login after failed attempts.
        This is the most critical indicator of compromise.
        Args:
            source_ip: Attacker IP
            target_host: Target machine
            minutes_after: Time window in minutes
            rule_description: Current alert description
            alert_rule_id: Current alert rule ID
        Returns:
            JSON with found status and details
        """
        try:
            if rule_description:
                desc_lower = rule_description.lower()
                if any(p in desc_lower for p in [
                    "successful authentication", "login succeeded",
                    "authentication succeeded", "followed by a success",
                    "successful login", "successfully logged in"
                ]):
                    return json.dumps({
                        "found": True,
                        "source": "alert_description",
                        "assessment": "CRITICAL — Alert confirms successful compromise."
                    })

            rows = db_manager.query("""
                SELECT rule_id, rule_description, timestamp, target_user
                FROM alerts
                WHERE source_ip = ? AND target_host = ?
                  AND rule_id IN (5501, 5502, 5715)
                ORDER BY timestamp DESC LIMIT 5
            """, [source_ip, target_host])

            logins = [dict(r) for r in rows]
            return json.dumps({
                "found":       len(logins) > 0,
                "login_count": len(logins),
                "logins":      logins,
                "assessment":  ("CRITICAL — Successful compromise detected"
                                if logins else "No successful login found")
            }, ensure_ascii=False, indent=2)
        except Exception as e:
            return json.dumps({"error": str(e)})

    @tool
    def get_asset_info(host_ip: str) -> str:
        """Get asset information: criticality, owner, services, DC status.
        Args:
            host_ip: IP of target host
        Returns:
            JSON with asset details
        """
        try:
            row = db_manager.query("""
                SELECT hostname, ip, criticality, owner, services,
                       is_domain_controller, os, department
                FROM asset_inventory WHERE ip = ?
            """, [host_ip])

            if row:
                asset         = dict(row[0])
                asset["found"] = True
                return json.dumps(asset, ensure_ascii=False, indent=2)
            return json.dumps({
                "found": False, "ip": host_ip,
                "criticality": "UNKNOWN",
                "note": "Not in inventory — treat as MEDIUM"
            })
        except Exception as e:
            return json.dumps({"error": str(e)})

    @tool
    def check_ip_reputation(ip_address: str) -> str:
        """Check IP reputation from local cache AND VirusTotal API.
        Args:
            ip_address: IP to check
        Returns:
            JSON with full reputation data including VT results
        """
        try:
            # ── 1. فحص قاعدة البيانات المحلية أولاً ──
            row = db_manager.query("""
                SELECT ip, vt_malicious, vt_suspicious, abuse_score,
                       abuse_reports, is_tor, is_vpn, country, last_updated
                FROM ip_reputation WHERE ip = ?
            """, [ip_address])

            # إذا موجود في DB وحديث (آخر 24 ساعة) استخدمه
            if row:
                cached = dict(row[0])
                last_updated = cached.get("last_updated", "")
                is_recent = False
                if last_updated:
                    try:
                        updated_dt = datetime.fromisoformat(last_updated)
                        is_recent  = (datetime.utcnow() - updated_dt).total_seconds < 86400
                    except Exception:
                        pass

                if is_recent:
                    cached["found"]        = True
                    cached["source"]       = "cache"
                    cached["is_malicious"] = (cached["vt_malicious"] > 5 or
                                              cached["abuse_score"] > 50)
                    return json.dumps(cached, ensure_ascii=False, indent=2)

            # ── 2. استدعاء VirusTotal API ──────────────
            vt_result = {"vt_malicious": 0, "vt_suspicious": 0,
                         "country": "Unknown", "vt_found": False}

            if vt_api_key:
                try:
                    vt_resp = requests.get(
                        f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}",
                        headers={"x-apikey": vt_api_key},
                        timeout=10
                    )
                    if vt_resp.status_code == 200:
                        vt_data  = vt_resp.json()
                        stats    = vt_data.get("data", {}).get(
                            "attributes", {}
                        ).get("last_analysis_stats", {})
                        country  = vt_data.get("data", {}).get(
                            "attributes", {}
                        ).get("country", "Unknown")

                        vt_malicious  = stats.get("malicious",  0)
                        vt_suspicious = stats.get("suspicious", 0)
                        vt_result = {
                            "vt_malicious":  vt_malicious,
                            "vt_suspicious": vt_suspicious,
                            "country":       country,
                            "vt_found":      True
                        }

                        # ── حفظ النتيجة في DB للكاش ──
                        db_manager.execute("""
                            INSERT OR REPLACE INTO ip_reputation
                                (ip, vt_malicious, vt_suspicious,
                                 abuse_score, abuse_reports,
                                 country, last_updated)
                            VALUES (?, ?, ?, ?, ?, ?, ?)
                        """, [
                            ip_address,
                            vt_malicious, vt_suspicious,
                            row[0]["abuse_score"] if row else 0,
                            row[0]["abuse_reports"] if row else 0,
                            country,
                            datetime.utcnow().isoformat()
                        ])
                        print(f"   🦠 VT: {ip_address} → "
                              f"{vt_malicious} malicious, "
                              f"{vt_suspicious} suspicious")
                    elif vt_resp.status_code == 404:
                        vt_result["vt_found"] = False
                    else:
                        print(f"   ⚠️  VT API error: {vt_resp.status_code}")
                except Exception as e:
                    print(f"   ⚠️  VT request failed: {e}")
            else:
                vt_result["note"] = "VT API key not configured"

            # ── 3. دمج النتائج ──────────────────────────
            is_internal = (ip_address.startswith("192.168.") or
                           ip_address.startswith("10.")       or
                           ip_address.startswith("172."))

            existing_abuse = row[0]["abuse_score"] if row else 0
            existing_tor   = bool(row[0]["is_tor"]) if row else False
            existing_vpn   = bool(row[0]["is_vpn"]) if row else False

            final = {
                "found":                 True,
                "ip":                    ip_address,
                "source":                "virustotal+cache",
                "vt_malicious_count":    vt_result["vt_malicious"],
                "vt_suspicious_count":   vt_result["vt_suspicious"],
                "abuse_confidence_score": existing_abuse,
                "is_tor":                existing_tor,
                "is_vpn":                existing_vpn,
                "country":               vt_result.get("country", "Unknown"),
                "is_internal":           is_internal,
                "is_malicious":          (vt_result["vt_malicious"] > 5 or
                                          existing_abuse > 50),
            }
            return json.dumps(final, ensure_ascii=False, indent=2)

        except Exception as e:
            return json.dumps({"error": str(e)})

    @tool
    def check_whitelist(ip_address: str) -> str:
        """Check if an IP is in the approved whitelist.
        Args:
            ip_address: IP to check
        Returns:
            JSON with whitelist status
        """
        try:
            row = db_manager.query("""
                SELECT ip, reason, added_by, added_at
                FROM ip_whitelist WHERE ip = ?
            """, [ip_address])

            if row:
                entry               = dict(row[0])
                entry["whitelisted"] = True
                return json.dumps(entry, ensure_ascii=False, indent=2)
            return json.dumps({"whitelisted": False, "ip": ip_address})
        except Exception as e:
            return json.dumps({"error": str(e)})

    @tool
    def get_alert_frequency(source_ip: str, rule_id: int, days: int = 7) -> str:
        """Get how often alerts with a specific rule appear from a source IP.
        Helps detect recurring false positive patterns.
        Args:
            source_ip: Source IP
            rule_id: Wazuh rule ID
            days: Days to look back
        Returns:
            JSON with frequency data
        """
        try:
            cutoff = datetime.utcnow() - timedelta(days=days)
            rows   = db_manager.query("""
                SELECT DATE(timestamp) as date, COUNT(*) as count
                FROM alerts
                WHERE source_ip = ? AND rule_id = ? AND timestamp >= ?
                GROUP BY DATE(timestamp)
                ORDER BY date DESC
            """, [source_ip, rule_id, cutoff.isoformat()])

            daily = [dict(r) for r in rows]
            total = sum(d["count"] for d in daily)
            return json.dumps({
                "total_in_period": total,
                "days_active":     len(daily),
                "daily_breakdown": daily,
                "is_recurring":    len(daily) >= 3,
                "avg_per_day":     round(total / max(days, 1), 1)
            }, ensure_ascii=False, indent=2)
        except Exception as e:
            return json.dumps({"error": str(e)})

    @tool
    def check_privilege_escalation(source_ip: str,
                                    target_host: str) -> str:
        """
        Check for privilege escalation attempts and successes on a target host.
        Rule IDs: 5400/5401=failed attempt, 5402/5403=successful escalation.
        Args:
            source_ip: The source IP
            target_host: Target host to check
        Returns:
            JSON with escalation details and severity assessment
        """
        try:
            rows = db_manager.query("""
                SELECT rule_id, rule_description, timestamp,
                       target_user, severity_level
                FROM alerts
                WHERE (source_ip = ? OR target_host = ?)
                  AND rule_id IN (5400, 5401, 5402, 5403,
                                  5500, 5501, 4720, 4732,
                                  4756, 4728)
                ORDER BY timestamp DESC LIMIT 20
            """, [source_ip, target_host])

            events = [dict(r) for r in rows]

            failed_attempts  = [e for e in events if e["rule_id"] in [5400, 5401]]
            successful_escalations = [e for e in events
                                       if e["rule_id"] in [5402, 5403]]
            privilege_changes = [e for e in events
                                  if e["rule_id"] in [4720, 4732, 4756, 4728]]

            has_successful = len(successful_escalations) > 0
            assessment = "CRITICAL" if has_successful else (
                "HIGH" if failed_attempts else "LOW"
            )

            return json.dumps({
                "has_privilege_escalation": len(events) > 0,
                "has_successful_escalation": has_successful,
                "failed_attempts_count":     len(failed_attempts),
                "successful_count":          len(successful_escalations),
                "privilege_changes_count":   len(privilege_changes),
                "assessment":                assessment,
                "recommendation": (
                    "BLOCK and ESCALATE immediately — successful privilege escalation"
                    if has_successful else
                    "Monitor closely — escalation attempts detected"
                    if failed_attempts else
                    "No privilege escalation detected"
                ),
                "events": events[:10]
            }, ensure_ascii=False, indent=2)
        except Exception as e:
            return json.dumps({"error": str(e)})

    @tool
    def get_wazuh_agent_status(agent_name: str) -> str:
        """Get the current status of a Wazuh agent.
        Args:
            agent_name: Name of the Wazuh agent
        Returns:
            JSON with agent status
        """
        try:
            token = _get_token()
            resp  = requests.get(
                f"{wazuh_url}/agents",
                headers={"Authorization": f"Bearer {token}"},
                params={"name": agent_name},
                verify=False, timeout=10
            )
            data = resp.json()
            if data["data"]["total_affected_items"] > 0:
                agent = data["data"]["affected_items"][0]
                return json.dumps({
                    "found":          True,
                    "name":           agent["name"],
                    "status":         agent["status"],
                    "ip":             agent.get("ip"),
                    "os":             agent.get("os", {}).get("name"),
                    "last_keepalive": agent.get("lastKeepAlive")
                })
            return json.dumps({"found": False, "name": agent_name})
        except Exception as e:
            return json.dumps({"error": str(e)})
        
    @tool
    def query_alerts_by_target(target_host: str, hours: int = 24) -> str:
        """Fetch all alerts where the target host matches.
        Use this when an alert has a missing or placeholder source IP (0.0.0.0)
        and you need to find which external IPs have been attacking this host.
        Args:
            target_host: Name or IP of the target machine
            hours: Lookback period (default 24)
        Returns:
            JSON with summary and alert list
        """
        try:
            cutoff = datetime.utcnow() - timedelta(hours=hours)
            rows = db_manager.query("""
                SELECT id, rule_id, rule_description, severity_level,
                       source_ip, target_host, target_user, timestamp
                FROM alerts
                WHERE target_host = ? AND timestamp >= ?
                ORDER BY timestamp DESC LIMIT 100
            """, [target_host, cutoff.isoformat()])

            alerts = [dict(r) for r in rows]
            source_ips = list(set(a["source_ip"] for a in alerts))

            return json.dumps({
                "total_alerts": len(alerts),
                "unique_source_ips": source_ips,
                "alerts": alerts[:30]
            }, ensure_ascii=False, indent=2)
        except Exception as e:
            return json.dumps({"error": str(e)})

    @tool
    def query_alerts_in_timeframe(source_ip: str,
                                   minutes_back: int = 10) -> str:
        """Query alerts from a source IP within the last N minutes.
        Args:
            source_ip: Attacker IP
            minutes_back: Minutes to look back (default 10)
        Returns:
            JSON with alerts summary
        """
        try:
            cutoff = datetime.utcnow() - timedelta(minutes=minutes_back)
            rows   = db_manager.query("""
                SELECT rule_id, rule_description, severity_level,
                       target_host, target_user, timestamp, mitre_technique
                FROM alerts
                WHERE source_ip = ? AND timestamp >= ?
                ORDER BY timestamp DESC LIMIT 100
            """, [source_ip, cutoff.isoformat()])

            alerts = [dict(r) for r in rows]
            return json.dumps({
                "total_count":      len(alerts),
                "unique_rules":     len(set(a["rule_id"] for a in alerts)),
                "unique_targets":   len(set(a["target_host"] for a in alerts)),
                "highest_severity": max((a["severity_level"] for a in alerts), default=0),
                "first_seen":       alerts[-1]["timestamp"] if alerts else None,
                "last_seen":        alerts[0]["timestamp"]  if alerts else None,
                "alerts":           alerts[:30]
            }, ensure_ascii=False, indent=2)
        except Exception as e:
            return json.dumps({"error": str(e)})



    return [
        query_recent_alerts,
        check_successful_login,
        get_asset_info,
        check_ip_reputation,
        check_whitelist,
        get_alert_frequency,
        check_privilege_escalation,
        get_wazuh_agent_status,
        query_alerts_in_timeframe,
        query_alerts_by_target,
    ]