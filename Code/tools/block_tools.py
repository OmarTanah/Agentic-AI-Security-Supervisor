import requests
import json
import subprocess
from datetime import datetime
from langchain.tools import tool
import urllib3
urllib3.disable_warnings()


def get_block_tools(db_manager, wazuh_config, policies):

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

    def _log_action(action_type, target, reason, duration,
                    alert_id, success):
        db_manager.execute("""
            INSERT INTO actions_taken
                (alert_id, action_type, target, reason,
                 duration_seconds, success, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, [alert_id, action_type, target, reason,
              duration, success, datetime.utcnow().isoformat()])

    # ─────────────────────────────────────────
    @tool
    def block_ip_firewall(ip_address: str, duration_seconds: int,
                        reason: str, alert_id: str, allow_internal: bool = True) -> str:
        """
        Block an IP address using iptables (Ubuntu) and Windows Firewall via SSH.
        The block is automatically removed after the specified duration.
        Args:
            ip_address: IP to block
            duration_seconds: How long to block (policy: LOW=30, MED=60,
                            HIGH=300, CRITICAL=3600)
            reason: Why this IP is being blocked (for audit log)
            alert_id: The alert that triggered this action
        Returns:
            JSON with success/failure and details
        """
        import subprocess
        import threading
        import paramiko
        results = {}

        # ── Block on Ubuntu (iptables) ─────────────────────────
        try:
            subprocess.run(
                ["sudo", "iptables", "-I", "INPUT", "1", "-s", ip_address, "-j", "DROP"],
                check=True, capture_output=True, text=True
            )
            results["ubuntu"] = {"status": "success", "message": f"Blocked {ip_address} on Ubuntu."}

            def remove_ubuntu():
                try:
                    subprocess.run(
                        ["sudo", "iptables", "-D", "INPUT", "-s", ip_address, "-j", "DROP"],
                        check=True, capture_output=True, text=True
                    )
                    print(f"[INFO] Removed iptables block for {ip_address}.", flush=True)
                except Exception as e:
                    print(f"[ERROR] Failed to remove iptables block: {e}", flush=True)

            threading.Timer(duration_seconds, remove_ubuntu).start()

        except Exception as e:
            results["ubuntu"] = {"status": "failed", "message": str(e)}

        # ── Block on Windows via SSH ───────────────────────────
        windows_host = "192.168.56.104"
        windows_user = "vboxuser"
        windows_password = "0000"    # adjust if needed

        rule_name = f"Block_{ip_address}"
        ps_add = (
            f'New-NetFirewallRule -DisplayName "{rule_name}" '
            f'-Direction Inbound -Action Block -RemoteAddress "{ip_address}"'
        )
        cmd_add = f'powershell -Command "{ps_add}"'

        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(windows_host, username=windows_user, password=windows_password, timeout=10)
            stdin, stdout, stderr = ssh.exec_command(cmd_add)
            exit_status = stdout.channel.recv_exit_status()
            if exit_status == 0:
                results["windows"] = {"status": "success", "message": f"Blocked {ip_address} on Windows."}
            else:
                error = stderr.read().decode()
                results["windows"] = {"status": "failed", "message": error}
            ssh.close()
        except Exception as e:
            results["windows"] = {"status": "error", "message": str(e)}

        # ── Schedule Windows unblock ───────────────────────────
        def remove_windows():
            try:
                ssh_rem = paramiko.SSHClient()
                ssh_rem.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh_rem.connect(windows_host, username=windows_user, password=windows_password, timeout=10)
                ps_del = f'Remove-NetFirewallRule -DisplayName "{rule_name}"'
                cmd_del = f'powershell -Command "{ps_del}"'
                stdin, stdout, stderr = ssh_rem.exec_command(cmd_del)
                if stdout.channel.recv_exit_status() == 0:
                    print(f"[INFO] Removed Windows firewall rule for {ip_address}.", flush=True)
                else:
                    print(f"[ERROR] Failed to remove Windows rule: {stderr.read().decode()}", flush=True)
                ssh_rem.close()
            except Exception as e:
                print(f"[ERROR] Exception while removing Windows rule: {e}", flush=True)

        threading.Timer(duration_seconds, remove_windows).start()

        overall = "success" if results.get("ubuntu", {}).get("status") == "success" else "failed"
        return json.dumps({"status": overall, "details": results})
    # ─────────────────────────────────────────
    @tool
    def disable_user_account(username: str, target_host: str,reason: str, alert_id: str) -> str:
        """
        Disable a compromised user account via Wazuh Active Response.
        Use ONLY when there is strong evidence of account compromise.
        Args:
            username: The account to disable
            target_host: Which host to run this on
            reason: Justification (required for audit)
            alert_id: The triggering alert ID
        Returns:
            JSON with result
        """
        # ── حماية: لا نعطّل حسابات النظام ──
        protected_accounts = ["root", "wazuh", "ubuntu", "admin",
                               "Administrator"]
        if username in protected_accounts:
            return json.dumps({
                "success":            False,
                "reason":             f"Cannot auto-disable protected account: {username}",
                "escalation_required": True
            })

        try:
            token = _get_token()

            # نجد الـ agent ID للـ target_host
            agent_resp = requests.get(
                f"{wazuh_url}/agents",
                headers={"Authorization": f"Bearer {token}"},
                params={"name": target_host},
                verify=False, timeout=10
            )
            agents = agent_resp.json()["data"]["affected_items"]
            if not agents:
                return json.dumps({"success": False,
                                   "reason": f"Agent {target_host} not found"})

            agent_id = agents[0]["id"]

            # إرسال Active Response command
            payload = {
                "command":   "disable-account",
                "arguments": [username],
                "agents_list": [agent_id]
            }
            resp = requests.put(
                f"{wazuh_url}/active-response",
                headers={"Authorization": f"Bearer {token}",
                         "Content-Type":  "application/json"},
                json=payload,
                verify=False, timeout=15
            )

            success = resp.status_code == 200
            _log_action("DISABLE_USER", f"{username}@{target_host}",
                        reason, 0, alert_id, success)

            return json.dumps({
                "success":     success,
                "username":    username,
                "target_host": target_host,
                "message": (f"Account {username} disabled on {target_host}"
                            if success else "Command failed")
            })

        except Exception as e:
            _log_action("DISABLE_USER", f"{username}@{target_host}",
                        reason, 0, alert_id, False)
            return json.dumps({"success": False, "error": str(e)})

    # ─────────────────────────────────────────
    @tool
    def escalate_to_analyst(alert_id: str, priority: str,
                             reason: str, summary: str) -> str:
        """
        Escalate an incident to a human Analyst (Tier-2).
        Use when: successful compromise detected, domain controller targeted,
        lateral movement found, or situation exceeds autonomous handling.
        Args:
            alert_id: Alert being escalated
            priority: CRITICAL / HIGH / MEDIUM
            reason: Why escalation is needed
            summary: Brief summary for the analyst
        Returns:
            JSON confirming escalation was logged
        """
        try:
            ticket_id = (f"ESC-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}"
                         f"-{alert_id[-4:]}")

            db_manager.execute("""
                INSERT INTO escalations
                    (ticket_id, alert_id, priority, reason,
                     summary, timestamp, status)
                VALUES (?, ?, ?, ?, ?, ?, 'OPEN')
            """, [ticket_id, alert_id, priority, reason,
                  summary, datetime.utcnow().isoformat()])

            _log_action("ESCALATE", "Analyst-Tier2", reason,
                        0, alert_id, True)

            print(f"\n{'='*60}")
            print(f"🚨 ESCALATION CREATED: {ticket_id}")
            print(f"   Priority : {priority}")
            print(f"   Alert ID : {alert_id}")
            print(f"   Reason   : {reason}")
            print(f"   Summary  : {summary}")
            print(f"{'='*60}\n")

            return json.dumps({
                "success":      True,
                "ticket_id":    ticket_id,
                "priority":     priority,
                "status":       "ESCALATED",
                "message":      f"Incident escalated. Ticket: {ticket_id}"
            })

        except Exception as e:
            return json.dumps({"success": False, "error": str(e)})

    # ─────────────────────────────────────────
    @tool
    def add_to_watchlist(ip_address: str, reason: str,
                         alert_id: str) -> str:
        """
        Add an IP to the monitoring watchlist for increased scrutiny.
        Use for suspicious but not yet confirmed malicious IPs.
        Args:
            ip_address: IP to watch
            reason: Why it's being watched
            alert_id: Triggering alert
        Returns:
            JSON confirmation
        """
        try:
            db_manager.execute("""
                INSERT OR REPLACE INTO watchlist
                    (ip, reason, alert_id, added_at, active)
                VALUES (?, ?, ?, ?, 1)
            """, [ip_address, reason, alert_id,
                  datetime.utcnow().isoformat()])

            _log_action("ADD_WATCHLIST", ip_address, reason,
                        0, alert_id, True)

            return json.dumps({
                "success":    True,
                "ip_address": ip_address,
                "message":    f"IP {ip_address} added to watchlist"
            })
        except Exception as e:
            return json.dumps({"success": False, "error": str(e)})

    return [
        block_ip_firewall,
        disable_user_account,
        escalate_to_analyst,
        add_to_watchlist,
    ]