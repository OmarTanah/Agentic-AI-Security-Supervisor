import json
from datetime import datetime
from langchain.tools import tool


def get_report_tools(db_manager):

    @tool
    def save_investigation_note(alert_id: str, note: str,
                                step: str) -> str:
        """
        Save a note during the investigation process.
        Use this to document important findings as you investigate.
        Args:
            alert_id: The alert being investigated
            note: Your finding or observation
            step: Which step (ENRICH / CORRELATE / ASSESS / DECIDE)
        Returns:
            Confirmation string
        """
        try:
            db_manager.execute("""
                INSERT INTO investigation_logs
                    (alert_id, step, note, timestamp)
                VALUES (?, ?, ?, ?)
            """, [alert_id, step, note,
                  datetime.utcnow().isoformat()])
            return json.dumps({"saved": True, "step": step})
        except Exception as e:
            return json.dumps({"saved": False, "error": str(e)})

    @tool
    def get_investigation_history(alert_id: str) -> str:
        """
        Retrieve all previously saved investigation notes for an alert.
        Args:
            alert_id: The alert to get history for
        Returns:
            JSON with all notes in order
        """
        try:
            rows = db_manager.query("""
                SELECT step, note, timestamp
                FROM investigation_logs
                WHERE alert_id = ?
                ORDER BY timestamp ASC
            """, [alert_id])

            notes = [dict(r) for r in rows]
            return json.dumps({
                "alert_id": alert_id,
                "notes_count": len(notes),
                "notes": notes
            }, ensure_ascii=False, indent=2)
        except Exception as e:
            return json.dumps({"error": str(e)})
    

    @tool
    def get_policies() -> str:
        """Retrieve the current SOC response policies.
        These policies are based on NIST 800-53 and MITRE ATT&CK.
        Call this tool whenever you need to determine how to respond to a specific threat.
        Returns:
            JSON string with all policy rules
        """
        import os, json
        # Go up one level from tools/ to the project root
        root_dir = os.path.dirname(os.path.dirname(__file__))
        policy_path = os.path.join(root_dir, "policies.json")
        try:
            with open(policy_path, "r") as f:
                policies = json.load(f)
            return json.dumps(policies, ensure_ascii=False, indent=2)
        except Exception as e:
            return json.dumps({"error": str(e)})

    @tool
    def close_alert_as_fp(alert_id: str, reason: str) -> str:
        """
        Mark an alert as a confirmed False Positive and close it.
        Use ONLY when you have clear evidence it's not a real threat.
        Args:
            alert_id: Alert to close
            reason: Clear justification for FP classification
        Returns:
            JSON confirmation
        """
        try:
            db_manager.execute("""
                UPDATE alerts
                SET status = 'CLOSED_FP',
                    resolution = ?,
                    resolved_at = ?
                WHERE id = ?
            """, [reason, datetime.utcnow().isoformat(), alert_id])

            return json.dumps({
                "success":    True,
                "alert_id":   alert_id,
                "status":     "CLOSED_FP",
                "reason":     reason,
                "message":    f"Alert {alert_id} closed as False Positive"
            })
        except Exception as e:
            return json.dumps({"success": False, "error": str(e)})

    return [
        save_investigation_note,
        get_investigation_history,
        close_alert_as_fp,
        get_policies,
    ]