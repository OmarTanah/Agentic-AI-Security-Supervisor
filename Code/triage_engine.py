import json
from datetime import datetime


class TriageEngine:
    """
    محرك التصنيف الكامل:
    1. FP Assessment
    2. Priority Scoring (مع Privilege Escalation)
    3. Escalation Decision
    """

    FP_INDICATORS = {
        "ip_is_whitelisted":          0.70,
        "is_recurring_pattern":       0.35,
        "is_internal_ip":             0.20,
        "no_threat_intel":            0.15,
        "is_business_hours_internal": 0.10,
    }
    

    TP_INDICATORS = {
        "vt_malicious_gt_20":             -0.55,
        "vt_malicious_gt_10":             -0.40,
        "abuse_score_gt_80":              -0.40,
        "successful_auth_after_failures": -0.80,
        "privilege_escalation_success":   -0.80,
        "targeting_privileged_account":   -0.30,
        "outside_business_hours":         -0.40,
        "multiple_targets":               -0.60,
        "ip_is_tor":                      -0.35,
        "ip_is_vpn":                      -0.20,
        "high_volume_attack":             -0.90,
    }

    ASSET_WEIGHTS = {
        "CRITICAL": 15,
        "HIGH":     10,
        "MEDIUM":    5,
        "LOW":       2,
        "UNKNOWN":   3,
    }

    def __init__(self, policies: dict):
        self.policies  = policies
        self.fp_thresh = policies.get("fp_thresholds", {
            "close_as_fp_above":  0.70,
            "confirmed_tp_below": 0.30
        })
        self.p_thresh = policies.get("priority_thresholds", {
            "CRITICAL": 40, "HIGH": 25, "MEDIUM": 15, "LOW": 0
        })

    def run(self, alert: dict, context: dict) -> dict:
        fp_assessment = self._assess_fp(alert, context)
        priority      = self._score_priority(alert, context, fp_assessment)
        escalation    = self._decide_escalation(alert, context, fp_assessment, priority)
        return {
            "fp_assessment": fp_assessment,
            "priority":      priority,
            "escalation":    escalation,
            "timestamp":     datetime.utcnow().isoformat(),
        }

    def _assess_fp(self, alert: dict, context: dict) -> dict:
        source_ip = alert.get("source_ip", "")
    
    # # التعديل لـ IP كالي الجديد
    #     if source_ip == "192.168.56.105":
    #         return {
    #             "verdict": "TRUE_POSITIVE",
    #             "confidence": 1.0,
    #             "reason": "LAB_OVERRIDE: Known hostile Kali IP (192.168.56.105)",
    #             "fp_probability": 0.0
    #         }
        score   = 0.50
        reasons = []

        # ── Override: known test threat ──────────────────
        if context.get("is_known_test_threat"):
            return {
                "fp_probability": 0.0,
                "verdict":        "TRUE_POSITIVE",
                "confidence":     1.0,
                "reasons":        ["IP is a known test threat — forced True Positive"],
            }

        # ── Override: Privilege Escalation ناجح ──────────
        if alert.get("rule_id") in [5402, 5403]:
            return {
                "fp_probability": 0.0,
                "verdict":        "TRUE_POSITIVE",
                "confidence":     1.0,
                "reasons":        [
                    f"Successful privilege escalation detected "
                    f"(rule {alert.get('rule_id')}) — forced True Positive"
                ],
            }

        # ── مؤشرات FP ────────────────────────────────────
        if context.get("ip_is_whitelisted"):
            score += self.FP_INDICATORS["ip_is_whitelisted"]
            reasons.append("IP is in approved whitelist (+0.70)")

        if context.get("is_recurring_pattern"):
            score += self.FP_INDICATORS["is_recurring_pattern"]
            reasons.append("Recurring daily pattern detected (+0.35)")

        if (context.get("is_internal_ip") and
                context.get("vt_malicious_count", 0) == 0):
            score += self.FP_INDICATORS["is_internal_ip"]
            reasons.append("Internal IP with no threat intel (+0.20)")

        if (context.get("vt_malicious_count", 0) == 0 and
                context.get("abuse_confidence_score", 0) < 20):
            score += self.FP_INDICATORS["no_threat_intel"]
            reasons.append("No threat intelligence hits (+0.15)")

        if (context.get("is_business_hours") and
                context.get("is_internal_ip")):
            score += self.FP_INDICATORS["is_business_hours_internal"]
            reasons.append("Business hours internal activity (+0.10)")

        # ── مؤشرات TP ────────────────────────────────────
        vt_count = context.get("vt_malicious_count", 0)
        if vt_count > 20:
            score += self.TP_INDICATORS["vt_malicious_gt_20"]
            reasons.append(f"VT: {vt_count} malicious detections (-0.55)")
        elif vt_count > 10:
            score += self.TP_INDICATORS["vt_malicious_gt_10"]
            reasons.append(f"VT: {vt_count} malicious detections (-0.40)")

        if context.get("abuse_confidence_score", 0) > 80:
            score += self.TP_INDICATORS["abuse_score_gt_80"]
            reasons.append(
                f"AbuseIPDB: {context['abuse_confidence_score']}% (-0.40)"
            )

        if context.get("has_successful_auth"):
            score += self.TP_INDICATORS["successful_auth_after_failures"]
            reasons.append("CRITICAL: Successful login after failures (-0.80)")

        target_user = alert.get("target_user", "").lower()
        if target_user in ["root", "admin", "administrator"]:
            score += self.TP_INDICATORS["targeting_privileged_account"]
            reasons.append(f"Targeting privileged account: {target_user} (-0.30)")

        if not context.get("is_business_hours"):
            score += self.TP_INDICATORS["outside_business_hours"]
            reasons.append("Activity outside business hours (-0.15)")

        if context.get("ip_unique_targets_24h", 0) > 3:
            score += self.TP_INDICATORS["multiple_targets"]
            reasons.append(
                f"Attacking {context['ip_unique_targets_24h']} targets in 24h (-0.40)"
            )

        if context.get("ip_is_tor"):
            score += self.TP_INDICATORS["ip_is_tor"]
            reasons.append("Source is TOR exit node (-0.35)")

        if context.get("similar_alerts_last_hour", 0) > 50:
            score += self.TP_INDICATORS["high_volume_attack"]
            reasons.append(
                f"High volume: {context['similar_alerts_last_hour']} alerts/hour (-0.30)"
            )

        final_score = max(0.0, min(1.0, score))

        if final_score > self.fp_thresh["close_as_fp_above"]:
            verdict = "FALSE_POSITIVE"
        elif final_score < self.fp_thresh["confirmed_tp_below"]:
            verdict = "TRUE_POSITIVE"
        else:
            verdict = "UNCERTAIN"

        confidence = abs(final_score - 0.5) * 2

        return {
            "fp_probability": round(final_score, 3),
            "verdict":        verdict,
            "confidence":     round(confidence, 3),
            "reasons":        reasons,
        }

    def _score_priority(self, alert: dict, context: dict, fp: dict) -> dict:

        # ── Override: known test threat ──────────────────
        if context.get("is_known_test_threat"):
            return {
                "level":       "CRITICAL",
                "score":       60,
                "breakdown":   {"test_threat": 60},
                "explanation": "Known test threat — forced Critical",
            }

        # ── Override: Privilege Escalation ناجح ──────────
        if alert.get("rule_id") in [5402, 5403]:
            return {
                "level":       "CRITICAL",
                "score":       60,
                "breakdown":   {"privilege_escalation_success": 60},
                "explanation": "Successful privilege escalation — forced Critical",
            }

        # ── FP واضح → لا أولوية ──────────────────────────
        if fp["verdict"] == "FALSE_POSITIVE" and fp["confidence"] > 0.70:
            return {
                "level":       "NONE",
                "score":       0,
                "breakdown":   {},
                "explanation": "Classified as False Positive"
            }

        score     = 0
        breakdown = {}

        # عامل 1: Wazuh Severity
        sev = alert.get("severity_level", 0)
        score            += sev
        breakdown["wazuh_severity"] = sev

        # عامل 2: Asset Criticality
        asset_score = self.ASSET_WEIGHTS.get(
            context.get("asset_criticality", "UNKNOWN"), 3
        )
        score            += asset_score
        breakdown["asset_criticality"] = asset_score

        # عامل 3: Threat Intelligence
        vt = context.get("vt_malicious_count", 0)
        ab = context.get("abuse_confidence_score", 0)
        if vt > 20:
            score += 15; breakdown["threat_intel_vt"] = 15
        elif vt > 10:
            score += 10; breakdown["threat_intel_vt"] = 10
        if ab > 80:
            score += 8;  breakdown["threat_intel_abuse"] = 8
        elif ab > 50:
            score += 4;  breakdown["threat_intel_abuse"] = 4

        # عامل 4: Successful Compromise
        if context.get("has_successful_auth"):
            score += 30
            breakdown["successful_compromise"] = 30

        # عامل 5: Privilege Escalation محاولة فاشلة
        if alert.get("rule_id") in [5400, 5401]:
            score += 15
            breakdown["privilege_escalation_attempt"] = 15

        # عامل 6: حساب مميز
        if alert.get("target_user", "").lower() in ["root", "admin", "administrator"]:
            score += 8
            breakdown["privileged_target"] = 8

        # عامل 7: Domain Controller
        if context.get("asset_is_domain_controller"):
            score += 15
            breakdown["domain_controller_target"] = 15

        # عامل 8: خارج أوقات العمل
        if not context.get("is_business_hours"):
            score += 5
            breakdown["after_hours"] = 5

        # عامل 9: حجم الهجوم
        vol = context.get("similar_alerts_last_hour", 0)
        if   vol > 100: score += 10; breakdown["high_volume"]   = 10
        elif vol > 50:  score += 5;  breakdown["medium_volume"] = 5

        # عامل 10: TOR
        if context.get("ip_is_tor"):
            score += 5; breakdown["tor_source"] = 5

        if   score >= self.p_thresh["CRITICAL"]: level = "CRITICAL"
        elif score >= self.p_thresh["HIGH"]:     level = "HIGH"
        elif score >= self.p_thresh["MEDIUM"]:   level = "MEDIUM"
        else:                                    level = "LOW"

        return {
            "level":       level,
            "score":       score,
            "breakdown":   breakdown,
            "explanation": self._build_priority_explanation(breakdown),
        }

    def _build_priority_explanation(self, breakdown: dict) -> str:
        labels = {
            "wazuh_severity":                "Wazuh severity",
            "asset_criticality":             "Asset criticality",
            "threat_intel_vt":               "VirusTotal hits",
            "threat_intel_abuse":            "AbuseIPDB score",
            "successful_compromise":         "Successful compromise",
            "privilege_escalation_success":  "Privilege escalation success",
            "privilege_escalation_attempt":  "Privilege escalation attempt",
            "privileged_target":             "Privileged account targeted",
            "domain_controller_target":      "Domain controller targeted",
            "after_hours":                   "Outside business hours",
            "high_volume":                   "High attack volume",
            "medium_volume":                 "Medium attack volume",
            "tor_source":                    "TOR exit node",
        }
        parts = [f"{labels.get(k, k)}: +{v}" for k, v in breakdown.items()]
        return " | ".join(parts) if parts else "No factors"

    def _decide_escalation(self, alert: dict, context: dict,
                            fp: dict, priority: dict) -> dict:
        mandatory = self.policies.get("mandatory_escalation_triggers", {})
        reasons   = []

        # ── Privilege Escalation ناجح ─────────────────────
        if alert.get("rule_id") in [5402, 5403]:
            reasons.append(
                f"Successful privilege escalation (rule {alert.get('rule_id')})"
            )

        # ── Successful auth بعد failures ──────────────────
        if (context.get("has_successful_auth") and
                mandatory.get("successful_auth_after_failures", True)):
            reasons.append("Successful authentication after brute force")

        # ── Domain Controller ─────────────────────────────
        if (context.get("asset_is_domain_controller") and
                mandatory.get("target_is_domain_controller", True)):
            reasons.append("Target is a Domain Controller")

        # ── Lateral Movement ──────────────────────────────
        if (context.get("ip_unique_targets_24h", 0) > 3 and
                mandatory.get("lateral_movement_detected", True)):
            reasons.append(
                f"Lateral movement — {context['ip_unique_targets_24h']} targets in 24h"
            )

        if reasons:
            return {
                "decision": "ESCALATE",
                "urgency":  "IMMEDIATE",
                "reasons":  reasons,
                "tier":     2,
            }

        if priority["level"] == "CRITICAL":
            return {
                "decision": "ESCALATE",
                "urgency":  "HIGH",
                "reasons":  ["Alert scored CRITICAL priority"],
                "tier":     2,
            }

        if (fp["verdict"] == "UNCERTAIN" and
                priority["level"] in ["HIGH", "CRITICAL"]):
            return {
                "decision": "ESCALATE",
                "urgency":  "MEDIUM",
                "reasons":  ["High/Critical priority with uncertain FP classification"],
                "tier":     2,
            }

        return {
            "decision": "HANDLE_AUTONOMOUSLY",
            "urgency":  priority["level"],
            "reasons":  ["Within autonomous handling parameters"],
            "tier":     1,
        }