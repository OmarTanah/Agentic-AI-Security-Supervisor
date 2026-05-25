

import os

def load_config() -> dict:
    return {
        "wazuh": {
            "url":      os.getenv("WAZUH_API_URL",  "https://192.168.56.103:55000"),
            "user":     os.getenv("WAZUH_USER",     "wazuh-wui"),
            "password": os.getenv("WAZUH_PASSWORD", "L8gghQKlIozUa.AhzFc.Wm3.lSPHkBE*"),
        },
        "wazuh_indexer": {
            "url":      os.getenv("WAZUH_INDEXER_URL", "https://192.168.56.103:9200"),
            "user":     os.getenv("INDEXER_USER",      "admin"),
            "password": os.getenv("INDEXER_PASSWORD",  ".2LDx2sWj0UwbR7VrlwQLerFJISE?qhN"),
        },
        "ollama": {
            "base_url": os.getenv("OLLAMA_BASE_URL", "http://192.168.56.1:11434"),
            "model":    os.getenv("OLLAMA_MODEL",    "gpt-oss:20b-cloud"),
        },
        # ── VirusTotal ──────────────────────────────────
        # احصل على API key مجاني من: https://www.virustotal.com
        # ثم شغّل: export VT_API_KEY="your_key_here"
        "virustotal": {
            "api_key": os.getenv("VT_API_KEY", ""),
        },
        "windows_vm": {
            "host":     os.getenv("WINDOWS_HOST",     "192.168.56.104"),
            "user":     os.getenv("WINDOWS_USER",     "vboxuser"),
            "password": os.getenv("WINDOWS_PASSWORD", "0000"),
        },
        "database": {
            "path":        os.getenv("DB_PATH",        "soc_agent.db"),
            "checkpoints": os.getenv("CHECKPOINTS_DB", "checkpoints.db"),
            "audit":       os.getenv("AUDIT_DB",       "audit.db"),
        },
        "flask": {
            "host":  os.getenv("FLASK_HOST", "0.0.0.0"),
            "port":  int(os.getenv("FLASK_PORT", 5001)),
            "debug": False,
        },
        "triage": {
            "fp_auto_close": float(os.getenv("FP_AUTO_CLOSE", 0.85)),
            "fp_uncertain":  float(os.getenv("FP_UNCERTAIN",  0.50)),
            "scores": {
                "critical": int(os.getenv("PRIORITY_CRITICAL", 40)),
                "high":     int(os.getenv("PRIORITY_HIGH",     25)),
                "medium":   int(os.getenv("PRIORITY_MEDIUM",   15)),
            }
        },
        "polling_interval_seconds":   int(os.getenv("POLL_INTERVAL",       30)),
        "correlation_window_minutes": int(os.getenv("CORRELATION_WINDOW",  30)),
        "internal_ips":               ["10.", "172.16.", "192.168.56.103"],
        "known_malicious_ips":        [
            ip.strip()
            for ip in os.getenv("KNOWN_MALICIOUS_IPS", "").split(",")
            if ip.strip()
        ],
        "aggregation_window_seconds": int(os.getenv("AGGREGATION_WINDOW", 5))
    }