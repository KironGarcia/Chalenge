import subprocess
import time
import psutil
from collections import defaultdict
import re
import json
import logging
from datetime import datetime
import threading

real_time_monitoring_active = False
monitoring_thread = None
last_journal_cursor = None

anomaly_detection_rules = {
    "failed_login": {
        "pattern": r"authentication failure|Failed password|Invalid user",
        "severity": "HIGH",
        "auto_action": "block_ip",
        "threshold": 3
    },
    "brute_force": {
        "pattern": r"sshd.*Failed password.*from",
        "severity": "CRITICAL", 
        "auto_action": "block_ip",
        "threshold": 5
    },
    "suspicious_file_access": {
        "pattern": r"permission denied|access denied",
        "severity": "MEDIUM",
        "auto_action": "isolate_process",
        "threshold": 1
    },
    "network_scan": {
        "pattern": r"nmap|masscan|scan|port.*scan",
        "severity": "HIGH",
        "auto_action": "create_firewall_rule",
        "threshold": 1
    }
}

def extract_ip_from_log(log_line: str) -> str:
    ip_pattern = r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"
    matches = re.findall(ip_pattern, log_line)
    return matches[0] if matches else None

def monitor_system_logs():
    logging.info("🔍 Iniciando monitoramento em tempo real")
    global last_journal_cursor, real_time_monitoring_active
    
    while real_time_monitoring_active:
        try:
            cmd = ["journalctl", "--since", "1 minute ago", "--no-pager", "--output", "json"]
            if last_journal_cursor:
                cmd.extend(["--after-cursor", last_journal_cursor])
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0 and result.stdout.strip():
                lines = result.stdout.strip().split("\n")
                for line in lines:
                    try:
                        log_entry = json.loads(line)
                        process_system_log_entry(log_entry)
                        last_journal_cursor = log_entry.get("__CURSOR__")
                    except:
                        continue
            
        except Exception as e:
            logging.error(f"Erro no monitoramento: {e}")
        
        time.sleep(10)

def process_system_log_entry(log_entry: dict):
    try:
        message = log_entry.get("MESSAGE", "")
        syslog_identifier = log_entry.get("SYSLOG_IDENTIFIER", "")
        
        structured_log = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "level": "INFO",
            "message": message,
            "source": f"system-{syslog_identifier.lower()}",
            "is_real": True
        }
        
        anomaly = detect_anomalies_real_time(structured_log)
        if anomaly:
            logging.warning(f"🚨 Anomalia detectada: {anomaly['rule']}")
            
    except Exception as e:
        logging.error(f"Erro processando log: {e}")

def detect_anomalies_real_time(log_entry: dict) -> dict:
    message = log_entry.get("message", "").lower()
    
    for rule_name, rule_config in anomaly_detection_rules.items():
        if re.search(rule_config["pattern"], message, re.IGNORECASE):
            return {
                "rule": rule_name,
                "severity": rule_config["severity"],
                "auto_action": rule_config["auto_action"]
            }
    return None

def start_real_time_monitoring():
    global real_time_monitoring_active, monitoring_thread
    
    if real_time_monitoring_active:
        return True
    
    real_time_monitoring_active = True
    monitoring_thread = threading.Thread(target=monitor_system_logs, daemon=True)
    monitoring_thread.start()
    
    logging.info("✅ Monitoramento em tempo real iniciado")
    return True

def stop_real_time_monitoring():
    global real_time_monitoring_active
    real_time_monitoring_active = False
    logging.info("🛑 Monitoramento em tempo real parado")
    return True
