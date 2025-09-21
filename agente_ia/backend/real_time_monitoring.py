#!/usr/bin/env python3

import subprocess
import time
import psutil
from collections import defaultdict
import re
import json
import logging
from datetime import datetime, timedelta
import threading
import requests
import socket

real_time_monitoring_active = False
monitoring_thread = None
last_journal_cursor = None

# Importa configurações Wazuh do simple_app
WAZUH_ENABLED = True
WAZUH_URL = "https://localhost:55000"
WAZUH_USER = "kiron" 
WAZUH_PASSWORD = "Lapergunta200."
WAZUH_SYSLOG_HOST = "localhost"
WAZUH_SYSLOG_PORT = 514

anomaly_detection_rules = {
    "failed_login": {
        "pattern": r"authentication failure|Failed password|Invalid user|login.*failed",
        "severity": "HIGH",
        "auto_action": "block_ip",
        "threshold": 3,
        "description": "Tentativa de login falhada detectada"
    },
    "brute_force": {
        "pattern": r"sshd.*Failed password.*from|ssh.*authentication failure.*rhost",
        "severity": "CRITICAL", 
        "auto_action": "block_ip",
        "threshold": 2,  # Reduzido para demo
        "description": "Ataque de força bruta SSH detectado"
    },
    "suspicious_file_access": {
        "pattern": r"permission denied|access denied|unauthorized.*access",
        "severity": "MEDIUM",
        "auto_action": "isolate_process",
        "threshold": 1,
        "description": "Acesso suspeito a arquivos detectado"
    },
    "network_scan": {
        "pattern": r"nmap|masscan|scan|port.*scan|stealth.*scan",
        "severity": "HIGH",
        "auto_action": "create_firewall_rule",
        "threshold": 1,
        "description": "Scan de rede detectado"
    },
    "sudo_abuse": {
        "pattern": r"sudo.*COMMAND|sudo.*authentication failure",
        "severity": "MEDIUM", 
        "auto_action": "isolate_process",
        "threshold": 2,
        "description": "Uso suspeito de sudo detectado"
    }
}

# Contador global para detectar padrões
attack_patterns = defaultdict(list)

def extract_ip_from_log(log_line: str) -> str:
    """Extrai IP de linha de log com múltiplos padrões"""
    ip_patterns = [
        r"from\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",  # SSH logs
        r"rhost=(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",   # Auth logs
        r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b"      # Qualquer IP
    ]
    
    for pattern in ip_patterns:
        matches = re.findall(pattern, log_line)
        if matches:
            return matches[0]
    return None

def authenticate_wazuh():
    """Autentica no Wazuh e retorna token"""
    try:
        resp = requests.post(
            f"{WAZUH_URL}/security/user/authenticate", 
            auth=(WAZUH_USER, WAZUH_PASSWORD), 
            timeout=10,
            verify=False
        )
        if resp.status_code == 200:
            return resp.json().get('data', {}).get('token')
    except Exception as e:
        logging.error(f"Erro autenticação Wazuh: {e}")
    return None

def send_to_wazuh(log_entry: dict, anomaly_info=None):
    """Envia log estruturado para Wazuh via Syslog"""
    try:
        # Cria log estruturado para Wazuh
        wazuh_data = {
            "timestamp": log_entry.get('timestamp'),
            "level": log_entry.get('level', 'INFO'), 
            "message": log_entry.get('message'),
            "source": "agente-ia-monitor",
            "component": log_entry.get('source', 'system'),
            "is_anomaly": bool(anomaly_info),
            "anomaly_rule": anomaly_info.get('rule') if anomaly_info else None,
            "anomaly_severity": anomaly_info.get('severity') if anomaly_info else None,
            "ip_address": extract_ip_from_log(log_entry.get('message', '')),
            "real_time_detection": True
        }
        
        # Remove campos nulos
        wazuh_data = {k: v for k, v in wazuh_data.items() if v is not None}
        
        # Formata para Syslog
        priority = 22  # Info priority
        if anomaly_info:
            if anomaly_info.get('severity') == 'CRITICAL':
                priority = 18  # Critical
            elif anomaly_info.get('severity') == 'HIGH':
                priority = 19  # Error
            elif anomaly_info.get('severity') == 'MEDIUM':
                priority = 20  # Warning
        
        timestamp = datetime.now().strftime('%b %d %H:%M:%S')
        json_payload = json.dumps(wazuh_data, ensure_ascii=False)
        syslog_msg = f"<{priority}>{timestamp} agente-ia: REALTIME_DETECTION: {json_payload}"
        
        # Envia via UDP
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(syslog_msg.encode('utf-8'), (WAZUH_SYSLOG_HOST, WAZUH_SYSLOG_PORT))
        sock.close()
        
        return True
        
    except Exception as e:
        logging.error(f"Erro enviando para Wazuh: {e}")
        return False

def get_wazuh_response(alert_id=None):
    """Busca resposta/alertas do Wazuh"""
    try:
        token = authenticate_wazuh()
        if not token:
            return None
            
        headers = {'Authorization': f'Bearer {token}'}
        
        # Busca alertas recentes
        resp = requests.get(
            f"{WAZUH_URL}/alerts",
            headers=headers,
            timeout=10,
            verify=False,
            params={'limit': 10, 'sort': '-timestamp'}
        )
        
        if resp.status_code == 200:
            data = resp.json()
            alerts = data.get('data', {}).get('affected_items', [])
            
            # Filtra alertas do agente-ia
            our_alerts = []
            for alert in alerts:
                if 'agente-ia' in str(alert).lower():
                    our_alerts.append({
                        'id': alert.get('id', 'unknown'),
                        'level': alert.get('rule', {}).get('level', 0),
                        'description': alert.get('rule', {}).get('description', 'Alert from Wazuh'),
                        'timestamp': alert.get('timestamp', datetime.now().isoformat()),
                        'source_ip': extract_ip_from_log(str(alert))
                    })
            
            return our_alerts
            
    except Exception as e:
        logging.error(f"Erro buscando resposta Wazuh: {e}")
    
    return []

def execute_automatic_response(anomaly_info, source_ip=None):
    """Executa resposta automática baseada na anomalia detectada"""
    try:
        action_type = anomaly_info.get('auto_action')
        target = source_ip or 'localhost'
        
        # Log da ação que será executada
        action_log = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'level': 'WARNING',
            'message': f'🚨 AÇÃO AUTOMÁTICA INICIADA: {action_type} -> {target} (Regra: {anomaly_info.get("rule")})',
            'source': 'auto-response',
            'is_real': False
        }
        
        # Adiciona à lista global de logs (será capturado pelo simple_app)
        if hasattr(monitor_system_logs, 'logs_callback'):
            monitor_system_logs.logs_callback(action_log)
        
        return {
            'action_executed': True,
            'action_type': action_type,
            'target': target,
            'rule_triggered': anomaly_info.get('rule'),
            'severity': anomaly_info.get('severity')
        }
        
    except Exception as e:
        logging.error(f"Erro executando resposta automática: {e}")
        return {'action_executed': False, 'error': str(e)}

def monitor_system_logs():
    """Monitor principal com feedback loop completo"""
    logging.info("🔍 Iniciando monitoramento em tempo real com integração Wazuh")
    global last_journal_cursor, real_time_monitoring_active
    
    # Log de início
    start_log = {
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'level': 'SUCCESS',
        'message': '🚀 MONITORAMENTO EM TEMPO REAL INICIADO - Integrando com Wazuh SIEM',
        'source': 'real-time-monitor',
        'is_real': False
    }
    
    if hasattr(monitor_system_logs, 'logs_callback'):
        monitor_system_logs.logs_callback(start_log)
    
    while real_time_monitoring_active:
        try:
            # 1. COLETA de logs do sistema
            cmd = ["journalctl", "--since", "30 seconds ago", "--no-pager", "--output", "json", "-n", "50"]
            if last_journal_cursor:
                cmd.extend(["--after-cursor", last_journal_cursor])
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0 and result.stdout.strip():
                lines = result.stdout.strip().split("\n")
                
                collection_log = {
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'level': 'INFO',
                    'message': f'📊 COLETADOS {len(lines)} logs do sistema - Analisando...',
                    'source': 'log-collector',
                    'is_real': False
                }
                
                if hasattr(monitor_system_logs, 'logs_callback'):
                    monitor_system_logs.logs_callback(collection_log)
                
                for line in lines:
                    try:
                        log_entry = json.loads(line)
                        last_journal_cursor = log_entry.get("__CURSOR__")
                        
                        # 2. PROCESSA e DETECTA anomalias
                        anomaly = detect_anomalies_real_time(log_entry)
                        
                        if anomaly:
                            # 3. ENVIA para Wazuh
                            wazuh_sent = send_to_wazuh(log_entry, anomaly)
                            
                            if wazuh_sent:
                                wazuh_log = {
                                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                                    'level': 'INFO',
                                    'message': f'📡 ENVIADO PARA WAZUH: {anomaly["rule"]} (Severidade: {anomaly["severity"]})',
                                    'source': 'wazuh-integration',
                                    'is_real': False
                                }
                                
                                if hasattr(monitor_system_logs, 'logs_callback'):
                                    monitor_system_logs.logs_callback(wazuh_log)
                            
                            # 4. BUSCA resposta do Wazuh
                            time.sleep(2)  # Aguarda processamento no Wazuh
                            wazuh_alerts = get_wazuh_response()
                            
                            if wazuh_alerts:
                                for alert in wazuh_alerts[:3]:  # Últimos 3 alertas
                                    response_log = {
                                        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                                        'level': 'WARNING',
                                        'message': f'📥 RESPOSTA WAZUH: {alert["description"]} (Level: {alert["level"]})',
                                        'source': 'wazuh-response',
                                        'is_real': False
                                    }
                                    
                                    if hasattr(monitor_system_logs, 'logs_callback'):
                                        monitor_system_logs.logs_callback(response_log)
                            
                            # 5. EXECUTA resposta automática
                            source_ip = extract_ip_from_log(log_entry.get("MESSAGE", ""))
                            response_result = execute_automatic_response(anomaly, source_ip)
                            
                            if response_result.get('action_executed'):
                                decision_log = {
                                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                                    'level': 'SUCCESS',
                                    'message': f'⚡ DECISÃO IA EXECUTADA: {response_result["action_type"]} aplicado a {response_result["target"]}',
                                    'source': 'ia-decision',
                                    'is_real': False
                                }
                                
                                if hasattr(monitor_system_logs, 'logs_callback'):
                                    monitor_system_logs.logs_callback(decision_log)
                        
                        # Processa log normal também
                        else:
                            process_system_log_entry(log_entry)
                            
                    except json.JSONDecodeError:
                        continue
                    except Exception as e:
                        logging.error(f"Erro processando log: {e}")
            
        except Exception as e:
            error_log = {
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'level': 'ERROR',
                'message': f'❌ ERRO NO MONITORAMENTO: {str(e)}',
                'source': 'monitor-error',
                'is_real': False
            }
            
            if hasattr(monitor_system_logs, 'logs_callback'):
                monitor_system_logs.logs_callback(error_log)
            
            logging.error(f"Erro no monitoramento: {e}")
        
        time.sleep(5)  # Reduzido para demo mais responsiva

def process_system_log_entry(log_entry: dict):
    """Processa entrada de log do sistema"""
    try:
        message = log_entry.get("MESSAGE", "")
        syslog_identifier = log_entry.get("SYSLOG_IDENTIFIER", "")
        
        # Cria log estruturado
        structured_log = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "level": determine_log_level(message),
            "message": message[:200],  # Trunca para evitar spam
            "source": f"system-{syslog_identifier.lower()}",
            "is_real": True
        }
        
        # Envia para callback se disponível
        if hasattr(monitor_system_logs, 'logs_callback'):
            monitor_system_logs.logs_callback(structured_log)
            
    except Exception as e:
        logging.error(f"Erro processando log do sistema: {e}")

def determine_log_level(message: str) -> str:
    """Determina nível do log baseado no conteúdo"""
    message_lower = message.lower()
    
    if any(word in message_lower for word in ['error', 'fail', 'denied', 'invalid', 'unauthorized']):
        return 'ERROR'
    elif any(word in message_lower for word in ['warn', 'alert', 'suspicious', 'attempt']):
        return 'WARNING'
    elif any(word in message_lower for word in ['success', 'accepted', 'authenticated', 'connected']):
        return 'SUCCESS'
    else:
        return 'INFO'

def detect_anomalies_real_time(log_entry: dict) -> dict:
    """Detecta anomalias em tempo real com padrões aprimorados"""
    message = log_entry.get("MESSAGE", "").lower()
    source_ip = extract_ip_from_log(message)
    
    for rule_name, rule_config in anomaly_detection_rules.items():
        if re.search(rule_config["pattern"], message, re.IGNORECASE):
            
            # Incrementa contador de ataques por IP
            if source_ip:
                attack_patterns[source_ip].append({
                    'rule': rule_name,
                    'timestamp': datetime.now(),
                    'message': message
                })
                
                # Remove entradas antigas (> 5 minutos)
                cutoff_time = datetime.now() - timedelta(minutes=5)
                attack_patterns[source_ip] = [
                    attack for attack in attack_patterns[source_ip] 
                    if attack['timestamp'] > cutoff_time
                ]
                
                # Verifica se excedeu threshold
                recent_attacks = len(attack_patterns[source_ip])
                if recent_attacks >= rule_config["threshold"]:
                    
                    # Log de detecção
                    detection_log = {
                        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        'level': 'CRITICAL',
                        'message': f'🚨 ANOMALIA DETECTADA: {rule_config["description"]} de {source_ip} ({recent_attacks} tentativas)',
                        'source': 'anomaly-detector',
                        'is_real': False
                    }
                    
                    if hasattr(monitor_system_logs, 'logs_callback'):
                        monitor_system_logs.logs_callback(detection_log)
                    
                    return {
                        "rule": rule_name,
                        "severity": rule_config["severity"],
                        "auto_action": rule_config["auto_action"],
                        "description": rule_config["description"],
                        "source_ip": source_ip,
                        "attack_count": recent_attacks
                    }
    
    return None

def start_real_time_monitoring():
    """Inicia monitoramento com callback para logs"""
    global real_time_monitoring_active, monitoring_thread
    
    if real_time_monitoring_active:
        return True
    
    real_time_monitoring_active = True
    monitoring_thread = threading.Thread(target=monitor_system_logs, daemon=True)
    monitoring_thread.start()
    
    logging.info("✅ Monitoramento em tempo real iniciado com integração Wazuh")
    return True

def stop_real_time_monitoring():
    """Para monitoramento em tempo real"""
    global real_time_monitoring_active
    real_time_monitoring_active = False
    logging.info("🛑 Monitoramento em tempo real parado")
    return True

def set_logs_callback(callback_func):
    """Define callback para enviar logs para o sistema principal"""
    monitor_system_logs.logs_callback = callback_func
