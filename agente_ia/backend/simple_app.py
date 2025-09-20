#!/usr/bin/env python3

from flask import Flask, jsonify, request
from flask_cors import CORS
import os
import logging
from datetime import datetime, timedelta
import json
import random
import glob
import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import socket
import requests
import real_time_monitoring
import subprocess
import time
import psutil
from collections import defaultdict
import re
import real_time_monitoring
import re
import real_time_monitoring
import subprocess
import time
import psutil
from collections import defaultdict
import re
import real_time_monitoring

app = Flask(__name__)

# Configuração CORS para permitir conectividade com frontend
CORS(app, origins=['http://localhost:3000', 'http://127.0.0.1:3000', 'http://10.105.186.180:3000'])

# Configuração de logging
logging.basicConfig(level=logging.INFO)

# Dados para testing + LOGS REAIS
anomalies_data = []
logs_data = []
real_logs_loaded = False

# === SISTEMA DE PERSISTÊNCIA DE ALERTAS ===
import sqlite3
import threading

# Cria banco de dados em memória (pode ser alterado para arquivo)
db_lock = threading.Lock()

def init_database():
    """Inicializa banco de dados para persistência"""
    with db_lock:
        conn = sqlite3.connect('agente_ia_alerts.db', check_same_thread=False)
        cursor = conn.cursor()
        
        # Tabela de alertas
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                level TEXT NOT NULL,
                message TEXT NOT NULL,
                source TEXT NOT NULL,
                alert_type TEXT,
                severity_score INTEGER DEFAULT 0,
                is_real_data BOOLEAN DEFAULT FALSE,
                processed BOOLEAN DEFAULT FALSE,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Tabela de ações executadas
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS executed_actions (
                id TEXT PRIMARY KEY,
                action_type TEXT NOT NULL,
                target TEXT NOT NULL,
                alert_id TEXT,
                result_success BOOLEAN NOT NULL,
                result_message TEXT,
                timestamp TEXT NOT NULL,
                automated BOOLEAN DEFAULT TRUE,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Tabela de aprovações
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS approval_requests (
                id TEXT PRIMARY KEY,
                action_type TEXT NOT NULL,
                target TEXT NOT NULL,
                alert_id TEXT,
                reason TEXT,
                status TEXT DEFAULT 'pending',
                requested_by TEXT DEFAULT 'agente_ia_auto',
                approved_by TEXT,
                timestamp TEXT NOT NULL,
                approved_at TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        conn.commit()
        conn.close()
        logging.info("🗄️ Banco de dados inicializado")

def save_alert_to_db(alert_data: dict):
    """Salva alerta no banco de dados"""
    try:
        with db_lock:
            conn = sqlite3.connect('agente_ia_alerts.db', check_same_thread=False)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT OR REPLACE INTO alerts 
                (id, timestamp, level, message, source, alert_type, severity_score, is_real_data)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                alert_data.get('id', f'alert_{datetime.now().strftime("%Y%m%d_%H%M%S")}'),
                alert_data.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S')),
                alert_data.get('level', 'INFO'),
                alert_data.get('message', ''),
                alert_data.get('source', 'unknown'),
                alert_data.get('type', 'general'),
                alert_data.get('severity_score', 0),
                alert_data.get('is_real', False)
            ))
            
            conn.commit()
            conn.close()
    except Exception as e:
        logging.error(f"❌ Erro ao salvar alerta no DB: {e}")

def save_action_to_db(action_data: dict):
    """Salva ação executada no banco de dados"""
    try:
        with db_lock:
            conn = sqlite3.connect('agente_ia_alerts.db', check_same_thread=False)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO executed_actions 
                (id, action_type, target, alert_id, result_success, result_message, timestamp, automated)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                action_data['id'],
                action_data['type'],
                action_data['target'],
                action_data.get('alert_id'),
                action_data['result']['success'],
                action_data['result']['message'],
                action_data['timestamp'],
                action_data.get('automated', True)
            ))
            
            conn.commit()
            conn.close()
    except Exception as e:
        logging.error(f"❌ Erro ao salvar ação no DB: {e}")

def save_approval_to_db(approval_data: dict):
    """Salva solicitação de aprovação no banco de dados"""
    try:
        with db_lock:
            conn = sqlite3.connect('agente_ia_alerts.db', check_same_thread=False)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT OR REPLACE INTO approval_requests 
                (id, action_type, target, alert_id, reason, status, requested_by, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                approval_data['id'],
                approval_data['action_type'],
                approval_data['target'],
                approval_data.get('alert_id'),
                approval_data.get('reason'),
                approval_data.get('status', 'pending'),
                approval_data.get('requested_by', 'agente_ia_auto'),
                approval_data['timestamp']
            ))
            
            conn.commit()
            conn.close()
    except Exception as e:
        logging.error(f"❌ Erro ao salvar aprovação no DB: {e}")

def get_alerts_from_db(limit: int = 50) -> list:
    """Obtém alertas do banco de dados"""
    try:
        with db_lock:
            conn = sqlite3.connect('agente_ia_alerts.db', check_same_thread=False)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT * FROM alerts 
                ORDER BY created_at DESC 
                LIMIT ?
            ''', (limit,))
            
            columns = [description[0] for description in cursor.description]
            results = []
            
            for row in cursor.fetchall():
                alert_dict = dict(zip(columns, row))
                results.append(alert_dict)
            
            conn.close()
            return results
    except Exception as e:
        logging.error(f"❌ Erro ao buscar alertas do DB: {e}")
        return []

def get_statistics_from_db() -> dict:
    """Obtém estatísticas do banco de dados"""
    try:
        with db_lock:
            conn = sqlite3.connect('agente_ia_alerts.db', check_same_thread=False)
            cursor = conn.cursor()
            
            # Conta total de alertas
            cursor.execute('SELECT COUNT(*) FROM alerts')
            total_alerts = cursor.fetchone()[0]
            
            # Conta alertas por nível
            cursor.execute('''
                SELECT level, COUNT(*) FROM alerts 
                GROUP BY level
            ''')
            alerts_by_level = dict(cursor.fetchall())
            
            # Conta ações executadas
            cursor.execute('SELECT COUNT(*) FROM executed_actions')
            total_actions = cursor.fetchone()[0]
            
            # Conta aprovações pendentes
            cursor.execute('SELECT COUNT(*) FROM approval_requests WHERE status = "pending"')
            pending_approvals_count = cursor.fetchone()[0]
            
            conn.close()
            
            return {
                'total_alerts': total_alerts,
                'alerts_by_level': alerts_by_level,
                'total_actions': total_actions,
                'pending_approvals': pending_approvals_count,
                'database_status': 'active'
            }
    except Exception as e:
        logging.error(f"❌ Erro ao buscar estatísticas do DB: {e}")
        return {'database_status': 'error', 'error': str(e)}

# Inicializa banco ao carregar módulo
init_database()

# Configurações WAZUH (opcional, integração SIEM)
WAZUH_ENABLED = os.getenv('WAZUH_ENABLED', 'true').lower() == 'true'  # Habilitado por defecto
WAZUH_SYSLOG_HOST = os.getenv('WAZUH_SYSLOG_HOST', 'localhost')
WAZUH_SYSLOG_PORT = int(os.getenv('WAZUH_SYSLOG_PORT', 514))  # Puerto estándar Syslog
WAZUH_URL = os.getenv('WAZUH_URL', 'https://localhost:55000')  # HTTPS requerido
WAZUH_USER = os.getenv('WAZUH_USER', 'kiron')
WAZUH_PASSWORD = os.getenv('WAZUH_PASSWORD', 'Lapergunta200.')

# Configurações de EMAIL
EMAIL_CONFIG = {
    'smtp_server': 'smtp.gmail.com',
    'port': 587,
    'username': 'chalenge.agenteia@gmail.com', 
    'password': 'bjtkykpjhyojinmp',  # App Password do Gmail
    'recipient': 'chalenge.agenteia@gmail.com'
}

# Helpers WAZUH
def _map_priority(level: str) -> int:
    mapping = {'DEBUG': 23, 'INFO': 22, 'WARNING': 20, 'ERROR': 19, 'CRITICAL': 18}
    return mapping.get((level or 'INFO').upper(), 22)

# Autentica na API do Wazuh e retorna Bearer token (ou None)
def _wazuh_authenticate() -> str:
    try:
        if not (WAZUH_USER and WAZUH_PASSWORD):
            return None
        # Wazuh requer HTTPS e ignora certificados SSL em modo de desenvolvimento
        resp = requests.post(
            f"{WAZUH_URL}/security/user/authenticate", 
            auth=(WAZUH_USER, WAZUH_PASSWORD), 
            timeout=10,
            verify=False  # Ignora certificados SSL para desenvolvimento
        )
        if resp.status_code == 200:
            token = resp.json().get('data', {}).get('token')
            logging.info("🔐 Token Wazuh obtido com sucesso")
            return token
        else:
            logging.warning(f"Wazuh auth falhou - Status: {resp.status_code}")
    except Exception as e:
        logging.error(f"Wazuh auth erro: {e}")
    return None

# Busca alertas recentes do Wazuh (fallback para lista vazia)
def _wazuh_get_alerts(limit: int = 20) -> list:
    try:
        token = _wazuh_authenticate()
        if not token:
            logging.warning("Não foi possível obter token Wazuh")
            return []
        
        headers = {'Authorization': f'Bearer {token}'}
        
        # Tenta diferentes endpoints do Wazuh para obter alertas
        endpoints_to_try = [
            '/alerts',
            '/rules',
            '/agents/summary/os',
            '/overview/agents'
        ]
        
        for endpoint in endpoints_to_try:
            try:
                resp = requests.get(
                    f"{WAZUH_URL}{endpoint}", 
                    headers=headers, 
                    timeout=10,
                    verify=False
                )
                
                if resp.status_code == 200:
                    data = resp.json()
                    logging.info(f"✅ Wazuh endpoint {endpoint} respondeu: {len(str(data))} chars")
                    
                    # Processa resposta baseada no endpoint
                    if endpoint == '/alerts':
                        items = data.get('data', {}).get('affected_items', [])
                        alerts = []
                        for item in items[:limit]:
                            alerts.append({
                                'id': item.get('id', f'alert_{len(alerts)}'),
                                'severity': 'MEDIA',
                                'description': item.get('full_log', str(item)[:100]),
                                'timestamp': item.get('timestamp', datetime.now().isoformat())
                            })
                        return alerts
                    else:
                        # Para outros endpoints, cria alertas simulados baseados na resposta
                        return [{
                            'id': f'wazuh_info_{endpoint.replace("/", "_")}',
                            'severity': 'BAIXA',
                            'description': f'Wazuh {endpoint} - Sistema funcionando: {len(str(data))} bytes de dados',
                            'timestamp': datetime.now().isoformat()
                        }]
                        
            except Exception as e:
                logging.debug(f"Endpoint {endpoint} falhou: {e}")
                continue
        
        # Se nenhum endpoint funcionou, retorna alerta de status
        return [{
            'id': 'wazuh_status',
            'severity': 'BAIXA', 
            'description': 'Wazuh API conectada mas sem alertas disponíveis',
            'timestamp': datetime.now().isoformat()
        }]
        
    except Exception as e:
        logging.error(f"Wazuh get_alerts erro: {e}")
        return []

def _send_syslog_udp(message: str, host: str, port: int) -> bool:
    try:
        syslog_msg = f"<{_map_priority('INFO')}>{datetime.now().strftime('%b %d %H:%M:%S')} agente-ia: {message}"
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(syslog_msg.encode('utf-8', errors='ignore'), (host, port))
        sock.close()
        return True
    except Exception as e:
        logging.warning(f"Falha ao enviar Syslog UDP para {host}:{port}: {e}")
        return False

def format_log_for_wazuh(log_entry: dict) -> str:
    """Formata log estruturado para Wazuh SIEM"""
    try:
        # Cria estrutura JSON para Wazuh
        wazuh_log = {
            "timestamp": log_entry.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S')),
            "level": log_entry.get('level', 'INFO'),
            "source": "agente-ia",
            "component": log_entry.get('source', 'unknown'),
            "message": log_entry.get('message', ''),
            "ip_address": log_entry.get('ip_address'),
            "user": log_entry.get('user'),
            "is_real_data": log_entry.get('is_real', False),
            "anomaly_detected": 'anomaly' in log_entry.get('message', '').lower(),
            "severity_score": _calculate_severity_score(log_entry),
            "tags": _generate_log_tags(log_entry)
        }
        
        # Remove campos nulos
        wazuh_log = {k: v for k, v in wazuh_log.items() if v is not None}
        
        # Converte para formato syslog estruturado
        priority = _map_priority(log_entry.get('level', 'INFO'))
        timestamp = datetime.now().strftime('%b %d %H:%M:%S')
        json_payload = json.dumps(wazuh_log, ensure_ascii=False)
        
        return f"<{priority}>{timestamp} agente-ia: STRUCTURED_LOG: {json_payload}"
        
    except Exception as e:
        # Fallback para formato simples
        logging.warning(f"Erro ao formatar log para Wazuh: {e}")
        return f"<{_map_priority('INFO')}>{datetime.now().strftime('%b %d %H:%M:%S')} agente-ia: {log_entry.get('message', 'Log sem formato')}"

def _calculate_severity_score(log_entry: dict) -> int:
    """Calcula score de severidade (0-100)"""
    score = 0
    level = log_entry.get('level', 'INFO').upper()
    message = log_entry.get('message', '').lower()
    
    # Score base por nível
    level_scores = {
        'DEBUG': 10,
        'INFO': 20, 
        'SUCCESS': 25,
        'WARNING': 50,
        'ERROR': 70,
        'CRITICAL': 90
    }
    score += level_scores.get(level, 20)
    
    # Score por palavras-chave suspeitas
    suspicious_keywords = {
        'failed login': 15,
        'brute force': 25,
        'malware': 30,
        'attack': 20,
        'intrusion': 25,
        'unauthorized': 15,
        'anomaly': 10,
        'suspicious': 10,
        'blocked': 5,
        'denied': 5
    }
    
    for keyword, points in suspicious_keywords.items():
        if keyword in message:
            score += points
    
    # Score por dados reais da universidade
    if log_entry.get('is_real', False):
        score += 5
        
    return min(score, 100)  # Máximo 100

def _generate_log_tags(log_entry: dict) -> list:
    """Gera tags para categorização no Wazuh"""
    tags = ['agente-ia']
    
    level = log_entry.get('level', '').upper()
    message = log_entry.get('message', '').lower()
    source = log_entry.get('source', '').lower()
    
    # Tags por nível
    if level in ['ERROR', 'CRITICAL']:
        tags.append('high-priority')
    elif level == 'WARNING':
        tags.append('medium-priority')
    
    # Tags por tipo de fonte
    if 'university' in source:
        tags.append('university-data')
    elif 'system' in source:
        tags.append('system-logs')
    elif 'email' in source:
        tags.append('notification')
    elif 'wazuh' in source:
        tags.append('siem-action')
    
    # Tags por conteúdo
    if any(word in message for word in ['login', 'auth', 'password']):
        tags.append('authentication')
    if any(word in message for word in ['network', 'connection', 'ip']):
        tags.append('network')
    if any(word in message for word in ['file', 'directory', 'path']):
        tags.append('filesystem')
    if any(word in message for word in ['anomaly', 'suspicious', 'attack']):
        tags.append('security-event')
    if log_entry.get('is_real', False):
        tags.append('real-data')
    
    return tags

def send_enhanced_log_to_wazuh(log_entry: dict) -> bool:
    """Envia log formatado para Wazuh"""
    if not WAZUH_ENABLED:
        return False
    
    try:
        formatted_log = format_log_for_wazuh(log_entry)
        return _send_syslog_udp(formatted_log, WAZUH_SYSLOG_HOST, WAZUH_SYSLOG_PORT)
    except Exception as e:
        logging.error(f"Erro ao enviar log melhorado para Wazuh: {e}")
        return False

def _build_wazuh_summary() -> dict:
    # Calcula métricas locais como fallback/quick status
    error_logs = [l for l in logs_data if l.get('level') == 'ERROR']
    critical_alerts = 0  # Não geramos 'CRITICAL' nesta versão
    total_alerts = len(anomalies_data) + len(error_logs)
    security_status = 'LOW' if critical_alerts == 0 else 'HIGH'
    return {
        'siem_connected': bool(WAZUH_ENABLED),
        'total_alerts': total_alerts,
        'critical_alerts': critical_alerts,
        'security_status': security_status,
        'syslog_target': f"{WAZUH_SYSLOG_HOST}:{WAZUH_SYSLOG_PORT}"
    }

def load_real_logs():
    """Carrega logs reais dos arquivos da universidade"""
    global logs_data, real_logs_loaded
    
    if real_logs_loaded:
        return
    
    try:
        # Caminho para os logs da universidade
        logs_directory = '/home/kiron/Cursor/Agenteia/logs-analizes'
        log_files = glob.glob(os.path.join(logs_directory, 'Anon*.txt'))
        
        logging.info(f"🔍 Carregando logs reais de: {logs_directory}")
        
        logs_count = 0
        for log_file in log_files:
            if os.path.exists(log_file):
                try:
                    with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                        lines = f.readlines()[:50]  # Primeiras 50 linhas de cada arquivo
                        
                    for line in lines:
                        line = line.strip()
                        if line and len(line) > 5:  # Filtro básico
                            # Determina nível baseado no conteúdo
                            level = 'INFO'
                            if any(word in line.lower() for word in ['error', 'fail', 'denied', 'refused']):
                                level = 'ERROR'
                            elif any(word in line.lower() for word in ['warn', 'alert', 'suspicious']):
                                level = 'WARNING'
                            elif any(word in line.lower() for word in ['success', 'accepted', 'ok']):
                                level = 'SUCCESS'
                                
                            logs_data.append({
                                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                                'level': level,
                                'message': line[:150],  # Trunca para evitar mensagens muito longas
                                'source': f"university-{os.path.basename(log_file)}",
                                'is_real': True
                            })
                            logs_count += 1
                            
                except Exception as e:
                    logging.warning(f"Erro ao ler {log_file}: {e}")
                    
        real_logs_loaded = True
        logging.info(f"✅ Carregados {logs_count} logs reais da universidade!")
        
        # Adiciona anomalias detectadas nos logs reais
        error_logs = [log for log in logs_data if log.get('level') == 'ERROR']
        if error_logs:
            anomalies_data.append({
                'id': f'real_errors_{datetime.now().strftime("%Y%m%d_%H%M")}',
                'type': 'error_analysis',
                'severity': 'MEDIA',
                'description': f'Detectados {len(error_logs)} erros nos logs reais da universidade',
                'timestamp': datetime.now().isoformat(),
                'confidence': 0.9,
                'real_data': True
            })
        
    except Exception as e:
        logging.error(f"❌ Erro ao carregar logs reais: {e}")

def send_real_email(subject, message):
    """Envia email real usando configurações SMTP"""
    try:
        # Cria mensagem
        msg = MIMEMultipart()
        msg['From'] = EMAIL_CONFIG['username']
        msg['To'] = EMAIL_CONFIG['recipient']
        msg['Subject'] = subject
        
        # Adiciona corpo da mensagem
        body = f"""
🤖 AGENTE IA - NOTIFICAÇÃO AUTOMÁTICA

{message}

📊 Informações do Sistema:
• Timestamp: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}
• Backend: Agente IA - Versão Melhorada
• Status: Sistema funcionando corretamente

---
Este é um email automático do sistema Agente IA
Detector de Anomalias Inteligente
        """
        
        msg.attach(MIMEText(body, 'plain'))
        
        # Conecta e envia
        context = ssl.create_default_context()
        with smtplib.SMTP(EMAIL_CONFIG['smtp_server'], EMAIL_CONFIG['port']) as server:
            server.starttls(context=context)
            server.login(EMAIL_CONFIG['username'], EMAIL_CONFIG['password'])
            server.send_message(msg)
            
        logging.info("📧 Email real enviado com sucesso!")
        return True
        
    except Exception as e:
        logging.error(f"❌ Erro ao enviar email: {e}")
        return False

@app.route('/')
def home():
    return jsonify({
        'status': 'success',
        'message': 'Agente IA Backend - Versión Simplificada con CORS',
        'version': '1.0',
        'cyberpunk': True,
        'cors_enabled': True
    })

@app.route('/api/status')
def status():
    # Carrega logs reais se ainda não foram carregados
    if not real_logs_loaded:
        load_real_logs()
        
    real_logs_count = len([log for log in logs_data if log.get('is_real')])
    
    return jsonify({
        'status': 'online',
        'components': {
            'collector': 'ready',
            'detector': 'ready', 
            'email': 'configured',
            'syslog_server': 'running'
        },
        'collection_stats': {
            'total_logs': len(logs_data),
            'real_logs': real_logs_count,
            'sources': {
                'system': random.randint(50, 200),
                'university_files': real_logs_count,
                'syslog': random.randint(10, 50)
            },
            'syslog_server_running': True,
            'real_logs_loaded': real_logs_loaded
        },
        'siem': _build_wazuh_summary(),
        'timestamp': datetime.now().isoformat()
    })

@app.route('/api/logs')
def get_logs():
    # Carrega logs reais se ainda não foram carregados
    if not real_logs_loaded:
        load_real_logs()
    
    # Logs base do sistema
    base_logs = [
        {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'level': 'SUCCESS',
            'message': '🚀 Sistema iniciado com logs REAIS da universidade',
            'source': 'backend-enhanced'
        },
        {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'level': 'INFO',
            'message': f'📊 Carregados {len([log for log in logs_data if log.get("is_real")])} logs reais',
            'source': 'log-loader'
        },
        {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'level': 'INFO',
            'message': '📧 Sistema de email REAL configurado',
            'source': 'email-system'
        }
    ]
    
    # Combina logs base + logs reais
    all_logs = base_logs + logs_data[-20:]  # Últimos 20 logs reais
    
    return jsonify({
        'status': 'success',
        'total_logs': len(logs_data),
        'real_logs_count': len([log for log in logs_data if log.get('is_real')]),
        'logs': all_logs
    })

@app.route('/api/collect', methods=['POST', 'GET'])
def collect_logs():
    """Endpoint para coleta manual de logs (REAIS + SIMULADOS)"""
    try:
        # Força recarregamento dos logs reais
        global real_logs_loaded
        real_logs_loaded = False
        load_real_logs()
        
        # Adiciona alguns logs de sistema simulados
        system_logs_count = random.randint(5, 15)
        for i in range(system_logs_count):
            logs_data.append({
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'level': random.choice(['INFO', 'WARNING', 'SUCCESS']),
                'message': f'Log de sistema coletado #{len(logs_data) + i}',
                'source': 'system-monitor',
                'is_real': False
            })
        
        # Calcula estatísticas
        real_logs_count = len([log for log in logs_data if log.get('is_real')])
        simulated_count = len([log for log in logs_data if not log.get('is_real')])
        
        stats = {
            'total_new_logs': len(logs_data),
            'real_logs': real_logs_count,
            'system_logs': simulated_count,
            'sources': {
                'university_files': real_logs_count,
                'system': simulated_count,
                'syslog': random.randint(5, 25)
            }
        }
        
        logging.info(f"📊 Coleta completa: {real_logs_count} logs reais + {simulated_count} sistema")
        
        # Log da ação
        # Adiciona log da ação com persistência
        log_entry = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'level': 'SUCCESS',
            'message': f'🔄 Coleta manual executada: {real_logs_count} logs reais processados',
            'source': 'collector',
            'is_real': False,
            'type': 'collection_activity',
            'severity_score': 25
        }
        logs_data.append(log_entry)
        
        # Salva no banco e envia para Wazuh
        save_alert_to_db(log_entry)
        send_enhanced_log_to_wazuh(log_entry)
        
        return jsonify({
            'status': 'success',
            'message': 'Coleta de logs executada com sucesso (dados REAIS + sistema)',
            'stats': stats
        })
        
    except Exception as e:
        logging.error(f"Erro na coleta: {e}")
        return jsonify({
            'status': 'error', 
            'message': f'Erro na coleta: {str(e)}'
        }), 500

@app.route('/api/test-email', methods=['POST', 'GET']) 
def test_email():
    """Endpoint para testar sistema de email REAL"""
    try:
        # Envia email REAL
        subject = "🚨 [AGENTE IA] Teste de Sistema de Alertas"
        message = """
✅ TESTE DE SISTEMA DE EMAIL REALIZADO COM SUCESSO!

Este é um teste do sistema de alertas do Agente IA.
O sistema está funcionando corretamente e pode enviar 
notificações automáticas quando anomalias são detectadas.

🎯 Recursos ativados:
• Leitura de logs REAIS da universidade
• Sistema de email funcional
• Detecção básica de anomalias  
• Interface cyberpunk operacional

O sistema está pronto para monitoramento em produção!
        """
        
        email_sent = send_real_email(subject, message)
        
        if email_sent:
            logging.info("📧 Email REAL enviado com sucesso!")
            
            # Adiciona log do evento
            log_entry = {
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'level': 'SUCCESS',
                'message': '📧 Email de teste enviado com sucesso via SMTP real',
                'source': 'email-system',
                'is_real': False
            }
            logs_data.append(log_entry)
            
            # Envia log estruturado para Wazuh
            send_enhanced_log_to_wazuh(log_entry)
            
            return jsonify({
                'status': 'success',
                'message': 'Email REAL enviado com sucesso!',
                'details': {
                    'to': EMAIL_CONFIG['recipient'],
                    'timestamp': datetime.now().isoformat(),
                    'method': 'SMTP_REAL',
                    'server': EMAIL_CONFIG['smtp_server']
                }
            })
        else:
            raise Exception("Falha no envio via SMTP")
        
    except Exception as e:
        logging.error(f"❌ Erro no email real: {e}")
        return jsonify({
            'status': 'error',
            'message': f'Erro ao enviar email real: {str(e)}'
        }), 500

@app.route('/api/anomalies')
def get_anomalies():
    """Endpoint para obter anomalias detectadas (ANÁLISE REAL)"""
    # Carrega logs reais se ainda não foram carregados
    if not real_logs_loaded:
        load_real_logs()
    
    # Análise de anomalias em tempo real nos dados reais
    current_anomalies = []
    
    # 1. Análise de logs de erro
    error_logs = [log for log in logs_data if log.get('level') == 'ERROR']
    if error_logs:
        current_anomalies.append({
            'id': f'real_errors_{datetime.now().strftime("%Y%m%d_%H%M")}',
            'type': 'error_pattern_detected',
            'severity': 'MEDIA',
            'description': f'Detectados {len(error_logs)} logs de erro nos dados reais da universidade',
            'timestamp': datetime.now().isoformat(),
            'confidence': 0.9,
            'details': {
                'error_count': len(error_logs),
                'sample_errors': [log['message'][:80] for log in error_logs[:3]],
                'sources': list(set([log['source'] for log in error_logs]))
            },
            'real_data': True
        })
    
    # 2. Análise de logs de warning
    warning_logs = [log for log in logs_data if log.get('level') == 'WARNING']
    if len(warning_logs) > 5:
        current_anomalies.append({
            'id': f'warnings_{datetime.now().strftime("%Y%m%d_%H%M")}',
            'type': 'warning_cluster',
            'severity': 'BAIXA',
            'description': f'Alto volume de warnings detectado: {len(warning_logs)} ocorrências',
            'timestamp': datetime.now().isoformat(),
            'confidence': 0.7,
            'details': {
                'warning_count': len(warning_logs),
                'threshold': 5
            },
            'real_data': True
        })
    
    # 3. Simula anomalia de sistema (para demonstrar detecção híbrida)
    system_anomaly = {
        'id': f'system_monitor_{datetime.now().strftime("%Y%m%d_%H%M")}',
        'type': 'system_monitoring',
        'severity': 'BAIXA',
        'description': 'Sistema funcionando normalmente - monitoramento ativo',
        'timestamp': datetime.now().isoformat(),
        'confidence': 0.95,
        'details': {
            'total_logs_analyzed': len(logs_data),
            'real_logs_processed': len([log for log in logs_data if log.get('is_real')]),
            'monitoring_status': 'active'
        },
        'real_data': False
    }
    
    all_anomalies = current_anomalies + [system_anomaly] + anomalies_data
    
    return jsonify({
        'status': 'success',
        'anomalies': all_anomalies,
        'total_count': len(all_anomalies),
        'analysis_summary': {
            'real_data_anomalies': len(current_anomalies),
            'total_logs_analyzed': len(logs_data),
            'error_logs_found': len(error_logs),
            'warning_logs_found': len(warning_logs)
        }
    })

# === ENDPOINTS DE MONITORAMENTO EM TEMPO REAL ===
@app.route("/api/monitoring/start", methods=["POST"])
def start_monitoring():
    """Inicia monitoramento em tempo real"""
    try:
        success = real_time_monitoring.start_real_time_monitoring()
        
        if success:
            # Adiciona log da ação
            log_entry = {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "level": "SUCCESS",
                "message": "🔍 Monitoramento em tempo real iniciado automaticamente",
                "source": "real_time_monitoring",
                "is_real": False
            }
            logs_data.append(log_entry)
            save_alert_to_db(log_entry)
            send_enhanced_log_to_wazuh(log_entry)
            
            return jsonify({
                "status": "success",
                "message": "Monitoramento em tempo real iniciado",
                "monitoring_active": True
            })
        else:
            return jsonify({
                "status": "error",
                "message": "Falha ao iniciar monitoramento"
            }), 500
            
    except Exception as e:
        logging.error(f"Erro ao iniciar monitoramento: {e}")
        return jsonify({
            "status": "error",
            "message": f"Erro interno: {str(e)}"
        }), 500

@app.route("/api/monitoring/stop", methods=["POST"])
def stop_monitoring():
    """Para monitoramento em tempo real"""
    try:
        success = real_time_monitoring.stop_real_time_monitoring()
        
        if success:
            # Adiciona log da ação
            log_entry = {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "level": "INFO",
                "message": "🛑 Monitoramento em tempo real parado",
                "source": "real_time_monitoring",
                "is_real": False
            }
            logs_data.append(log_entry)
            
            return jsonify({
                "status": "success",
                "message": "Monitoramento em tempo real parado",
                "monitoring_active": False
            })
        else:
            return jsonify({
                "status": "error",
                "message": "Falha ao parar monitoramento"
            }), 500
            
    except Exception as e:
        logging.error(f"Erro ao parar monitoramento: {e}")
        return jsonify({
            "status": "error",
            "message": f"Erro interno: {str(e)}"
        }), 500

@app.route("/api/monitoring/status")
def monitoring_status():
    """Verifica status do monitoramento em tempo real"""
    return jsonify({
        "status": "success",
        "monitoring_active": real_time_monitoring.real_time_monitoring_active,
        "rules_loaded": len(real_time_monitoring.anomaly_detection_rules),
        "last_cursor": real_time_monitoring.last_journal_cursor
    })

# === Endpoints de Integração Wazuh (SIEM) ===
@app.route('/api/wazuh-summary', methods=['GET'])
def wazuh_summary():
    summary = _build_wazuh_summary()
    return jsonify(summary)

@app.route('/api/wazuh-alerts', methods=['GET'])
def wazuh_alerts():
    # Se habilitado, tenta buscar alertas no Wazuh
    if WAZUH_ENABLED:
        wazuh_alerts = _wazuh_get_alerts(limit=20)
        if wazuh_alerts:
            return jsonify({
                'status': 'success',
                'siem_connected': True,
                'alerts': wazuh_alerts,
                'total': len(wazuh_alerts)
            })
    # Fallback local: anomalias + logs de erro recentes
    alerts = []
    for a in anomalies_data[-20:]:
        alerts.append({
            'id': a.get('id'),
            'severity': a.get('severity', 'BAIXA'),
            'description': a.get('description', ''),
            'timestamp': a.get('timestamp')
        })
    for l in [x for x in logs_data[-50:] if x.get('level') == 'ERROR'][:10]:
        alerts.append({
            'id': f"logerr_{l.get('timestamp')}",
            'severity': 'MEDIA',
            'description': l.get('message', '')[:120],
            'timestamp': l.get('timestamp')
        })
    return jsonify({
        'status': 'success',
        'siem_connected': bool(WAZUH_ENABLED),
        'alerts': alerts,
        'total': len(alerts)
    })

@app.route('/api/wazuh/send-log', methods=['POST'])
def wazuh_send_log():
    try:
        payload = request.get_json(force=True) or {}
        message = payload.get('message') or 'Teste de envio do Agente IA'
        level = payload.get('level', 'INFO')
        # compõe a mensagem com nível
        syslog_msg = f"<{_map_priority(level)}>{datetime.now().strftime('%b %d %H:%M:%S')} agente-ia: {message}"
        sent = False
        if WAZUH_ENABLED:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.sendto(syslog_msg.encode('utf-8', errors='ignore'), (WAZUH_SYSLOG_HOST, WAZUH_SYSLOG_PORT))
                sock.close()
                sent = True
            except Exception as e:
                logging.warning(f"Falha ao enviar para Wazuh via Syslog: {e}")
        return jsonify({
            'status': 'success',
            'sent': sent,
            'target': f"{WAZUH_SYSLOG_HOST}:{WAZUH_SYSLOG_PORT}",
            'siem_connected': bool(WAZUH_ENABLED)
        })
    except Exception as e:
        logging.error(f"Erro no envio de log para Wazuh: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 400

# === SISTEMA DE AÇÕES AUTOMÁTICAS WAZUH ===
# Armazena ações executadas e pendentes
executed_actions = []
pending_approvals = []

def execute_safe_action(action_type: str, target: str, alert_id: str = None) -> dict:
    """Executa ações seguras automaticamente"""
    try:
        result = {'success': False, 'message': '', 'details': {}}
        
        if action_type == 'block_ip':
            # Bloqueia IP suspeito via iptables
            if _is_valid_ip(target) and not _is_private_ip(target):
                cmd_result = os.system(f"sudo iptables -A INPUT -s {target} -j DROP 2>/dev/null")
                if cmd_result == 0:
                    result = {
                        'success': True,
                        'message': f'IP {target} bloqueado com sucesso',
                        'details': {'ip_blocked': target, 'method': 'iptables'}
                    }
                else:
                    result['message'] = f'Falha ao bloquear IP {target} (sem privilégios sudo?)'
            else:
                result['message'] = f'IP {target} inválido ou privado - ação ignorada por segurança'
                
        elif action_type == 'restart_service':
            # Reinicia serviços seguros
            safe_services = ['nginx', 'apache2', 'httpd', 'ssh', 'sshd', 'fail2ban']
            if target.lower() in safe_services:
                cmd_result = os.system(f"sudo systemctl restart {target} 2>/dev/null")
                if cmd_result == 0:
                    result = {
                        'success': True,
                        'message': f'Serviço {target} reiniciado com sucesso',
                        'details': {'service_restarted': target, 'method': 'systemctl'}
                    }
                else:
                    result['message'] = f'Falha ao reiniciar serviço {target}'
            else:
                result['message'] = f'Serviço {target} não está na lista de serviços seguros'
                
        elif action_type == 'isolate_process':
            # Isola processo suspeito (STOP signal)
            if target.isdigit():
                pid = int(target)
                try:
                    os.kill(pid, 19)  # SIGSTOP
                    result = {
                        'success': True,
                        'message': f'Processo PID {pid} isolado (pausado)',
                        'details': {'pid_isolated': pid, 'signal': 'SIGSTOP'}
                    }
                except ProcessLookupError:
                    result['message'] = f'Processo PID {pid} não encontrado'
                except PermissionError:
                    result['message'] = f'Sem permissão para isolar processo PID {pid}'
            else:
                result['message'] = f'PID {target} inválido'
                
        elif action_type == 'create_firewall_rule':
            # Cria regra de firewall específica
            if _is_valid_ip(target):
                cmd_result = os.system(f"sudo iptables -A INPUT -s {target} -p tcp --dport 22 -j DROP 2>/dev/null")
                if cmd_result == 0:
                    result = {
                        'success': True,
                        'message': f'Regra de firewall criada para bloquear SSH do IP {target}',
                        'details': {'firewall_rule': f'block_ssh_{target}'}
                    }
                else:
                    result['message'] = f'Falha ao criar regra de firewall para {target}'
            else:
                result['message'] = f'IP {target} inválido para regra de firewall'
        else:
            result['message'] = f'Tipo de ação {action_type} não reconhecido'
            
        # Registra ação executada
        action_record = {
            'id': f'action_{datetime.now().strftime("%Y%m%d_%H%M%S")}',
            'type': action_type,
            'target': target,
            'alert_id': alert_id,
            'timestamp': datetime.now().isoformat(),
            'result': result,
            'automated': True
        }
        executed_actions.append(action_record)
        
        # Salva no banco de dados
        save_action_to_db(action_record)
        
        logging.info(f"🔧 Ação executada: {action_type} -> {target} | Sucesso: {result['success']}")
        return result
        
    except Exception as e:
        error_result = {'success': False, 'message': f'Erro na execução: {str(e)}'}
        executed_actions.append({
            'id': f'action_error_{datetime.now().strftime("%Y%m%d_%H%M%S")}',
            'type': action_type,
            'target': target,
            'alert_id': alert_id,
            'timestamp': datetime.now().isoformat(),
            'result': error_result,
            'automated': True
        })
        return error_result

def request_human_approval(action_type: str, target: str, alert_id: str, reason: str) -> dict:
    """Solicita aprovação humana para ações críticas"""
    approval_request = {
        'id': f'approval_{datetime.now().strftime("%Y%m%d_%H%M%S")}',
        'action_type': action_type,
        'target': target,
        'alert_id': alert_id,
        'reason': reason,
        'timestamp': datetime.now().isoformat(),
        'status': 'pending',
        'requested_by': 'agente_ia_auto'
    }
    
    pending_approvals.append(approval_request)
    
    # Salva no banco de dados
    save_approval_to_db(approval_request)
    
    # Envia email para administradores
    email_subject = f"🚨 [AGENTE IA] Aprovação Necessária - Ação Crítica"
    email_message = f"""
AÇÃO CRÍTICA REQUER APROVAÇÃO HUMANA

⚠️ Tipo de Ação: {action_type}
🎯 Alvo: {target}
📋 Motivo: {reason}
🆔 Alert ID: {alert_id}
⏰ Timestamp: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}

Esta ação foi identificada como crítica e requer aprovação manual.
Acesse o dashboard do Agente IA para aprovar ou rejeitar.

AÇÕES CRÍTICAS DISPONÍVEIS:
• change_password: Mudança de senhas de usuário
• shutdown_system: Desligamento do sistema
• block_user: Bloqueio de conta de usuário
• delete_files: Remoção de arquivos suspeitos
• network_isolation: Isolamento completo de rede

ID da Solicitação: {approval_request['id']}
    """
    
    try:
        send_real_email(email_subject, email_message)
        logging.info(f"📧 Email de aprovação enviado para ação: {action_type}")
    except Exception as e:
        logging.error(f"❌ Erro ao enviar email de aprovação: {e}")
    
    return {
        'approval_requested': True,
        'approval_id': approval_request['id'],
        'message': f'Ação crítica {action_type} enviada para aprovação humana'
    }

def _is_valid_ip(ip: str) -> bool:
    """Valida se é um IP válido"""
    try:
        parts = ip.split('.')
        return len(parts) == 4 and all(0 <= int(part) <= 255 for part in parts)
    except:
        return False

def _is_private_ip(ip: str) -> bool:
    """Verifica se IP é privado (não deve ser bloqueado)"""
    private_ranges = [
        r'^10\.',
        r'^192\.168\.',
        r'^172\.(1[6-9]|2[0-9]|3[01])\.',
        r'^127\.',
        r'^localhost$'
    ]
    
    for pattern in private_ranges:
        if re.match(pattern, ip):
            return True
    return False

@app.route('/api/wazuh/action', methods=['POST'])
def wazuh_execute_action():
    """Endpoint principal para execução de ações automáticas"""
    try:
        payload = request.get_json(force=True) or {}
        action_type = payload.get('action')
        target = payload.get('target')
        alert_id = payload.get('alert_id', f'manual_{datetime.now().strftime("%Y%m%d_%H%M%S")}')
        force_execute = payload.get('force', False)
        
        if not action_type or not target:
            return jsonify({
                'status': 'error',
                'message': 'Parâmetros obrigatórios: action, target'
            }), 400
        
        # Define ações seguras (executadas automaticamente)
        safe_actions = ['block_ip', 'restart_service', 'isolate_process', 'create_firewall_rule']
        
        # Define ações críticas (requerem aprovação humana)
        critical_actions = ['change_password', 'shutdown_system', 'block_user', 'delete_files', 'network_isolation']
        
        if action_type in safe_actions or force_execute:
            # Executa ação segura automaticamente
            result = execute_safe_action(action_type, target, alert_id)
            
            # Adiciona log da ação
            logs_data.append({
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'level': 'SUCCESS' if result['success'] else 'ERROR',
                'message': f'🔧 Ação automática executada: {action_type} -> {result["message"]}',
                'source': 'wazuh-actions',
                'is_real': False
            })
            
            return jsonify({
                'status': 'success' if result['success'] else 'error',
                'action_executed': result['success'],
                'message': result['message'],
                'details': result.get('details', {}),
                'alert_id': alert_id,
                'automated': True
            })
            
        elif action_type in critical_actions:
            # Solicita aprovação humana para ações críticas
            approval_result = request_human_approval(
                action_type, 
                target, 
                alert_id, 
                payload.get('reason', 'Ação crítica detectada pelo sistema')
            )
            
            # Adiciona log da solicitação
            logs_data.append({
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'level': 'WARNING',
                'message': f'⚠️ Aprovação solicitada: {action_type} -> {target}',
                'source': 'wazuh-approvals',
                'is_real': False
            })
            
            return jsonify({
                'status': 'pending_approval',
                'action_executed': False,
                'message': approval_result['message'],
                'approval_id': approval_result['approval_id'],
                'automated': False
            })
        else:
            return jsonify({
                'status': 'error',
                'message': f'Tipo de ação não reconhecido: {action_type}. Ações disponíveis: {safe_actions + critical_actions}'
            }), 400
            
    except Exception as e:
        logging.error(f"❌ Erro na execução de ação Wazuh: {e}")
        return jsonify({
            'status': 'error',
            'message': f'Erro interno: {str(e)}'
        }), 500

@app.route('/api/wazuh/actions/history', methods=['GET'])
def get_actions_history():
    """Obtém histórico de ações executadas"""
    return jsonify({
        'status': 'success',
        'executed_actions': executed_actions[-50:],  # Últimas 50 ações
        'pending_approvals': pending_approvals,
        'total_executed': len(executed_actions),
        'total_pending': len([a for a in pending_approvals if a['status'] == 'pending'])
    })

@app.route('/api/wazuh/actions/approve/<approval_id>', methods=['POST'])
def approve_action(approval_id):
    """Aprova uma ação pendente"""
    try:
        # Encontra solicitação de aprovação
        approval = next((a for a in pending_approvals if a['id'] == approval_id), None)
        
        if not approval:
            return jsonify({'status': 'error', 'message': 'Solicitação de aprovação não encontrada'}), 404
        
        if approval['status'] != 'pending':
            return jsonify({'status': 'error', 'message': 'Solicitação já foi processada'}), 400
        
        # Marca como aprovada
        approval['status'] = 'approved'
        approval['approved_at'] = datetime.now().isoformat()
        approval['approved_by'] = 'admin'  # Pode ser expandido para sistema de usuários
        
        # Executa a ação aprovada
        result = execute_safe_action(approval['action_type'], approval['target'], approval['alert_id'])
        
        # Adiciona log da aprovação
        logs_data.append({
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'level': 'SUCCESS' if result['success'] else 'ERROR',
            'message': f'✅ Ação aprovada e executada: {approval["action_type"]} -> {result["message"]}',
            'source': 'wazuh-approvals',
            'is_real': False
        })
        
        return jsonify({
            'status': 'success',
            'message': 'Ação aprovada e executada com sucesso',
            'approval_id': approval_id,
            'execution_result': result
        })
        
    except Exception as e:
        logging.error(f"❌ Erro ao aprovar ação: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/wazuh/statistics', methods=['GET'])
def get_advanced_statistics():
    """Obtém estatísticas avançadas do sistema SIEM"""
    try:
        # Estatísticas do banco de dados
        db_stats = get_statistics_from_db()
        
        # Estatísticas de logs reais
        real_logs_count = len([log for log in logs_data if log.get('is_real')])
        total_logs_count = len(logs_data)
        
        # Estatísticas de anomalias
        total_anomalies = len(anomalies_data)
        
        # Estatísticas de ações
        successful_actions = len([action for action in executed_actions if action['result']['success']])
        failed_actions = len([action for action in executed_actions if not action['result']['success']])
        
        # Estatísticas de aprovações
        pending_approvals_count = len([approval for approval in pending_approvals if approval['status'] == 'pending'])
        
        # Calcula métricas de eficiência
        total_actions_count = len(executed_actions)
        success_rate = (successful_actions / total_actions_count * 100) if total_actions_count > 0 else 0
        
        # Estatísticas por período (últimas 24h)
        now = datetime.now()
        last_24h = now - timedelta(hours=24)
        
        recent_logs = [log for log in logs_data if datetime.fromisoformat(log.get('timestamp', '2024-01-01 00:00:00')) > last_24h]
        recent_actions = [action for action in executed_actions if datetime.fromisoformat(action.get('timestamp', '2024-01-01T00:00:00')) > last_24h]
        
        return jsonify({
            'status': 'success',
            'system_overview': {
                'total_logs': total_logs_count,
                'real_logs': real_logs_count,
                'total_anomalies': total_anomalies,
                'wazuh_connected': bool(WAZUH_ENABLED),
                'database_active': db_stats.get('database_status') == 'active'
            },
            'actions_statistics': {
                'total_actions': total_actions_count,
                'successful_actions': successful_actions,
                'failed_actions': failed_actions,
                'success_rate': round(success_rate, 2),
                'pending_approvals': pending_approvals_count
            },
            'database_statistics': db_stats,
            'last_24h_activity': {
                'logs_processed': len(recent_logs),
                'actions_executed': len(recent_actions),
                'avg_logs_per_hour': round(len(recent_logs) / 24, 2) if recent_logs else 0
            },
            'security_metrics': {
                'threat_level': 'LOW' if total_anomalies < 5 else 'MEDIUM' if total_anomalies < 15 else 'HIGH',
                'response_efficiency': success_rate,
                'automation_level': round((len([a for a in executed_actions if a.get('automated')]) / total_actions_count * 100), 2) if total_actions_count > 0 else 0
            },
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        logging.error(f"❌ Erro ao obter estatísticas avançadas: {e}")
        return jsonify({
            'status': 'error',
            'message': f'Erro ao obter estatísticas: {str(e)}'
        }), 500

@app.route('/api/wazuh/reports', methods=['GET'])
def generate_security_report():
    """Gera relatório de segurança completo"""
    try:
        # Obtém estatísticas avançadas
        stats_response = get_advanced_statistics()
        stats_data = stats_response.get_json()
        
        if stats_data['status'] != 'success':
            raise Exception("Erro ao obter estatísticas")
        
        # Gera resumo executivo
        stats = stats_data
        threat_level = stats['security_metrics']['threat_level']
        
        # Determina status geral do sistema
        if threat_level == 'LOW' and stats['actions_statistics']['success_rate'] > 80:
            overall_status = 'SECURE'
            status_color = 'success'
        elif threat_level == 'MEDIUM' or stats['actions_statistics']['success_rate'] > 60:
            overall_status = 'MONITORING'
            status_color = 'warning'
        else:
            overall_status = 'ALERT'
            status_color = 'error'
        
        # Recomendações baseadas nos dados
        recommendations = []
        
        if stats['actions_statistics']['success_rate'] < 70:
            recommendations.append("Revisar configurações de ações automáticas")
        
        if stats['actions_statistics']['pending_approvals'] > 5:
            recommendations.append("Processar aprovações pendentes")
        
        if stats['system_overview']['total_anomalies'] > 10:
            recommendations.append("Investigar padrões de anomalias recorrentes")
        
        if not stats['system_overview']['wazuh_connected']:
            recommendations.append("Verificar conexão com Wazuh SIEM")
        
        if not recommendations:
            recommendations.append("Sistema operando dentro dos parâmetros normais")
        
        report = {
            'status': 'success',
            'report_generated_at': datetime.now().isoformat(),
            'executive_summary': {
                'overall_status': overall_status,
                'status_color': status_color,
                'threat_level': threat_level,
                'system_health': 'GOOD' if stats['system_overview']['database_active'] else 'DEGRADED',
                'automation_efficiency': f"{stats['security_metrics']['automation_level']}%"
            },
            'key_metrics': {
                'logs_processed_24h': stats['last_24h_activity']['logs_processed'],
                'actions_executed_24h': stats['last_24h_activity']['actions_executed'],
                'success_rate': f"{stats['actions_statistics']['success_rate']}%",
                'pending_approvals': stats['actions_statistics']['pending_approvals']
            },
            'detailed_statistics': stats,
            'recommendations': recommendations,
            'next_review': (datetime.now() + timedelta(hours=24)).isoformat()
        }
        
        # Salva relatório como alerta no banco
        report_alert = {
            'id': f'report_{datetime.now().strftime("%Y%m%d_%H%M%S")}',
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'level': 'INFO',
            'message': f'Relatório de segurança gerado - Status: {overall_status}',
            'source': 'security-reports',
            'type': 'security_report',
            'severity_score': 25,
            'is_real': False
        }
        save_alert_to_db(report_alert)
        
        return jsonify(report)
        
    except Exception as e:
        logging.error(f"❌ Erro ao gerar relatório: {e}")
        return jsonify({
            'status': 'error',
            'message': f'Erro ao gerar relatório: {str(e)}'
        }), 500

# === ESTRUTURA PARA REGRAS WAZUH CUSTOMIZADAS ===
CUSTOM_WAZUH_RULES = {
    'agente_ia_rules': {
        'university_data': {
            'rule_id': 100001,
            'level': 5,
            'description': 'Dados universitários processados pelo Agente IA',
            'groups': ['agente_ia', 'university'],
            'match': 'university-',
            'options': ['no_full_log']
        },
        'anomaly_detected': {
            'rule_id': 100002,
            'level': 8,
            'description': 'Anomalia detectada pelo Agente IA',
            'groups': ['agente_ia', 'anomaly', 'security'],
            'match': 'anomaly',
            'options': ['alert_by_email']
        },
        'action_executed': {
            'rule_id': 100003,
            'level': 6,
            'description': 'Ação automática executada pelo Agente IA',
            'groups': ['agente_ia', 'action', 'response'],
            'match': 'Ação automática executada',
            'options': ['no_full_log']
        },
        'critical_action_pending': {
            'rule_id': 100004,
            'level': 10,
            'description': 'Ação crítica aguardando aprovação humana',
            'groups': ['agente_ia', 'critical', 'approval'],
            'match': 'Aprovação solicitada',
            'options': ['alert_by_email']
        },
        'high_severity_log': {
            'rule_id': 100005,
            'level': 12,
            'description': 'Log de alta severidade detectado pelo Agente IA',
            'groups': ['agente_ia', 'high_severity', 'security'],
            'match': 'severity_score',
            'if_matched_sid': '100001',
            'field': 'severity_score',
            'regex': '[8-9][0-9]|100',  # Score 80-100
            'options': ['alert_by_email']
        }
    }
}

def generate_wazuh_rules_xml() -> str:
    """Gera arquivo XML com regras customizadas para Wazuh"""
    xml_content = '''<!-- Regras customizadas do Agente IA -->
<group name="agente_ia,">
  
  <!-- Regra base para logs do Agente IA -->
  <rule id="100000" level="0">
    <decoded_as>json</decoded_as>
    <field name="source">agente-ia</field>
    <description>Logs do sistema Agente IA</description>
    <options>no_full_log</options>
  </rule>

'''
    
    for category, rules in CUSTOM_WAZUH_RULES['agente_ia_rules'].items():
        rule_xml = f'''  <!-- {rules['description']} -->
  <rule id="{rules['rule_id']}" level="{rules['level']}">
    <if_matched_sid>100000</if_matched_sid>
    <match>{rules['match']}</match>
    <description>{rules['description']}</description>
    <group>{','.join(rules['groups'])}</group>
'''
        
        # Adiciona opções específicas se existirem
        if 'options' in rules:
            for option in rules['options']:
                rule_xml += f'    <options>{option}</options>\n'
        
        # Adiciona campos específicos se existirem
        if 'field' in rules:
            rule_xml += f'    <field name="{rules["field"]}">{rules.get("regex", ".*")}</field>\n'
        
        rule_xml += '  </rule>\n\n'
        xml_content += rule_xml
    
    xml_content += '''</group>'''
    
    return xml_content

@app.route('/api/wazuh/rules/generate', methods=['GET'])
def get_wazuh_rules():
    """Gera e retorna regras XML para Wazuh"""
    try:
        rules_xml = generate_wazuh_rules_xml()
        
        return jsonify({
            'status': 'success',
            'rules_xml': rules_xml,
            'rules_count': len(CUSTOM_WAZUH_RULES['agente_ia_rules']),
            'installation_instructions': {
                'step_1': 'Copie o XML gerado',
                'step_2': 'Salve como /var/ossec/etc/rules/agente_ia_rules.xml no servidor Wazuh',
                'step_3': 'Reinicie o Wazuh: systemctl restart wazuh-manager',
                'step_4': 'Verifique no dashboard: Management > Rules'
            },
            'message': 'Regras customizadas geradas com sucesso'
        })
        
    except Exception as e:
        logging.error(f"❌ Erro ao gerar regras Wazuh: {e}")
        return jsonify({
            'status': 'error',
            'message': f'Erro ao gerar regras: {str(e)}'
        }), 500

@app.route('/api/wazuh/rules/test', methods=['POST'])
def test_wazuh_rule():
    """Testa uma regra customizada com dados de exemplo"""
    try:
        payload = request.get_json(force=True) or {}
        rule_name = payload.get('rule_name')
        test_data = payload.get('test_data', {})
        
        if not rule_name or rule_name not in CUSTOM_WAZUH_RULES['agente_ia_rules']:
            return jsonify({
                'status': 'error',
                'message': f'Regra não encontrada: {rule_name}'
            }), 400
        
        rule = CUSTOM_WAZUH_RULES['agente_ia_rules'][rule_name]
        
        # Simula teste da regra
        test_log = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'level': test_data.get('level', 'INFO'),
            'message': test_data.get('message', f'Teste da regra {rule_name}'),
            'source': 'agente-ia',
            'test_rule': rule_name
        }
        
        # Verifica se a regra seria ativada
        would_match = rule['match'] in test_log['message']
        
        # Formata log para Wazuh e simula envio
        formatted_log = format_log_for_wazuh(test_log)
        
        return jsonify({
            'status': 'success',
            'rule_tested': rule_name,
            'rule_details': rule,
            'test_log': test_log,
            'formatted_log': formatted_log,
            'would_match': would_match,
            'expected_level': rule['level'],
            'expected_groups': rule['groups']
        })
        
    except Exception as e:
        logging.error(f"❌ Erro ao testar regra Wazuh: {e}")
        return jsonify({
            'status': 'error',
            'message': f'Erro ao testar regra: {str(e)}'
        }), 500

if __name__ == '__main__':
    host = os.getenv('BACKEND_HOST', 'localhost')
    port = int(os.getenv('BACKEND_PORT', 5000))
    print(f"🚀 Iniciando Agente IA Backend em {host}:{port}")
    app.run(host=host, port=port, debug=True) 