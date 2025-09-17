"""
AGENTE IA - Detector de Anomalias (FASE 1)
==========================================
Sistema básico de detecção com regras simples
Base para a IA Híbrida Adaptativa (Fase 2)
"""

import re
from datetime import datetime, timedelta
from typing import List, Dict, Any, Tuple
from collections import defaultdict, Counter
import logging
from ..core.log_collector import LogEntry

class Anomaly:
    """Representa uma anomalia detectada"""
    
    def __init__(self, 
                 tipo: str, 
                 severidade: str, 
                 descricao: str, 
                 logs_relacionados: List[LogEntry],
                 confianca: float = 1.0,
                 detalhes: Dict[str, Any] = None):
        """
        Inicializa uma anomalia
        
        Args:
            tipo: Tipo da anomalia (login_suspeito, ddos, etc.)
            severidade: BAIXA, MEDIA, ALTA, CRITICA
            descricao: Descrição em português da anomalia
            logs_relacionados: Logs que geraram a anomalia
            confianca: Nível de confiança (0.0 a 1.0)
            detalhes: Informações adicionais
        """
        self.id = f"{tipo}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self.tipo = tipo
        self.severidade = severidade
        self.descricao = descricao
        self.logs_relacionados = logs_relacionados
        self.confianca = confianca
        self.detalhes = detalhes or {}
        self.timestamp = datetime.now()
    
    def to_dict(self) -> Dict[str, Any]:
        """Converte para dicionário"""
        return {
            'id': self.id,
            'tipo': self.tipo,
            'severidade': self.severidade,
            'descricao': self.descricao,
            'timestamp': self.timestamp,
            'confianca': self.confianca,
            'detalhes': self.detalhes,
            'logs_count': len(self.logs_relacionados),
            'logs_sample': [log.message for log in self.logs_relacionados[:3]]
        }

class BasicAnomalyDetector:
    """Detector básico de anomalias com regras simples (Fase 1)"""
    
    def __init__(self):
        """Inicializa o detector básico"""
        self.anomalies_detected = []
        self.ip_attempts = defaultdict(list)  # IP -> lista de tentativas
        self.user_attempts = defaultdict(list)  # User -> lista de tentativas
        self.error_patterns = []
        
        # Configurações básicas
        self.config = {
            'max_failed_logins': 5,
            'time_window_minutes': 5,
            'max_requests_per_minute': 100,
            'suspicious_ips_threshold': 10,
            'error_burst_threshold': 20
        }
        
        # Padrões suspeitos
        self.suspicious_patterns = [
            r'(?i)(sql injection|union select|drop table)',
            r'(?i)(xss|<script|javascript:)',
            r'(?i)(password|passwd|pwd).*(crack|brute|force)',
            r'(?i)(admin|administrator|root).*(login|access)',
            r'(?i)(backdoor|malware|virus|trojan)',
            r'(?i)(port scan|nmap|vulnerability)',
            r'(?i)(failed|invalid|incorrect).*(login|password|auth)',
        ]
    
    def detect_anomalies(self, logs: List[LogEntry]) -> List[Anomaly]:
        """
        Detecta anomalias usando regras básicas
        
        Args:
            logs: Lista de logs para analisar
            
        Returns:
            Lista de anomalias detectadas
        """
        anomalies = []
        
        # Limpa dados antigos
        self._cleanup_old_data()
        
        # Processa logs em ordem cronológica
        sorted_logs = sorted(logs, key=lambda x: x.timestamp)
        
        for log in sorted_logs:
            # Detecta tentativas de login falhadas
            if self._is_failed_login(log):
                anomaly = self._detect_brute_force(log)
                if anomaly:
                    anomalies.append(anomaly)
            
            # Detecta padrões suspeitos
            anomaly = self._detect_suspicious_patterns(log)
            if anomaly:
                anomalies.append(anomaly)
            
            # Detecta burst de erros
            if log.level in ['ERROR', 'CRITICAL']:
                anomaly = self._detect_error_burst(log)
                if anomaly:
                    anomalies.append(anomaly)
            
            # Detecta IPs suspeitos
            if log.ip_address:
                anomaly = self._detect_suspicious_ip(log)
                if anomaly:
                    anomalies.append(anomaly)
        
        # Detecta anomalias de volume
        volume_anomaly = self._detect_volume_anomalies(sorted_logs)
        if volume_anomaly:
            anomalies.append(volume_anomaly)
        
        self.anomalies_detected.extend(anomalies)
        
        if anomalies:
            logging.info(f"🚨 {len(anomalies)} anomalias detectadas")
        
        return anomalies
    
    def _is_failed_login(self, log: LogEntry) -> bool:
        """Verifica se o log representa uma tentativa de login falhada"""
        failed_patterns = [
            r'(?i)failed.*login',
            r'(?i)invalid.*user',
            r'(?i)authentication.*failed',
            r'(?i)login.*failed',
            r'(?i)incorrect.*password',
            r'(?i)access.*denied'
        ]
        
        for pattern in failed_patterns:
            if re.search(pattern, log.message):
                return True
        
        return False
    
    def _detect_brute_force(self, log: LogEntry) -> Anomaly:
        """Detecta ataques de força bruta"""
        now = datetime.now()
        window_start = now - timedelta(minutes=self.config['time_window_minutes'])
        
        # Registra tentativa por IP
        if log.ip_address:
            self.ip_attempts[log.ip_address].append(now)
            
            # Remove tentativas antigas
            self.ip_attempts[log.ip_address] = [
                t for t in self.ip_attempts[log.ip_address] 
                if t > window_start
            ]
            
            # Verifica se excedeu o limite
            if len(self.ip_attempts[log.ip_address]) >= self.config['max_failed_logins']:
                return Anomaly(
                    tipo="brute_force",
                    severidade="ALTA",
                    descricao=f"Ataque de força bruta detectado do IP {log.ip_address}: "
                             f"{len(self.ip_attempts[log.ip_address])} tentativas em "
                             f"{self.config['time_window_minutes']} minutos",
                    logs_relacionados=[log],
                    confianca=0.9,
                    detalhes={
                        'ip_address': log.ip_address,
                        'tentativas': len(self.ip_attempts[log.ip_address]),
                        'janela_tempo': self.config['time_window_minutes']
                    }
                )
        
        # Registra tentativa por usuário
        if log.user:
            self.user_attempts[log.user].append(now)
            
            # Remove tentativas antigas
            self.user_attempts[log.user] = [
                t for t in self.user_attempts[log.user] 
                if t > window_start
            ]
            
            # Verifica se excedeu o limite
            if len(self.user_attempts[log.user]) >= self.config['max_failed_logins']:
                return Anomaly(
                    tipo="account_compromise",
                    severidade="MEDIA",
                    descricao=f"Possível comprometimento da conta '{log.user}': "
                             f"{len(self.user_attempts[log.user])} tentativas falhadas",
                    logs_relacionados=[log],
                    confianca=0.8,
                    detalhes={
                        'usuario': log.user,
                        'tentativas': len(self.user_attempts[log.user])
                    }
                )
        
        return None
    
    def _detect_suspicious_patterns(self, log: LogEntry) -> Anomaly:
        """Detecta padrões suspeitos na mensagem"""
        for pattern in self.suspicious_patterns:
            match = re.search(pattern, log.message)
            if match:
                return Anomaly(
                    tipo="suspicious_activity",
                    severidade="MEDIA",
                    descricao=f"Atividade suspeita detectada: padrão '{match.group(0)}' "
                             f"encontrado nos logs",
                    logs_relacionados=[log],
                    confianca=0.7,
                    detalhes={
                        'padrao_detectado': match.group(0),
                        'fonte': log.source,
                        'ip_address': log.ip_address
                    }
                )
        
        return None
    
    def _detect_error_burst(self, log: LogEntry) -> Anomaly:
        """Detecta rajadas de erros"""
        now = datetime.now()
        window_start = now - timedelta(minutes=1)  # Janela de 1 minuto
        
        # Conta erros recentes
        recent_errors = [
            anomaly for anomaly in self.anomalies_detected
            if (anomaly.timestamp > window_start and 
                anomaly.tipo in ['error_burst', 'system_error'])
        ]
        
        if len(recent_errors) >= self.config['error_burst_threshold']:
            return Anomaly(
                tipo="error_burst",
                severidade="ALTA",
                descricao=f"Rajada de erros detectada: {len(recent_errors)} erros "
                         f"em 1 minuto - possível instabilidade do sistema",
                logs_relacionados=[log],
                confianca=0.85,
                detalhes={
                    'erros_por_minuto': len(recent_errors),
                    'nivel_log': log.level,
                    'fonte': log.source
                }
            )
        
        return None
    
    def _detect_suspicious_ip(self, log: LogEntry) -> Anomaly:
        """Detecta IPs suspeitos baseado em atividade"""
        if not log.ip_address:
            return None
        
        # IPs privados geralmente são seguros
        if self._is_private_ip(log.ip_address):
            return None
        
        # Conta atividades do IP
        now = datetime.now()
        window_start = now - timedelta(hours=1)
        
        ip_activities = [
            anomaly for anomaly in self.anomalies_detected
            if (anomaly.timestamp > window_start and 
                anomaly.detalhes.get('ip_address') == log.ip_address)
        ]
        
        if len(ip_activities) >= self.config['suspicious_ips_threshold']:
            return Anomaly(
                tipo="suspicious_ip",
                severidade="MEDIA",
                descricao=f"IP suspeito detectado: {log.ip_address} com "
                         f"{len(ip_activities)} atividades suspeitas na última hora",
                logs_relacionados=[log],
                confianca=0.75,
                detalhes={
                    'ip_address': log.ip_address,
                    'atividades_suspeitas': len(ip_activities),
                    'janela_tempo': '1 hora'
                }
            )
        
        return None
    
    def _detect_volume_anomalies(self, logs: List[LogEntry]) -> Anomaly:
        """Detecta anomalias de volume de tráfego"""
        if len(logs) < 100:  # Muito poucos logs para análise
            return None
        
        now = datetime.now()
        window_start = now - timedelta(minutes=1)
        
        # Conta logs no último minuto
        recent_logs = [
            log for log in logs
            if log.timestamp > window_start
        ]
        
        if len(recent_logs) > self.config['max_requests_per_minute']:
            return Anomaly(
                tipo="traffic_spike",
                severidade="MEDIA",
                descricao=f"Pico de tráfego detectado: {len(recent_logs)} requisições "
                         f"no último minuto (limite: {self.config['max_requests_per_minute']})",
                logs_relacionados=recent_logs[:5],  # Apenas alguns exemplos
                confianca=0.8,
                detalhes={
                    'requisicoes_por_minuto': len(recent_logs),
                    'limite_configurado': self.config['max_requests_per_minute'],
                    'possivel_ddos': len(recent_logs) > self.config['max_requests_per_minute'] * 5
                }
            )
        
        return None
    
    def _is_private_ip(self, ip: str) -> bool:
        """Verifica se o IP é privado"""
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
    
    def _cleanup_old_data(self):
        """Remove dados antigos para economizar memória"""
        cutoff_time = datetime.now() - timedelta(hours=24)
        
        # Remove tentativas antigas
        for ip in list(self.ip_attempts.keys()):
            self.ip_attempts[ip] = [
                t for t in self.ip_attempts[ip] 
                if t > cutoff_time
            ]
            if not self.ip_attempts[ip]:
                del self.ip_attempts[ip]
        
        for user in list(self.user_attempts.keys()):
            self.user_attempts[user] = [
                t for t in self.user_attempts[user] 
                if t > cutoff_time
            ]
            if not self.user_attempts[user]:
                del self.user_attempts[user]
        
        # Remove anomalias antigas
        self.anomalies_detected = [
            anomaly for anomaly in self.anomalies_detected
            if anomaly.timestamp > cutoff_time
        ]
    
    def get_statistics(self) -> Dict[str, Any]:
        """Obtém estatísticas do detector"""
        if not self.anomalies_detected:
            return {
                'total_anomalias': 0,
                'anomalias_por_tipo': {},
                'anomalias_por_severidade': {}
            }
        
        tipos = Counter([a.tipo for a in self.anomalies_detected])
        severidades = Counter([a.severidade for a in self.anomalies_detected])
        
        return {
            'total_anomalias': len(self.anomalies_detected),
            'anomalias_por_tipo': dict(tipos),
            'anomalias_por_severidade': dict(severidades),
            'confianca_media': sum(a.confianca for a in self.anomalies_detected) / len(self.anomalies_detected),
            'ultima_anomalia': max(a.timestamp for a in self.anomalies_detected) if self.anomalies_detected else None
        }
    
    def clear_history(self):
        """Limpa todo o histórico de anomalias"""
        self.anomalies_detected.clear()
        self.ip_attempts.clear()
        self.user_attempts.clear()
        logging.info("🧹 Histórico de anomalias limpo") 