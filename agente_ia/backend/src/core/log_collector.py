"""
AGENTE IA - Coletor de Logs (FASE 1 + EXPANSÃO INDEPENDENTE)
============================================================
Sistema inteligente de coleta e processamento de logs
Suporte multifonte: Sistema Operacional, Syslog, SSH Remoto
Completamente independente de ferramentas SIEM externas
"""

import os
import re
import pandas as pd
from datetime import datetime, timedelta
from typing import List, Dict, Any, Generator
from pathlib import Path
import logging
import subprocess
import platform
import socket
import socketserver
import threading
import paramiko
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import time
import json

class LogEntry:
    """Representa uma entrada de log processada"""
    
    def __init__(self, timestamp: datetime, source: str, level: str, message: str, raw: str, source_type: str = "file"):
        self.timestamp = timestamp
        self.source = source
        self.level = level
        self.message = message
        self.raw = raw
        self.source_type = source_type  # file, system, syslog, ssh
        self.ip_address = self._extract_ip()
        self.user = self._extract_user()
        
    def _extract_ip(self) -> str:
        """Extrai endereço IP da mensagem"""
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        match = re.search(ip_pattern, self.message)
        return match.group(0) if match else None
        
    def _extract_user(self) -> str:
        """Extrai usuário da mensagem"""
        user_patterns = [
            r'user[:\s]+([a-zA-Z0-9_-]+)',
            r'login[:\s]+([a-zA-Z0-9_-]+)',
            r'for\s+([a-zA-Z0-9_-]+)\s+from'
        ]
        
        for pattern in user_patterns:
            match = re.search(pattern, self.message, re.IGNORECASE)
            if match:
                return match.group(1)
        return None
    
    def to_dict(self) -> Dict[str, Any]:
        """Converte para dicionário"""
        return {
            'timestamp': self.timestamp,
            'source': self.source,
            'source_type': self.source_type,
            'level': self.level,
            'message': self.message,
            'ip_address': self.ip_address,
            'user': self.user,
            'raw': self.raw
        }

class SyslogHandler(socketserver.BaseRequestHandler):
    """Handler para servidor Syslog"""
    
    def __init__(self, request, client_address, server, log_collector):
        self.log_collector = log_collector
        super().__init__(request, client_address, server)
    
    def handle(self):
        data = self.request[0].strip().decode('utf-8', errors='ignore')
        client_ip = self.client_address[0]
        
        # Processa mensagem syslog
        entry = self.log_collector._parse_syslog_message(data, client_ip)
        if entry:
            self.log_collector.processed_logs.append(entry)
            logging.info(f"📨 Syslog recebido de {client_ip}: {entry.level}")

class SyslogServer(socketserver.ThreadingUDPServer):
    """Servidor Syslog UDP threading"""
    
    def __init__(self, server_address, handler_class, log_collector):
        self.log_collector = log_collector
        super().__init__(server_address, lambda *args: handler_class(*args, log_collector))

class LogFileHandler(FileSystemEventHandler):
    """Handler para monitoramento de arquivos de log"""
    
    def __init__(self, callback):
        self.callback = callback
        
    def on_modified(self, event):
        if not event.is_directory:
            self.callback(event.src_path)

class LogCollector:
    """Coletor inteligente de logs para o Agente IA - Completamente Independente"""
    
    def __init__(self):
        """Inicializa o coletor de logs"""
        self.logs_directory = self._get_logs_directory()
        self.processed_logs = []
        self.observers = []
        self.is_monitoring = False
        self.syslog_server = None
        self.syslog_thread = None
        
        # Padrões de parsing para diferentes tipos de log
        self.log_patterns = {
            'syslog': r'(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\w+)\s+(.+)',
            'auth': r'(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\w+)\s+(.+)',
            'apache': r'(\d+\.\d+\.\d+\.\d+)\s+.+\s+\[([^\]]+)\]\s+"(.+)"\s+(\d+)',
            'generic': r'(.+)'
        }
        
        # Configurações SSH para coleta remota
        self.ssh_configs = []
        
    def _get_logs_directory(self) -> str:
        """Obtém o diretório dos logs da universidade"""
        current_dir = Path(__file__).parent.parent.parent.parent
        return str(current_dir / "logs-analizes")
    
    # === COLETA DE LOGS DO SISTEMA OPERACIONAL ===
    
    def collect_system_logs(self) -> List[LogEntry]:
        """Coleta logs diretamente do sistema operacional"""
        system_logs = []
        
        if platform.system() == "Linux":
            system_logs.extend(self._collect_linux_logs())
        elif platform.system() == "Windows":
            system_logs.extend(self._collect_windows_logs())
        elif platform.system() == "Darwin":  # macOS
            system_logs.extend(self._collect_macos_logs())
        
        logging.info(f"🖥️ Coletados {len(system_logs)} logs do sistema operacional")
        return system_logs
    
    def _collect_linux_logs(self) -> List[LogEntry]:
        """Coleta logs do Linux"""
        logs = []
        
        # Logs do systemd/journalctl
        try:
            result = subprocess.run(['journalctl', '--since', '1 hour ago', '--no-pager'], 
                                  capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if line.strip():
                        entry = self._parse_log_line(line, "journalctl", "system")
                        if entry:
                            logs.append(entry)
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            logging.warning(f"⚠️ Erro ao coletar journalctl: {e}")
        
        # Logs de autenticação
        auth_files = ['/var/log/auth.log', '/var/log/secure']
        for auth_file in auth_files:
            if os.path.exists(auth_file):
                try:
                    logs.extend(self._read_system_log_file(auth_file, "auth-system"))
                except PermissionError:
                    logging.warning(f"⚠️ Sem permissão para ler {auth_file}")
        
        # Logs do sistema
        sys_files = ['/var/log/syslog', '/var/log/messages']
        for sys_file in sys_files:
            if os.path.exists(sys_file):
                try:
                    logs.extend(self._read_system_log_file(sys_file, "syslog-system"))
                except PermissionError:
                    logging.warning(f"⚠️ Sem permissão para ler {sys_file}")
        
        return logs
    
    def _collect_windows_logs(self) -> List[LogEntry]:
        """Coleta logs do Windows Event Log"""
        logs = []
        
        try:
            # Logs de Segurança
            result = subprocess.run(['wevtutil', 'qe', 'Security', '/c:100', '/rd:true', '/f:text'], 
                                  capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if line.strip():
                        entry = self._parse_log_line(line, "Windows-Security", "system")
                        if entry:
                            logs.append(entry)
            
            # Logs do Sistema
            result = subprocess.run(['wevtutil', 'qe', 'System', '/c:100', '/rd:true', '/f:text'], 
                                  capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if line.strip():
                        entry = self._parse_log_line(line, "Windows-System", "system")
                        if entry:
                            logs.append(entry)
                            
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            logging.warning(f"⚠️ Erro ao coletar logs do Windows: {e}")
        
        return logs
    
    def _collect_macos_logs(self) -> List[LogEntry]:
        """Coleta logs do macOS"""
        logs = []
        
        try:
            # Logs do sistema usando log command
            result = subprocess.run(['log', 'show', '--predicate', 'eventType == logEvent', 
                                   '--info', '--last', '1h'], 
                                  capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if line.strip():
                        entry = self._parse_log_line(line, "macOS-System", "system")
                        if entry:
                            logs.append(entry)
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            logging.warning(f"⚠️ Erro ao coletar logs do macOS: {e}")
        
        return logs
    
    def _read_system_log_file(self, file_path: str, source: str) -> List[LogEntry]:
        """Lê arquivo de log do sistema (últimas 100 linhas)"""
        logs = []
        
        try:
            # Usa tail para ler apenas as últimas linhas
            result = subprocess.run(['tail', '-100', file_path], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if line.strip():
                        entry = self._parse_log_line(line, source, "system")
                        if entry:
                            logs.append(entry)
        except Exception as e:
            logging.warning(f"⚠️ Erro ao ler {file_path}: {e}")
        
        return logs
    
    # === SERVIDOR SYSLOG ===
    
    def start_syslog_server(self, port: int = 514):
        """Inicia servidor Syslog para receber logs via rede"""
        try:
            # Usa porta alternativa se 514 não estiver disponível (requer root)
            if port == 514 and os.geteuid() != 0:
                port = 5140
                logging.info("📡 Usando porta 5140 (porta 514 requer privilégios root)")
            
            self.syslog_server = SyslogServer(('0.0.0.0', port), SyslogHandler, self)
            self.syslog_thread = threading.Thread(target=self.syslog_server.serve_forever)
            self.syslog_thread.daemon = True
            self.syslog_thread.start()
            
            logging.info(f"📡 Servidor Syslog iniciado na porta {port}")
            return True
            
        except Exception as e:
            logging.error(f"❌ Erro ao iniciar servidor Syslog: {e}")
            return False
    
    def stop_syslog_server(self):
        """Para o servidor Syslog"""
        if self.syslog_server:
            self.syslog_server.shutdown()
            self.syslog_server = None
            logging.info("📡 Servidor Syslog parado")
    
    def _parse_syslog_message(self, message: str, client_ip: str) -> LogEntry:
        """Processa mensagem syslog recebida"""
        # Formato padrão syslog: <priority>timestamp hostname tag: message
        syslog_pattern = r'<(\d+)>(.+)'
        match = re.match(syslog_pattern, message)
        
        if match:
            priority = int(match.group(1))
            content = match.group(2)
            
            # Extrai nível de severidade da prioridade
            severity = priority & 7
            levels = ['EMERGENCY', 'ALERT', 'CRITICAL', 'ERROR', 'WARNING', 'NOTICE', 'INFO', 'DEBUG']
            level = levels[severity] if severity < len(levels) else 'INFO'
            
            timestamp = self._extract_timestamp(content)
            
            return LogEntry(
                timestamp=timestamp,
                source=f"syslog-{client_ip}",
                level=level,
                message=content,
                raw=message,
                source_type="syslog"
            )
        else:
            # Mensagem sem formato padrão
            return LogEntry(
                timestamp=datetime.now(),
                source=f"syslog-{client_ip}",
                level='INFO',
                message=message,
                raw=message,
                source_type="syslog"
            )
    
    # === COLETA REMOTA VIA SSH ===
    
    def add_ssh_source(self, hostname: str, username: str, password: str = None, 
                      key_file: str = None, log_paths: List[str] = None):
        """Adiciona uma fonte SSH para coleta remota"""
        ssh_config = {
            'hostname': hostname,
            'username': username,
            'password': password,
            'key_file': key_file,
            'log_paths': log_paths or ['/var/log/auth.log', '/var/log/syslog']
        }
        self.ssh_configs.append(ssh_config)
        logging.info(f"🔗 Fonte SSH adicionada: {username}@{hostname}")
    
    def collect_ssh_logs(self) -> List[LogEntry]:
        """Coleta logs de todas as fontes SSH configuradas"""
        all_logs = []
        
        for config in self.ssh_configs:
            try:
                logs = self._collect_from_ssh_host(config)
                all_logs.extend(logs)
            except Exception as e:
                logging.error(f"❌ Erro ao coletar de {config['hostname']}: {e}")
        
        logging.info(f"🔗 Coletados {len(all_logs)} logs via SSH")
        return all_logs
    
    def _collect_from_ssh_host(self, config: Dict) -> List[LogEntry]:
        """Coleta logs de um host específico via SSH"""
        logs = []
        
        try:
            # Estabelece conexão SSH
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            if config['key_file']:
                ssh.connect(config['hostname'], username=config['username'], 
                           key_filename=config['key_file'], timeout=30)
            else:
                ssh.connect(config['hostname'], username=config['username'], 
                           password=config['password'], timeout=30)
            
            # Coleta logs de cada caminho configurado
            for log_path in config['log_paths']:
                stdin, stdout, stderr = ssh.exec_command(f'tail -100 {log_path}')
                
                for line in stdout:
                    line = line.strip()
                    if line:
                        entry = self._parse_log_line(line, f"ssh-{config['hostname']}", "ssh")
                        if entry:
                            logs.append(entry)
            
            ssh.close()
            
        except Exception as e:
            logging.error(f"❌ Erro SSH {config['hostname']}: {e}")
        
        return logs

    # === MÉTODOS EXISTENTES (mantidos) ===
    
    def load_university_logs(self) -> List[LogEntry]:
        """
        Carrega os 4 arquivos de logs da universidade
        
        Returns:
            Lista de LogEntry processadas
        """
        log_files = [
            "Anon1_anon.txt",
            "Anon2_anon.txt", 
            "Anon3_anon.txt",
            "Anon4_anon_v3.txt"
        ]
        
        all_entries = []
        
        for log_file in log_files:
            file_path = os.path.join(self.logs_directory, log_file)
            
            if os.path.exists(file_path):
                logging.info(f"📁 Carregando: {log_file}")
                entries = self._parse_log_file(file_path, log_file)
                all_entries.extend(entries)
                logging.info(f"✅ {len(entries)} entradas carregadas de {log_file}")
            else:
                logging.warning(f"⚠️ Arquivo não encontrado: {log_file}")
        
        self.processed_logs.extend(all_entries)
        logging.info(f"🎯 Total de logs carregados: {len(all_entries)}")
        
        return all_entries
    
    def _parse_log_file(self, file_path: str, source: str) -> List[LogEntry]:
        """
        Faz parsing de um arquivo de log específico
        
        Args:
            file_path: Caminho para o arquivo
            source: Nome da fonte do log
            
        Returns:
            Lista de LogEntry
        """
        entries = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
                for line_num, line in enumerate(file, 1):
                    line = line.strip()
                    if not line:
                        continue
                    
                    try:
                        entry = self._parse_log_line(line, source)
                        if entry:
                            entries.append(entry)
                    except Exception as e:
                        logging.debug(f"Erro ao processar linha {line_num}: {e}")
                        
        except Exception as e:
            logging.error(f"❌ Erro ao ler arquivo {file_path}: {e}")
            
        return entries
    
    def _parse_log_line(self, line: str, source: str, source_type: str = "file") -> LogEntry:
        """
        Faz parsing de uma linha de log
        
        Args:
            line: Linha do log
            source: Fonte do log
            source_type: Tipo da fonte (file, system, syslog, ssh)
            
        Returns:
            LogEntry ou None
        """
        # Tenta extrair timestamp
        timestamp = self._extract_timestamp(line)
        
        # Determina o nível do log
        level = self._determine_log_level(line)
        
        # Limpa a mensagem
        message = self._clean_message(line)
        
        return LogEntry(
            timestamp=timestamp,
            source=source,
            level=level,
            message=message,
            raw=line,
            source_type=source_type
        )
    
    def _extract_timestamp(self, line: str) -> datetime:
        """Extrai timestamp da linha de log"""
        timestamp_patterns = [
            r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})',
            r'(\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2})',
            r'(\w+\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})',
            r'(\d{10})',  # Unix timestamp
        ]
        
        for pattern in timestamp_patterns:
            match = re.search(pattern, line)
            if match:
                try:
                    timestamp_str = match.group(1)
                    
                    # Tenta diferentes formatos
                    formats = [
                        '%Y-%m-%d %H:%M:%S',
                        '%d/%m/%Y %H:%M:%S',
                        '%b %d %H:%M:%S',
                        '%m/%d/%Y %H:%M:%S'
                    ]
                    
                    for fmt in formats:
                        try:
                            dt = datetime.strptime(timestamp_str, fmt)
                            # Se não tem ano, usa o ano atual
                            if dt.year == 1900:
                                dt = dt.replace(year=datetime.now().year)
                            return dt
                        except ValueError:
                            continue
                            
                    # Se é timestamp Unix
                    if timestamp_str.isdigit():
                        return datetime.fromtimestamp(int(timestamp_str))
                        
                except Exception:
                    pass
        
        # Se não encontrou timestamp, usa timestamp atual
        return datetime.now()
    
    def _determine_log_level(self, line: str) -> str:
        """Determina o nível de severidade do log"""
        line_lower = line.lower()
        
        if any(word in line_lower for word in ['error', 'err', 'failed', 'failure', 'exception']):
            return 'ERROR'
        elif any(word in line_lower for word in ['warning', 'warn', 'alert']):
            return 'WARNING'
        elif any(word in line_lower for word in ['critical', 'crit', 'fatal', 'emergency']):
            return 'CRITICAL'
        elif any(word in line_lower for word in ['debug', 'trace']):
            return 'DEBUG'
        else:
            return 'INFO'
    
    def _clean_message(self, line: str) -> str:
        """Limpa e normaliza a mensagem do log"""
        # Remove caracteres especiais desnecessários
        cleaned = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', line)
        
        # Remove espaços extras
        cleaned = re.sub(r'\s+', ' ', cleaned).strip()
        
        return cleaned
    
    def get_logs_by_timerange(self, start_time: datetime, end_time: datetime) -> List[LogEntry]:
        """Obtém logs em um intervalo de tempo"""
        return [
            log for log in self.processed_logs
            if start_time <= log.timestamp <= end_time
        ]
    
    def get_logs_by_level(self, level: str) -> List[LogEntry]:
        """Obtém logs por nível de severidade"""
        return [log for log in self.processed_logs if log.level == level]
    
    def get_logs_by_ip(self, ip_address: str) -> List[LogEntry]:
        """Obtém logs de um IP específico"""
        return [log for log in self.processed_logs if log.ip_address == ip_address]
    
    def get_statistics(self) -> Dict[str, Any]:
        """Obtém estatísticas dos logs coletados"""
        if not self.processed_logs:
            return {}
        
        df = pd.DataFrame([log.to_dict() for log in self.processed_logs])
        
        return {
            'total_logs': len(self.processed_logs),
            'logs_por_nivel': df['level'].value_counts().to_dict(),
            'logs_por_fonte': df['source'].value_counts().to_dict(),
            'ips_unicos': df['ip_address'].nunique() if 'ip_address' in df.columns else 0,
            'usuarios_unicos': df['user'].nunique() if 'user' in df.columns else 0,
            'periodo': {
                'inicio': min(log.timestamp for log in self.processed_logs),
                'fim': max(log.timestamp for log in self.processed_logs)
            }
        }
    
    def start_monitoring(self, callback=None):
        """Inicia monitoramento em tempo real"""
        if self.is_monitoring:
            return
        
        self.is_monitoring = True
        
        # Monitor do diretório de logs
        event_handler = LogFileHandler(callback or self._on_file_change)
        observer = Observer()
        observer.schedule(event_handler, self.logs_directory, recursive=True)
        observer.start()
        
        self.observers.append(observer)
        logging.info("🔍 Monitoramento de logs iniciado")
    
    def stop_monitoring(self):
        """Para o monitoramento"""
        for observer in self.observers:
            observer.stop()
            observer.join()
        
        self.observers.clear()
        self.is_monitoring = False
        logging.info("⏹️ Monitoramento de logs parado")
    
    def _on_file_change(self, file_path: str):
        """Callback chamado quando um arquivo é modificado"""
        logging.info(f"📝 Arquivo modificado: {file_path}")
        # Reprocessa o arquivo modificado
        # Implementar lógica de processamento incremental aqui
    
    def export_to_dataframe(self) -> pd.DataFrame:
        """Exporta logs processados para DataFrame do pandas"""
        if not self.processed_logs:
            return pd.DataFrame()
        
        return pd.DataFrame([log.to_dict() for log in self.processed_logs])
    
    # === MÉTODO PRINCIPAL DE COLETA INTEGRADA ===
    
    def collect_all_logs(self) -> Dict[str, Any]:
        """
        Método principal que coleta logs de todas as fontes configuradas
        
        Returns:
            Dicionário com estatísticas da coleta
        """
        total_logs_before = len(self.processed_logs)
        
        # 1. Carrega logs da universidade (arquivos locais)
        university_logs = self.load_university_logs()
        
        # 2. Coleta logs do sistema operacional
        system_logs = self.collect_system_logs()
        self.processed_logs.extend(system_logs)
        
        # 3. Coleta logs via SSH (se configurado)
        if self.ssh_configs:
            ssh_logs = self.collect_ssh_logs()
            self.processed_logs.extend(ssh_logs)
        
        total_logs_after = len(self.processed_logs)
        new_logs = total_logs_after - total_logs_before
        
        stats = {
            'total_logs_collected': new_logs,
            'university_logs': len(university_logs),
            'system_logs': len(system_logs),
            'ssh_logs': len(self.collect_ssh_logs()) if self.ssh_configs else 0,
            'sources': {
                'file': len([log for log in self.processed_logs if log.source_type == 'file']),
                'system': len([log for log in self.processed_logs if log.source_type == 'system']),
                'syslog': len([log for log in self.processed_logs if log.source_type == 'syslog']),
                'ssh': len([log for log in self.processed_logs if log.source_type == 'ssh'])
            },
            'syslog_server_running': self.syslog_server is not None
        }
        
        logging.info(f"🎯 Coleta completa: {new_logs} novos logs de {len(stats['sources'])} tipos de fonte")
        return stats
    
    def start_all_collection_services(self):
        """Inicia todos os serviços de coleta disponíveis"""
        # Inicia monitoramento de arquivos
        self.start_monitoring()
        
        # Inicia servidor Syslog
        self.start_syslog_server()
        
        logging.info("🚀 Todos os serviços de coleta iniciados")
    
    def stop_all_collection_services(self):
        """Para todos os serviços de coleta"""
        self.stop_monitoring()
        self.stop_syslog_server()
        
        logging.info("⏹️ Todos os serviços de coleta parados")

    def __del__(self):
        """Cleanup quando o objeto é destruído"""
        self.stop_all_collection_services() 