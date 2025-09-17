"""
AGENTE IA - Sistema de Alertas por Email
========================================
Sistema profissional para envio de alertas de anomalias
Suporte a templates HTML e texto simples
"""

import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from datetime import datetime
from typing import List, Dict, Any, Optional
import logging
import os
from ..core.config_loader import config
from ..core.anomaly_detector import Anomaly

class EmailSender:
    """Sistema inteligente de envio de emails para alertas"""
    
    def __init__(self):
        """Inicializa o sistema de email"""
        self.email_config = config.get_email_config()
        self.smtp_server = None
        self.is_connected = False
        
        # Configurações
        self.max_retries = 3
        self.retry_delay = 5
        
        # Templates de email
        self.templates = {
            'anomaly_alert': self._get_anomaly_template(),
            'system_status': self._get_status_template(),
            'daily_report': self._get_daily_report_template()
        }
        
    def connect(self) -> bool:
        """
        Conecta ao servidor SMTP
        
        Returns:
            True se conectado com sucesso
        """
        try:
            # Cria conexão SSL
            context = ssl.create_default_context()
            self.smtp_server = smtplib.SMTP(
                self.email_config['servidor_smtp'], 
                self.email_config['porta']
            )
            
            # Inicia TLS
            self.smtp_server.starttls(context=context)
            
            # Faz login
            self.smtp_server.login(
                self.email_config['usuario'],
                self.email_config['senha_app']
            )
            
            self.is_connected = True
            logging.info("✅ Conexão SMTP estabelecida")
            return True
            
        except Exception as e:
            logging.error(f"❌ Erro ao conectar SMTP: {e}")
            self.is_connected = False
            return False
    
    def disconnect(self):
        """Desconecta do servidor SMTP"""
        if self.smtp_server and self.is_connected:
            try:
                self.smtp_server.quit()
                self.is_connected = False
                logging.info("📧 Conexão SMTP encerrada")
            except Exception as e:
                logging.warning(f"Aviso ao desconectar SMTP: {e}")
    
    def send_anomaly_alert(self, anomaly: Anomaly) -> bool:
        """
        Envia alerta de anomalia detectada
        
        Args:
            anomaly: Anomalia detectada
            
        Returns:
            True se enviado com sucesso
        """
        try:
            # Determina prioridade do email
            priority = self._get_email_priority(anomaly.severidade)
            
            # Cria o email
            msg = MIMEMultipart('alternative')
            msg['From'] = self.email_config['usuario']
            msg['To'] = self.email_config['destinatario']
            msg['Subject'] = f"🚨 [AGENTE IA] {anomaly.severidade} - {anomaly.tipo.upper()}"
            msg['X-Priority'] = str(priority)
            
            # Conteúdo em texto simples
            text_content = self._create_text_alert(anomaly)
            text_part = MIMEText(text_content, 'plain', 'utf-8')
            
            # Conteúdo em HTML
            html_content = self._create_html_alert(anomaly)
            html_part = MIMEText(html_content, 'html', 'utf-8')
            
            msg.attach(text_part)
            msg.attach(html_part)
            
            # Envia o email
            return self._send_email(msg)
            
        except Exception as e:
            logging.error(f"❌ Erro ao enviar alerta de anomalia: {e}")
            return False
    
    def send_system_status(self, status_data: Dict[str, Any]) -> bool:
        """
        Envia relatório de status do sistema
        
        Args:
            status_data: Dados de status do sistema
            
        Returns:
            True se enviado com sucesso
        """
        try:
            msg = MIMEMultipart('alternative')
            msg['From'] = self.email_config['usuario']
            msg['To'] = self.email_config['destinatario']
            msg['Subject'] = f"📊 [AGENTE IA] Relatório de Status - {datetime.now().strftime('%d/%m/%Y')}"
            
            # Conteúdo
            text_content = self._create_text_status(status_data)
            html_content = self._create_html_status(status_data)
            
            msg.attach(MIMEText(text_content, 'plain', 'utf-8'))
            msg.attach(MIMEText(html_content, 'html', 'utf-8'))
            
            return self._send_email(msg)
            
        except Exception as e:
            logging.error(f"❌ Erro ao enviar status: {e}")
            return False
    
    def send_daily_report(self, anomalies: List[Anomaly], stats: Dict[str, Any]) -> bool:
        """
        Envia relatório diário de anomalias
        
        Args:
            anomalies: Lista de anomalias do dia
            stats: Estatísticas gerais
            
        Returns:
            True se enviado com sucesso
        """
        try:
            msg = MIMEMultipart('alternative')
            msg['From'] = self.email_config['usuario']
            msg['To'] = self.email_config['destinatario']
            msg['Subject'] = f"📈 [AGENTE IA] Relatório Diário - {datetime.now().strftime('%d/%m/%Y')}"
            
            # Conteúdo
            text_content = self._create_text_daily_report(anomalies, stats)
            html_content = self._create_html_daily_report(anomalies, stats)
            
            msg.attach(MIMEText(text_content, 'plain', 'utf-8'))
            msg.attach(MIMEText(html_content, 'html', 'utf-8'))
            
            return self._send_email(msg)
            
        except Exception as e:
            logging.error(f"❌ Erro ao enviar relatório diário: {e}")
            return False
    
    def test_connection(self) -> bool:
        """
        Testa conexão SMTP enviando email de teste
        
        Returns:
            True se teste passou
        """
        try:
            msg = MIMEText(
                f"""
🎯 AGENTE IA - TESTE DE CONEXÃO

Este é um email de teste para verificar se o sistema de alertas está funcionando corretamente.

📊 Informações do Teste:
• Data/Hora: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}
• Servidor SMTP: {self.email_config['servidor_smtp']}
• Porta: {self.email_config['porta']}
• Usuário: {self.email_config['usuario']}

✅ Se você recebeu este email, o sistema está configurado corretamente!

---
Agente IA - Detector de Anomalias Inteligente
Desenvolvido para universidades brasileiras
                """, 
                'plain', 
                'utf-8'
            )
            
            msg['From'] = self.email_config['usuario']
            msg['To'] = self.email_config['destinatario']
            msg['Subject'] = "✅ [AGENTE IA] Teste de Conexão SMTP"
            
            return self._send_email(msg)
            
        except Exception as e:
            logging.error(f"❌ Erro no teste de conexão: {e}")
            return False
    
    def _send_email(self, msg: MIMEMultipart) -> bool:
        """
        Envia email com retry automático
        
        Args:
            msg: Mensagem a ser enviada
            
        Returns:
            True se enviado com sucesso
        """
        for attempt in range(self.max_retries):
            try:
                # Conecta se necessário
                if not self.is_connected:
                    if not self.connect():
                        continue
                
                # Envia email
                self.smtp_server.send_message(msg)
                logging.info(f"📧 Email enviado: {msg['Subject']}")
                return True
                
            except Exception as e:
                logging.warning(f"⚠️ Tentativa {attempt + 1} falhou: {e}")
                self.is_connected = False
                
                if attempt < self.max_retries - 1:
                    import time
                    time.sleep(self.retry_delay)
        
        logging.error("❌ Falha ao enviar email após todas as tentativas")
        return False
    
    def _get_email_priority(self, severidade: str) -> int:
        """Determina prioridade do email baseado na severidade"""
        priority_map = {
            'CRITICA': 1,  # Alta prioridade
            'ALTA': 2,     # Média-alta
            'MEDIA': 3,    # Normal
            'BAIXA': 4     # Baixa
        }
        return priority_map.get(severidade, 3)
    
    def _create_text_alert(self, anomaly: Anomaly) -> str:
        """Cria conteúdo de alerta em texto simples"""
        return f"""
🚨 ALERTA DE ANOMALIA DETECTADA

Tipo: {anomaly.tipo.upper()}
Severidade: {anomaly.severidade}
Descrição: {anomaly.descricao}

📊 Detalhes:
• ID: {anomaly.id}
• Timestamp: {anomaly.timestamp.strftime('%d/%m/%Y %H:%M:%S')}
• Confiança: {anomaly.confianca:.2%}
• Logs relacionados: {len(anomaly.logs_relacionados)}

🔍 Informações Adicionais:
{self._format_details_text(anomaly.detalhes)}

📋 Amostras de Logs:
{self._format_log_samples_text(anomaly.logs_relacionados[:3])}

---
Agente IA - Detector de Anomalias Inteligente
Sistema de Monitoramento Automático
        """.strip()
    
    def _create_html_alert(self, anomaly: Anomaly) -> str:
        """Cria conteúdo de alerta em HTML"""
        severity_colors = {
            'CRITICA': '#f44336',
            'ALTA': '#ff9800', 
            'MEDIA': '#ff9800',
            'BAIXA': '#4caf50'
        }
        
        color = severity_colors.get(anomaly.severidade, '#ff9800')
        
        return f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <style>
        body {{ font-family: Arial, sans-serif; background: #f5f5f5; margin: 0; padding: 20px; }}
        .container {{ max-width: 600px; margin: 0 auto; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 4px 12px rgba(0,0,0,0.1); }}
        .header {{ background: {color}; color: white; padding: 20px; text-align: center; }}
        .header h1 {{ margin: 0; font-size: 24px; }}
        .content {{ padding: 30px; }}
        .info-box {{ background: #f8f9fa; padding: 15px; border-radius: 6px; margin: 15px 0; border-left: 4px solid {color}; }}
        .details {{ background: #fff3cd; padding: 15px; border-radius: 6px; border: 1px solid #ffeaa7; }}
        .logs {{ background: #1a1a1a; color: #00ff00; padding: 15px; border-radius: 6px; font-family: monospace; font-size: 12px; overflow-x: auto; }}
        .footer {{ background: #6c757d; color: white; padding: 15px; text-align: center; font-size: 12px; }}
        .badge {{ display: inline-block; padding: 4px 8px; border-radius: 4px; color: white; font-size: 12px; font-weight: bold; background: {color}; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🚨 ALERTA DE ANOMALIA</h1>
            <p>Agente IA - Sistema de Detecção</p>
        </div>
        
        <div class="content">
            <div class="info-box">
                <h3>📊 Informações da Anomalia</h3>
                <p><strong>Tipo:</strong> <span class="badge">{anomaly.tipo.upper()}</span></p>
                <p><strong>Severidade:</strong> <span class="badge">{anomaly.severidade}</span></p>
                <p><strong>Timestamp:</strong> {anomaly.timestamp.strftime('%d/%m/%Y %H:%M:%S')}</p>
                <p><strong>Confiança:</strong> {anomaly.confianca:.2%}</p>
                <p><strong>ID:</strong> {anomaly.id}</p>
            </div>
            
            <div class="info-box">
                <h3>📝 Descrição</h3>
                <p>{anomaly.descricao}</p>
            </div>
            
            <div class="details">
                <h3>🔍 Detalhes Técnicos</h3>
                {self._format_details_html(anomaly.detalhes)}
            </div>
            
            <div class="info-box">
                <h3>📋 Logs Relacionados ({len(anomaly.logs_relacionados)})</h3>
                <div class="logs">
{self._format_log_samples_html(anomaly.logs_relacionados[:3])}
                </div>
            </div>
        </div>
        
        <div class="footer">
            Agente IA - Detector de Anomalias Inteligente<br>
            Desenvolvido para universidades brasileiras
        </div>
    </div>
</body>
</html>
        """.strip()
    
    def _create_text_status(self, status_data: Dict[str, Any]) -> str:
        """Cria relatório de status em texto"""
        return f"""
📊 RELATÓRIO DE STATUS DO SISTEMA

Data: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}

🎯 Status Geral: {status_data.get('status', 'Desconhecido')}

📈 Estatísticas:
• Logs processados: {status_data.get('logs_processados', 0)}
• Anomalias detectadas: {status_data.get('anomalias_detectadas', 0)}
• Uptime: {status_data.get('uptime', 'N/A')}
• Uso de memória: {status_data.get('memoria_uso', 'N/A')}

🔧 Componentes:
• Coletor de Logs: {status_data.get('collector_status', 'N/A')}
• Detector de Anomalias: {status_data.get('detector_status', 'N/A')}
• Sistema de Email: {status_data.get('email_status', 'N/A')}

---
Agente IA - Sistema de Monitoramento
        """.strip()
    
    def _create_html_status(self, status_data: Dict[str, Any]) -> str:
        """Cria relatório de status em HTML"""
        # Implementação similar ao HTML de alerta
        return f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <style>
        body {{ font-family: Arial, sans-serif; background: #f5f5f5; margin: 0; padding: 20px; }}
        .container {{ max-width: 600px; margin: 0 auto; background: white; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); }}
        .header {{ background: #4dd0e1; color: white; padding: 20px; text-align: center; }}
        .content {{ padding: 30px; }}
        .status-ok {{ color: #4caf50; font-weight: bold; }}
        .status-error {{ color: #f44336; font-weight: bold; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>📊 RELATÓRIO DE STATUS</h1>
            <p>Agente IA - Sistema de Detecção</p>
        </div>
        <div class="content">
            <h3>🎯 Status Geral</h3>
            <p class="status-ok">{status_data.get('status', 'Desconhecido')}</p>
            
            <h3>📈 Estatísticas</h3>
            <ul>
                <li>Logs processados: {status_data.get('logs_processados', 0)}</li>
                <li>Anomalias detectadas: {status_data.get('anomalias_detectadas', 0)}</li>
                <li>Uptime: {status_data.get('uptime', 'N/A')}</li>
            </ul>
        </div>
    </div>
</body>
</html>
        """.strip()
    
    def _create_text_daily_report(self, anomalies: List[Anomaly], stats: Dict[str, Any]) -> str:
        """Cria relatório diário em texto"""
        return f"""
📈 RELATÓRIO DIÁRIO DE ANOMALIAS

Data: {datetime.now().strftime('%d/%m/%Y')}

📊 Resumo do Dia:
• Total de anomalias: {len(anomalies)}
• Logs processados: {stats.get('total_logs', 0)}
• Taxa de detecção: {stats.get('detection_rate', 0):.2%}

🚨 Anomalias por Severidade:
{self._format_anomaly_summary_text(anomalies)}

📋 Top 5 Anomalias:
{self._format_top_anomalies_text(anomalies[:5])}

---
Agente IA - Relatório Automático
        """.strip()
    
    def _create_html_daily_report(self, anomalies: List[Anomaly], stats: Dict[str, Any]) -> str:
        """Cria relatório diário em HTML"""
        # Implementação similar aos outros templates HTML
        return "<!-- HTML do relatório diário -->"
    
    def _format_details_text(self, details: Dict[str, Any]) -> str:
        """Formata detalhes para texto simples"""
        if not details:
            return "Nenhum detalhe adicional disponível."
        
        formatted = []
        for key, value in details.items():
            formatted.append(f"• {key}: {value}")
        
        return "\n".join(formatted)
    
    def _format_details_html(self, details: Dict[str, Any]) -> str:
        """Formata detalhes para HTML"""
        if not details:
            return "<p>Nenhum detalhe adicional disponível.</p>"
        
        formatted = ["<ul>"]
        for key, value in details.items():
            formatted.append(f"<li><strong>{key}:</strong> {value}</li>")
        formatted.append("</ul>")
        
        return "".join(formatted)
    
    def _format_log_samples_text(self, logs) -> str:
        """Formata amostras de logs para texto"""
        if not logs:
            return "Nenhuma amostra disponível."
        
        formatted = []
        for i, log in enumerate(logs, 1):
            formatted.append(f"{i}. [{log.timestamp.strftime('%H:%M:%S')}] {log.message[:100]}...")
        
        return "\n".join(formatted)
    
    def _format_log_samples_html(self, logs) -> str:
        """Formata amostras de logs para HTML"""
        if not logs:
            return "Nenhuma amostra disponível."
        
        formatted = []
        for log in logs:
            formatted.append(f"[{log.timestamp.strftime('%H:%M:%S')}] {log.message[:100]}...")
        
        return "\n".join(formatted)
    
    def _format_anomaly_summary_text(self, anomalies: List[Anomaly]) -> str:
        """Formata resumo de anomalias para texto"""
        if not anomalies:
            return "Nenhuma anomalia detectada hoje."
        
        summary = {}
        for anomaly in anomalies:
            summary[anomaly.severidade] = summary.get(anomaly.severidade, 0) + 1
        
        formatted = []
        for severity, count in summary.items():
            formatted.append(f"• {severity}: {count}")
        
        return "\n".join(formatted)
    
    def _format_top_anomalies_text(self, anomalies: List[Anomaly]) -> str:
        """Formata top anomalias para texto"""
        if not anomalies:
            return "Nenhuma anomalia para exibir."
        
        formatted = []
        for i, anomaly in enumerate(anomalies, 1):
            formatted.append(f"{i}. [{anomaly.severidade}] {anomaly.tipo} - {anomaly.descricao[:80]}...")
        
        return "\n".join(formatted)
    
    def _get_anomaly_template(self) -> str:
        """Template para alertas de anomalia"""
        return "anomaly_alert"
    
    def _get_status_template(self) -> str:
        """Template para status do sistema"""
        return "system_status"
    
    def _get_daily_report_template(self) -> str:
        """Template para relatório diário"""
        return "daily_report"
    
    def __del__(self):
        """Cleanup ao destruir objeto"""
        self.disconnect()

# Instância global para fácil acesso
email_sender = EmailSender() 