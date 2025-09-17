"""
AGENTE IA - Carregador de Configurações
========================================
Sistema profissional para carregar configurações do sistema
Desenvolvido para universidades brasileiras
"""

import yaml
import os
from typing import Dict, Any
from pathlib import Path
import logging

class ConfigLoader:
    """Carregador inteligente de configurações do sistema"""
    
    def __init__(self, config_path: str = None):
        """
        Inicializa o carregador de configurações
        
        Args:
            config_path: Caminho para o arquivo de configuração
        """
        self.config_path = config_path or self._get_default_config_path()
        self.config = {}
        self._load_config()
        
    def _get_default_config_path(self) -> str:
        """Obtém o caminho padrão do arquivo de configuração"""
        current_dir = Path(__file__).parent.parent.parent
        return str(current_dir / "config" / "config.yaml")
    
    def _load_config(self) -> None:
        """Carrega as configurações do arquivo YAML"""
        try:
            with open(self.config_path, 'r', encoding='utf-8') as file:
                self.config = yaml.safe_load(file)
            
            logging.info(f"✅ Configurações carregadas: {self.config_path}")
            
        except FileNotFoundError:
            logging.error(f"❌ Arquivo de configuração não encontrado: {self.config_path}")
            self._create_default_config()
            
        except yaml.YAMLError as e:
            logging.error(f"❌ Erro ao carregar YAML: {e}")
            raise
    
    def _create_default_config(self) -> None:
        """Cria configuração padrão se não existir"""
        default_config = {
            'sistema': {
                'nome': 'Agente IA',
                'versao': '1.0.0',
                'debug': True
            },
            'alertas': {
                'email': {
                    'usuario': 'chalenge.agenteia@gmail.com',
                    'senha_app': 'bjtkykpjhyojinmp'
                }
            }
        }
        
        os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
        with open(self.config_path, 'w', encoding='utf-8') as file:
            yaml.dump(default_config, file, default_flow_style=False)
        
        self.config = default_config
        logging.info("✅ Configuração padrão criada")
    
    def get(self, key_path: str, default: Any = None) -> Any:
        """
        Obtém valor de configuração usando notação de ponto
        
        Args:
            key_path: Caminho da chave (ex: 'alertas.email.usuario')
            default: Valor padrão se a chave não existir
            
        Returns:
            Valor da configuração ou valor padrão
        """
        keys = key_path.split('.')
        value = self.config
        
        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return default
                
        return value
    
    def get_email_config(self) -> Dict[str, str]:
        """Obtém configurações específicas de email"""
        return {
            'servidor_smtp': self.get('alertas.email.servidor_smtp', 'smtp.gmail.com'),
            'porta': self.get('alertas.email.porta', 587),
            'usuario': self.get('alertas.email.usuario'),
            'senha_app': self.get('alertas.email.senha_app'),
            'destinatario': self.get('alertas.email.destinatario')
        }
    
    def get_ia_config(self) -> Dict[str, Any]:
        """Obtém configurações da IA Híbrida Adaptativa"""
        return {
            'algoritmos': self.get('deteccao.ia_hibrida.algoritmos', []),
            'auto_selecao': self.get('deteccao.ia_hibrida.auto_selecao', True),
            'retreinamento_automatico': self.get('deteccao.ia_hibrida.retreinamento_automatico', True),
            'threshold_confianca': self.get('deteccao.ia_hibrida.threshold_confianca', 0.85)
        }
    
    def get_frontend_colors(self) -> Dict[str, str]:
        """Obtém configurações de cores do frontend"""
        return {
            'fundo_principal': self.get('frontend.cores.fundo_principal', '#1a1a1a'),
            'fundo_secundario': self.get('frontend.cores.fundo_secundario', '#2d2d2d'),
            'botoes': self.get('frontend.cores.botoes', '#4dd0e1'),
            'texto_principal': self.get('frontend.cores.texto_principal', '#ffffff'),
            'texto_secundario': self.get('frontend.cores.texto_secundario', '#b0b0b0')
        }
    
    def reload(self) -> None:
        """Recarrega as configurações do arquivo"""
        self._load_config()
        logging.info("🔄 Configurações recarregadas")

# Instância global para fácil acesso
config = ConfigLoader() 