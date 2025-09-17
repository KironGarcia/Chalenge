#!/usr/bin/env python3
"""
DEMO - Agente IA Coleta Independente
===================================
Script de demonstração das novas capacidades de coleta
Completamente independente de ferramentas SIEM externas

Como usar:
    python demo_coleta_independente.py
"""

import sys
import os
import time
import logging
from datetime import datetime

# Adiciona o diretório src ao path
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from core.log_collector import LogCollector
from core.config_loader import config

def configurar_logging():
    """Configura logging para a demonstração"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler('demo_coleta.log')
        ]
    )

def demonstrar_coleta_arquivos(collector):
    """Demonstra coleta de arquivos locais"""
    print("\n" + "="*60)
    print("🗂️  DEMONSTRAÇÃO: COLETA DE ARQUIVOS LOCAIS")
    print("="*60)
    
    logs = collector.load_university_logs()
    print(f"✅ Carregados {len(logs)} logs dos arquivos da universidade")
    
    if logs:
        print(f"📊 Exemplo de log: {logs[0].message[:100]}...")
        print(f"🏷️  Fonte: {logs[0].source}")
        print(f"📅 Timestamp: {logs[0].timestamp}")

def demonstrar_coleta_sistema(collector):
    """Demonstra coleta do sistema operacional"""
    print("\n" + "="*60)
    print("🖥️  DEMONSTRAÇÃO: COLETA DO SISTEMA OPERACIONAL")
    print("="*60)
    
    system_logs = collector.collect_system_logs()
    print(f"✅ Coletados {len(system_logs)} logs do sistema operacional")
    
    if system_logs:
        print(f"📊 Exemplo de log do sistema: {system_logs[0].message[:100]}...")
        print(f"🏷️  Fonte: {system_logs[0].source}")
        print(f"📅 Timestamp: {system_logs[0].timestamp}")

def demonstrar_servidor_syslog(collector):
    """Demonstra servidor Syslog"""
    print("\n" + "="*60)
    print("📡 DEMONSTRAÇÃO: SERVIDOR SYSLOG")
    print("="*60)
    
    # Inicia servidor Syslog
    success = collector.start_syslog_server()
    
    if success:
        print("✅ Servidor Syslog iniciado com sucesso!")
        print("📡 Aguardando mensagens syslog na porta 5140...")
        print("💡 Para testar, execute em outro terminal:")
        print("   logger -n localhost -P 5140 'Teste do Agente IA'")
        print("   ou configure seus equipamentos para enviar syslog para este servidor")
        
        # Aguarda alguns segundos para possíveis mensagens
        time.sleep(5)
        
        syslog_logs = [log for log in collector.processed_logs if log.source_type == 'syslog']
        print(f"📨 Recebidas {len(syslog_logs)} mensagens syslog")
        
        collector.stop_syslog_server()
    else:
        print("❌ Falha ao iniciar servidor Syslog")

def demonstrar_ssh_remoto(collector):
    """Demonstra coleta SSH remota"""
    print("\n" + "="*60)
    print("🔗 DEMONSTRAÇÃO: COLETA SSH REMOTA")
    print("="*60)
    
    print("ℹ️  A coleta SSH está desabilitada por padrão por segurança")
    print("💡 Para habilitar, configure o arquivo config.yaml:")
    print("   ssh_remoto:")
    print("     ativo: true")
    print("     hosts:")
    print("       - hostname: 'servidor.exemplo.com'")
    print("         username: 'admin'")
    print("         password: 'senha'")
    print("         log_paths: ['/var/log/auth.log']")
    
    if collector.ssh_configs:
        print("🔗 Configurações SSH encontradas, coletando...")
        ssh_logs = collector.collect_ssh_logs()
        print(f"✅ Coletados {len(ssh_logs)} logs via SSH")
    else:
        print("⚠️  Nenhuma configuração SSH encontrada")

def demonstrar_coleta_completa(collector):
    """Demonstra coleta de todas as fontes"""
    print("\n" + "="*60)
    print("🎯 DEMONSTRAÇÃO: COLETA COMPLETA (TODAS AS FONTES)")
    print("="*60)
    
    stats = collector.collect_all_logs()
    
    print(f"📊 ESTATÍSTICAS DA COLETA:")
    print(f"   Total de logs coletados: {stats['total_logs_collected']}")
    print(f"   Logs da universidade: {stats['university_logs']}")
    print(f"   Logs do sistema: {stats['system_logs']}")
    print(f"   Logs via SSH: {stats['ssh_logs']}")
    print(f"   Servidor Syslog: {'Ativo' if stats['syslog_server_running'] else 'Inativo'}")
    
    print(f"\n📈 LOGS POR TIPO DE FONTE:")
    for source_type, count in stats['sources'].items():
        print(f"   {source_type.upper()}: {count} logs")

def demonstrar_estatisticas(collector):
    """Demonstra estatísticas dos logs"""
    print("\n" + "="*60)
    print("📈 DEMONSTRAÇÃO: ESTATÍSTICAS DOS LOGS")
    print("="*60)
    
    stats = collector.get_statistics()
    
    if stats:
        print(f"📊 RESUMO GERAL:")
        print(f"   Total de logs: {stats['total_logs']}")
        print(f"   IPs únicos: {stats['ips_unicos']}")
        print(f"   Usuários únicos: {stats['usuarios_unicos']}")
        
        print(f"\n🎯 LOGS POR NÍVEL:")
        for level, count in stats['logs_por_nivel'].items():
            print(f"   {level}: {count}")
        
        print(f"\n🗂️  LOGS POR FONTE:")
        for source, count in stats['logs_por_fonte'].items():
            print(f"   {source}: {count}")
        
        if 'periodo' in stats:
            print(f"\n📅 PERÍODO:")
            print(f"   Início: {stats['periodo']['inicio']}")
            print(f"   Fim: {stats['periodo']['fim']}")

def main():
    """Função principal da demonstração"""
    configurar_logging()
    
    print("🚀 AGENTE IA - DEMONSTRAÇÃO DE COLETA INDEPENDENTE")
    print("=" * 70)
    print("Este demo mostra como o Agente IA coleta logs de múltiplas fontes")
    print("sem depender de ferramentas SIEM externas.")
    print("=" * 70)
    
    # Inicializa o coletor
    collector = LogCollector()
    
    try:
        # Demonstra cada tipo de coleta
        demonstrar_coleta_arquivos(collector)
        demonstrar_coleta_sistema(collector)
        demonstrar_servidor_syslog(collector)
        demonstrar_ssh_remoto(collector)
        demonstrar_coleta_completa(collector)
        demonstrar_estatisticas(collector)
        
        print("\n" + "="*60)
        print("✅ DEMONSTRAÇÃO CONCLUÍDA COM SUCESSO!")
        print("="*60)
        print("🎯 O Agente IA agora é completamente independente!")
        print("📡 Pode coletar logs de:")
        print("   • Arquivos locais (monitoramento em tempo real)")
        print("   • Sistema operacional (Linux, Windows, macOS)")
        print("   • Rede via Syslog (equipamentos, servidores)")
        print("   • Servidores remotos via SSH")
        print("\n💡 Para usar em produção, configure o config.yaml")
        print("   e execute o backend com 'python app.py'")
        
    except KeyboardInterrupt:
        print("\n⚠️  Demonstração interrompida pelo usuário")
    except Exception as e:
        logging.error(f"Erro na demonstração: {e}")
        print(f"❌ Erro: {e}")
    finally:
        # Cleanup
        collector.stop_all_collection_services()
        print("\n🧹 Cleanup realizado")

if __name__ == "__main__":
    main() 