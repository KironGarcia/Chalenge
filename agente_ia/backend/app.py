from flask import Flask, jsonify, render_template
from flask_cors import CORS
import os
from dotenv import load_dotenv

# Carrega variáveis de ambiente do arquivo .env
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), '..', '.env'))

from src.core.config_loader import config
from src.core.log_collector import LogCollector
from src.core.anomaly_detector import BasicAnomalyDetector
import logging

app = Flask(__name__)
CORS(app)

# Configuração de logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Inicializa componentes
collector = LogCollector()
detector = BasicAnomalyDetector()

# Inicia todos os serviços de coleta
collector.start_all_collection_services()

@app.route('/')
def home():
    return jsonify({
        'status': 'success',
        'message': 'Agente IA - Backend funcionando!',
        'version': config.get('sistema.versao', '1.0.0'),
        'features': [
            'Coleta de logs do sistema operacional',
            'Servidor Syslog integrado',
            'Coleta remota via SSH',
            'Detecção de anomalias com IA',
            'Completamente independente de SIEM'
        ]
    })

@app.route('/api/status')
def status():
    stats = collector.get_statistics()
    return jsonify({
        'status': 'online',
        'components': {
            'collector': 'ready',
            'detector': 'ready',
            'email': 'configured',
            'syslog_server': 'running' if collector.syslog_server else 'stopped'
        },
        'collection_stats': stats
    })

@app.route('/api/collect')
def collect_logs():
    """Endpoint para forçar coleta manual de logs"""
    try:
        stats = collector.collect_all_logs()
        return jsonify({
            'status': 'success',
            'message': 'Coleta de logs executada com sucesso',
            'stats': stats
        })
    except Exception as e:
        logging.error(f"Erro na coleta de logs: {e}")
        return jsonify({
            'status': 'error',
            'message': f'Erro na coleta: {str(e)}'
        }), 500

@app.route('/api/logs')
def get_logs():
    """Endpoint para obter logs coletados"""
    try:
        logs_data = []
        for log in collector.processed_logs[-100:]:  # Últimos 100 logs
            logs_data.append(log.to_dict())
        
        return jsonify({
            'status': 'success',
            'total_logs': len(collector.processed_logs),
            'logs': logs_data
        })
    except Exception as e:
        logging.error(f"Erro ao obter logs: {e}")
        return jsonify({
            'status': 'error',
            'message': f'Erro ao obter logs: {str(e)}'
        }), 500

if __name__ == '__main__':
    host = os.getenv('BACKEND_HOST', 'localhost')
    port = int(os.getenv('BACKEND_PORT', 5000))
    app.run(host=host, port=port, debug=True)
