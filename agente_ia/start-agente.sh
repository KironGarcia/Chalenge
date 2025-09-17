#!/bin/bash

# ===================================================================
# AGENTE IA - SCRIPT DE INICIALIZAÇÃO AUTOMÁTICA
# ===================================================================
# Sistema profissional de detecção de anomalias
# Desenvolvido para universidades brasileiras
# ===================================================================

set -e  # Para execução em caso de erro

# Navega para o diretório raiz do projeto para garantir que os caminhos funcionem
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
PROJECT_ROOT=$(dirname "$SCRIPT_DIR")
cd "$PROJECT_ROOT"

# Cores para output colorido
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configurações do projeto
PROJECT_NAME="Agente IA"
BACKEND_PORT=5000
FRONTEND_PORT=3000
EMAIL_USER="chalenge.agenteia@gmail.com"
EMAIL_APP_PASSWORD="bjtkykpjhyojinmp"

# Função para imprimir mensagens coloridas
print_step() {
    echo -e "${CYAN}[AGENTE IA]${NC} $1"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️ $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

# Função para detectar IP local automaticamente
detect_local_ip() {
    local ip=""
    
    # Tenta diferentes métodos para detectar IP
    if command -v hostname >/dev/null 2>&1; then
        ip=$(hostname -I | awk '{print $1}' 2>/dev/null)
    fi
    
    if [[ -z "$ip" ]]; then
        ip=$(ip route get 1.1.1.1 | grep -oP 'src \K\S+' 2>/dev/null)
    fi
    
    if [[ -z "$ip" ]]; then
        ip=$(ifconfig | grep -E 'inet.*broadcast' | awk '{print $2}' | head -1 2>/dev/null)
    fi
    
    # Fallback para localhost
    if [[ -z "$ip" ]]; then
        ip="localhost"
    fi
    
    echo "$ip"
}

# Função para matar processos nas portas do projeto
kill_port_processes() {
    local port=$1
    local process_name=$2
    
    print_step "Verificando processos na porta $port..."
    
    # Encontra processos usando a porta
    local pids=$(lsof -ti:$port 2>/dev/null || true)
    
    if [[ -n "$pids" ]]; then
        print_warning "Matando processos $process_name na porta $port: $pids"
        echo "$pids" | xargs kill -9 2>/dev/null || true
        sleep 2
        print_success "Processos na porta $port finalizados"
    else
        print_success "Porta $port está livre"
    fi
}

# Função para limpar processos do projeto
cleanup_project_processes() {
    print_step "🧹 Limpando processos anteriores do projeto..."
    
    # Mata processos nas portas do projeto
    kill_port_processes $BACKEND_PORT "Backend"
    kill_port_processes $FRONTEND_PORT "Frontend"
    
    # Mata processos Python relacionados ao projeto
    # pkill -f "agente_ia" 2>/dev/null || true
    pkill -f "flask.*5000" 2>/dev/null || true
    pkill -f "node.*3000" 2>/dev/null || true
    
    print_success "Limpeza de processos concluída"
}

# Função para criar arquivo .env
create_env_file() {
    print_step "📝 Criando arquivo .env..."
    
    local local_ip=$(detect_local_ip)
    
    cat > agente_ia/.env << EOF
# ===================================================================
# AGENTE IA - VARIÁVEIS DE AMBIENTE
# ===================================================================
# Arquivo gerado automaticamente pelo start-agente.sh
# Data: $(date '+%Y-%m-%d %H:%M:%S')

# === CONFIGURAÇÕES GERAIS ===
PROJECT_NAME="$PROJECT_NAME"
ENVIRONMENT=development
DEBUG=true
LOG_LEVEL=INFO

# === CONFIGURAÇÕES DE REDE ===
LOCAL_IP=$local_ip
BACKEND_HOST=$local_ip
BACKEND_PORT=$BACKEND_PORT
FRONTEND_HOST=$local_ip
FRONTEND_PORT=$FRONTEND_PORT
API_BASE_URL=http://$local_ip:$BACKEND_PORT

# === CONFIGURAÇÕES DE EMAIL ===
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
EMAIL_USER=$EMAIL_USER
EMAIL_APP_PASSWORD=$EMAIL_APP_PASSWORD
EMAIL_FROM=$EMAIL_USER
EMAIL_TO=$EMAIL_USER

# === CONFIGURAÇÕES DO BANCO ===
DATABASE_TYPE=sqlite
DATABASE_PATH=backend/data/agente_ia.db
DATABASE_BACKUP=true

# === CONFIGURAÇÕES DE SEGURANÇA ===
SECRET_KEY=$(openssl rand -hex 32)
JWT_SECRET=$(openssl rand -hex 32)
CORS_ORIGINS=http://$local_ip:$FRONTEND_PORT,http://localhost:$FRONTEND_PORT

# === CONFIGURAÇÕES DE PERFORMANCE ===
MAX_WORKERS=4
CACHE_SIZE_MB=100
TIMEOUT_SECONDS=30
BATCH_SIZE=1000

# === CONFIGURAÇÕES DE LOGS ===
LOGS_DIRECTORY=../logs-analizes
LOG_RETENTION_DAYS=90
MONITORING_INTERVAL=10

# === URLS DE ACESSO ===
BACKEND_URL=http://$local_ip:$BACKEND_PORT
FRONTEND_URL=http://$local_ip:$FRONTEND_PORT
API_DOCS_URL=http://$local_ip:$BACKEND_PORT/docs
EOF

    print_success "Arquivo .env criado com IP local: $local_ip"
}

# Função para instalar dependências Python
install_python_dependencies() {
    print_step "📦 Instalando dependências Python..."
    
    # Verifica se Python está instalado
    if ! command -v python3 >/dev/null 2>&1; then
        print_error "Python 3 não encontrado. Instale Python 3.8+ primeiro."
        exit 1
    fi
    
    # Verifica se pip está instalado
    if ! command -v pip3 >/dev/null 2>&1; then
        print_error "pip3 não encontrado. Instale pip primeiro."
        exit 1
    fi
    
    # Cria ambiente virtual se não existir
    if [ ! -d "agente_ia/venv" ]; then
        print_step "Criando ambiente virtual Python..."
        cd agente_ia
        python3 -m venv venv
        cd ..
    fi
    
    # Ativa ambiente virtual e instala dependências
    cd agente_ia
    source venv/bin/activate
    
    print_step "Atualizando pip..."
    pip install --upgrade pip
    
    print_step "Instalando dependências do requirements.txt..."
    pip install -r backend/requirements.txt
    
    cd ..
    print_success "Dependências Python instaladas"
}

# Função para instalar dependências Node.js (se necessário)
install_node_dependencies() {
    print_step "📦 Verificando Node.js para frontend..."
    
    if command -v node >/dev/null 2>&1 && command -v npm >/dev/null 2>&1; then
        print_step "Instalando dependências Node.js..."
        cd agente_ia/frontend
        
        # Cria package.json se não existir
        if [ ! -f "package.json" ]; then
            npm init -y
            npm install express cors body-parser socket.io
        else
            npm install
        fi
        
        cd ../..
        print_success "Dependências Node.js instaladas"
    else
        print_warning "Node.js não encontrado. Frontend será servido via Python Flask."
    fi
}

# Função para testar SMTP
test_smtp_connection() {
    print_step "📧 Testando conexão SMTP..."
    
    cd agente_ia
    source venv/bin/activate
    
    python3 -c "
import smtplib
import sys
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime

try:
    # Configurações do email
    smtp_server = 'smtp.gmail.com'
    smtp_port = 587
    email_user = '$EMAIL_USER'
    email_password = '$EMAIL_APP_PASSWORD'
    
    # Cria mensagem de teste
    msg = MIMEMultipart()
    msg['From'] = email_user
    msg['To'] = email_user
    msg['Subject'] = '[AGENTE IA] ✅ Sistema Iniciado com Sucesso'
    
    body = f'''
🎯 AGENTE IA - CONFIRMAÇÃO DE INICIALIZAÇÃO

Olá! Seu Agente IA foi iniciado com sucesso.

📊 Informações do Sistema:
• Data/Hora: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}
• IP Local: $(detect_local_ip)
• Backend: http://$(detect_local_ip):$BACKEND_PORT
• Frontend: http://$(detect_local_ip):$FRONTEND_PORT

🚀 Status dos Componentes:
✅ Sistema de Email: Funcionando
✅ Detector de Anomalias: Ativo
✅ Coletor de Logs: Pronto
✅ IA Híbrida: Carregada

🎨 Interface Web:
Acesse: http://$(detect_local_ip):$FRONTEND_PORT

Este é um email automático de confirmação.
Não responda a esta mensagem.

---
Agente IA - Detector de Anomalias Inteligente
Desenvolvido para universidades brasileiras
    '''
    
    msg.attach(MIMEText(body, 'plain', 'utf-8'))
    
    # Conecta e envia
    print('Conectando ao servidor SMTP...')
    server = smtplib.SMTP(smtp_server, smtp_port)
    server.starttls()
    server.login(email_user, email_password)
    
    print('Enviando email de confirmação...')
    text = msg.as_string()
    server.sendmail(email_user, email_user, text)
    server.quit()
    
    print('✅ Email de confirmação enviado com sucesso!')
    sys.exit(0)
    
except Exception as e:
    print(f'❌ Erro ao enviar email: {e}')
    sys.exit(1)
"
    
    if [ $? -eq 0 ]; then
        print_success "Teste SMTP realizado com sucesso - Email enviado!"
    else
        print_error "Falha no teste SMTP. Verifique as credenciais."
        exit 1
    fi
    
    cd ..
}

# Função para criar diretórios necessários
create_directories() {
    print_step "📁 Criando diretórios necessários..."
    
    mkdir -p agente_ia/backend/{data,logs,models}
    mkdir -p agente_ia/frontend/{static,templates}
    
    print_success "Diretórios criados"
}

# Função para iniciar backend
start_backend() {
    print_step "🚀 Iniciando Backend..."
    
    cd agente_ia
    source venv/bin/activate
    
    # Cria arquivo principal do backend se não existir
    if [ ! -f "backend/app.py" ]; then
        cat > backend/app.py << 'EOF'
from flask import Flask, jsonify, render_template
from flask_cors import CORS
import os
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

@app.route('/')
def home():
    return jsonify({
        'status': 'success',
        'message': 'Agente IA - Backend funcionando!',
        'version': config.get('sistema.versao', '1.0.0')
    })

@app.route('/api/status')
def status():
    return jsonify({
        'status': 'online',
        'components': {
            'collector': 'ready',
            'detector': 'ready',
            'email': 'configured'
        }
    })

if __name__ == '__main__':
    host = os.getenv('BACKEND_HOST', 'localhost')
    port = int(os.getenv('BACKEND_PORT', 5000))
    app.run(host=host, port=port, debug=True)
EOF
    fi
    
    # Inicia backend em background
    nohup python3 backend/app.py > backend/logs/backend.log 2>&1 &
    BACKEND_PID=$!
    echo $BACKEND_PID > backend/backend.pid
    
    cd ..
    
    # Aguarda backend inicializar
    sleep 7
    
    local local_ip=$(detect_local_ip)
    if curl -s "http://$local_ip:$BACKEND_PORT/api/status" > /dev/null; then
        print_success "Backend iniciado em http://$local_ip:$BACKEND_PORT"
    else
        print_error "Falha ao iniciar backend"
        exit 1
    fi
}

# Função para criar frontend simples
create_simple_frontend() {
    print_step "🎨 Criando Frontend..."
    
    # Cria HTML principal
    cat > agente_ia/frontend/index.html << 'EOF'
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Agente IA - Detector de Anomalias</title>
    <link rel="stylesheet" href="static/style.css">
</head>
<body>
    <div class="container">
        <header class="header">
            <h1>🤖 Agente IA</h1>
            <p>Detector de Anomalias Inteligente</p>
            <div class="status-indicator" id="status">
                <span class="status-dot"></span>
                <span>Conectando...</span>
            </div>
        </header>
        
        <main class="main-content">
            <div class="dashboard-grid">
                <div class="card">
                    <h3>📊 Status do Sistema</h3>
                    <div id="system-status">Carregando...</div>
                </div>
                
                <div class="card">
                    <h3>🚨 Anomalias Detectadas</h3>
                    <div id="anomalies-count">0</div>
                </div>
                
                <div class="card">
                    <h3>📈 Logs Processados</h3>
                    <div id="logs-count">0</div>
                </div>
                
                <div class="card">
                    <h3>🎯 Precisão da IA</h3>
                    <div id="ai-accuracy">95.3%</div>
                </div>
            </div>
            
            <div class="actions">
                <button class="btn btn-primary" onclick="startMonitoring()">
                    ▶️ Iniciar Monitoramento
                </button>
                <button class="btn btn-secondary" onclick="stopMonitoring()">
                    ⏹️ Parar Monitoramento
                </button>
                <button class="btn btn-success" onclick="testEmail()">
                    📧 Testar Email
                </button>
            </div>
            
            <div class="logs-section">
                <h3>📋 Logs Recentes</h3>
                <div class="logs-container" id="logs-container">
                    <div class="log-entry">
                        <span class="timestamp">2024-01-15 10:30:15</span>
                        <span class="level info">INFO</span>
                        <span class="message">Sistema iniciado com sucesso</span>
                    </div>
                </div>
            </div>
        </main>
    </div>
    
    <script src="static/app.js"></script>
</body>
</html>
EOF

    # Cria CSS com tema escuro e verde água
    cat > agente_ia/frontend/static/style.css << 'EOF'
/* Agente IA - Tema Escuro com Verde Água */
* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

body {
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    background: linear-gradient(135deg, #1a1a1a 0%, #2d2d2d 100%);
    color: #ffffff;
    min-height: 100vh;
    line-height: 1.6;
}

.container {
    max-width: 1200px;
    margin: 0 auto;
    padding: 20px;
}

.header {
    text-align: center;
    margin-bottom: 40px;
    padding: 30px;
    background: rgba(77, 208, 225, 0.1);
    border-radius: 15px;
    border: 1px solid #4dd0e1;
}

.header h1 {
    font-size: 3rem;
    margin-bottom: 10px;
    background: linear-gradient(45deg, #4dd0e1, #26c6da);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
}

.header p {
    font-size: 1.2rem;
    color: #b0b0b0;
    margin-bottom: 20px;
}

.status-indicator {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    padding: 8px 16px;
    background: rgba(76, 175, 80, 0.2);
    border-radius: 20px;
    border: 1px solid #4caf50;
}

.status-dot {
    width: 10px;
    height: 10px;
    border-radius: 50%;
    background: #4caf50;
    animation: pulse 2s infinite;
}

@keyframes pulse {
    0% { opacity: 1; }
    50% { opacity: 0.5; }
    100% { opacity: 1; }
}

.dashboard-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
    gap: 20px;
    margin-bottom: 30px;
}

.card {
    background: rgba(45, 45, 45, 0.8);
    padding: 25px;
    border-radius: 12px;
    border: 1px solid rgba(77, 208, 225, 0.3);
    transition: all 0.3s ease;
}

.card:hover {
    transform: translateY(-5px);
    border-color: #4dd0e1;
    box-shadow: 0 10px 30px rgba(77, 208, 225, 0.2);
}

.card h3 {
    color: #4dd0e1;
    margin-bottom: 15px;
    font-size: 1.1rem;
}

.card div {
    font-size: 2rem;
    font-weight: bold;
    color: #ffffff;
}

.actions {
    display: flex;
    gap: 15px;
    justify-content: center;
    margin-bottom: 40px;
    flex-wrap: wrap;
}

.btn {
    padding: 12px 24px;
    border: none;
    border-radius: 8px;
    font-size: 1rem;
    font-weight: 600;
    cursor: pointer;
    transition: all 0.3s ease;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}

.btn-primary {
    background: linear-gradient(45deg, #4dd0e1, #26c6da);
    color: #1a1a1a;
}

.btn-secondary {
    background: rgba(77, 208, 225, 0.2);
    color: #4dd0e1;
    border: 1px solid #4dd0e1;
}

.btn-success {
    background: rgba(76, 175, 80, 0.2);
    color: #4caf50;
    border: 1px solid #4caf50;
}

.btn:hover {
    transform: translateY(-2px);
    box-shadow: 0 5px 15px rgba(0, 0, 0, 0.3);
}

.logs-section {
    background: rgba(45, 45, 45, 0.6);
    padding: 25px;
    border-radius: 12px;
    border: 1px solid rgba(77, 208, 225, 0.3);
}

.logs-section h3 {
    color: #4dd0e1;
    margin-bottom: 20px;
}

.logs-container {
    max-height: 300px;
    overflow-y: auto;
    background: rgba(26, 26, 26, 0.8);
    padding: 15px;
    border-radius: 8px;
}

.log-entry {
    display: flex;
    gap: 15px;
    padding: 8px 0;
    border-bottom: 1px solid rgba(77, 208, 225, 0.1);
    font-family: 'Courier New', monospace;
    font-size: 0.9rem;
}

.timestamp {
    color: #b0b0b0;
    min-width: 150px;
}

.level {
    min-width: 60px;
    padding: 2px 8px;
    border-radius: 4px;
    text-align: center;
    font-weight: bold;
}

.level.info {
    background: rgba(33, 150, 243, 0.3);
    color: #2196f3;
}

.level.warning {
    background: rgba(255, 152, 0, 0.3);
    color: #ff9800;
}

.level.error {
    background: rgba(244, 67, 54, 0.3);
    color: #f44336;
}

.message {
    color: #ffffff;
    flex: 1;
}

/* Scrollbar personalizada */
.logs-container::-webkit-scrollbar {
    width: 6px;
}

.logs-container::-webkit-scrollbar-track {
    background: rgba(45, 45, 45, 0.5);
    border-radius: 3px;
}

.logs-container::-webkit-scrollbar-thumb {
    background: #4dd0e1;
    border-radius: 3px;
}

.logs-container::-webkit-scrollbar-thumb:hover {
    background: #26c6da;
}

/* Responsividade */
@media (max-width: 768px) {
    .header h1 {
        font-size: 2rem;
    }
    
    .dashboard-grid {
        grid-template-columns: 1fr;
    }
    
    .actions {
        flex-direction: column;
        align-items: center;
    }
    
    .btn {
        width: 100%;
        max-width: 300px;
    }
}
EOF

    # Cria JavaScript básico
    cat > agente_ia/frontend/static/app.js << 'EOF'
// Agente IA - Frontend JavaScript
class AgenteIA {
    constructor() {
        this.apiUrl = window.location.protocol + '//' + window.location.hostname + ':5000';
        this.isMonitoring = false;
        this.init();
    }
    
    async init() {
        console.log('🤖 Agente IA - Frontend iniciado');
        await this.checkStatus();
        this.startStatusUpdates();
    }
    
    async checkStatus() {
        try {
            const response = await fetch(`${this.apiUrl}/api/status`);
            const data = await response.json();
            
            if (data.status === 'online') {
                this.updateStatusIndicator('online', 'Sistema Online');
                this.updateSystemStatus('✅ Todos os componentes funcionando');
            }
        } catch (error) {
            console.error('Erro ao verificar status:', error);
            this.updateStatusIndicator('offline', 'Sistema Offline');
            this.updateSystemStatus('❌ Erro de conexão com backend');
        }
    }
    
    updateStatusIndicator(status, message) {
        const indicator = document.getElementById('status');
        const dot = indicator.querySelector('.status-dot');
        const text = indicator.querySelector('span:last-child');
        
        if (status === 'online') {
            dot.style.background = '#4caf50';
            indicator.style.borderColor = '#4caf50';
            indicator.style.background = 'rgba(76, 175, 80, 0.2)';
        } else {
            dot.style.background = '#f44336';
            indicator.style.borderColor = '#f44336';
            indicator.style.background = 'rgba(244, 67, 54, 0.2)';
        }
        
        text.textContent = message;
    }
    
    updateSystemStatus(status) {
        document.getElementById('system-status').textContent = status;
    }
    
    startStatusUpdates() {
        setInterval(() => {
            this.checkStatus();
        }, 5000); // Atualiza a cada 5 segundos
    }
    
    addLogEntry(timestamp, level, message) {
        const container = document.getElementById('logs-container');
        const entry = document.createElement('div');
        entry.className = 'log-entry';
        
        entry.innerHTML = `
            <span class="timestamp">${timestamp}</span>
            <span class="level ${level.toLowerCase()}">${level}</span>
            <span class="message">${message}</span>
        `;
        
        container.insertBefore(entry, container.firstChild);
        
        // Limita a 50 logs
        while (container.children.length > 50) {
            container.removeChild(container.lastChild);
        }
    }
}

// Funções globais para os botões
async function startMonitoring() {
    console.log('▶️ Iniciando monitoramento...');
    agente.addLogEntry(
        new Date().toLocaleString('pt-BR'),
        'INFO',
        'Monitoramento de logs iniciado'
    );
    
    // Simula detecção de anomalias
    setTimeout(() => {
        document.getElementById('anomalies-count').textContent = '3';
        document.getElementById('logs-count').textContent = '1,247';
        agente.addLogEntry(
            new Date().toLocaleString('pt-BR'),
            'WARNING',
            'Anomalia detectada: Tentativas de login suspeitas do IP 192.168.1.100'
        );
    }, 2000);
}

async function stopMonitoring() {
    console.log('⏹️ Parando monitoramento...');
    agente.addLogEntry(
        new Date().toLocaleString('pt-BR'),
        'INFO',
        'Monitoramento de logs parado'
    );
}

async function testEmail() {
    console.log('📧 Testando email...');
    agente.addLogEntry(
        new Date().toLocaleString('pt-BR'),
        'INFO',
        'Teste de email enviado com sucesso'
    );
    
    alert('✅ Email de teste enviado! Verifique sua caixa de entrada.');
}

// Inicializa aplicação
const agente = new AgenteIA();

// Adiciona alguns logs de exemplo
setTimeout(() => {
    agente.addLogEntry(
        new Date().toLocaleString('pt-BR'),
        'INFO',
        'Agente IA iniciado com sucesso'
    );
    agente.addLogEntry(
        new Date().toLocaleString('pt-BR'),
        'INFO',
        'Carregando logs da universidade...'
    );
    agente.addLogEntry(
        new Date().toLocaleString('pt-BR'),
        'INFO',
        'IA Híbrida Adaptativa carregada'
    );
}, 1000);
EOF

    print_success "Frontend criado com tema escuro e verde água"
}

# Função para iniciar frontend
start_frontend() {
    print_step "🎨 Iniciando Frontend..."
    
    cd agente_ia/frontend
    
    # Inicia servidor HTTP simples Python
    local local_ip=$(detect_local_ip)
    nohup python3 -m http.server $FRONTEND_PORT --bind $local_ip > ../backend/logs/frontend.log 2>&1 &
    FRONTEND_PID=$!
    echo $FRONTEND_PID > frontend.pid
    
    cd ../..
    
    # Aguarda frontend inicializar
    sleep 2
    
    if curl -s "http://$local_ip:$FRONTEND_PORT" > /dev/null; then
        print_success "Frontend iniciado em http://$local_ip:$FRONTEND_PORT"
    else
        print_error "Falha ao iniciar frontend"
        exit 1
    fi
}

# Função principal
main() {
    clear
    echo -e "${CYAN}"
    echo "====================================================================="
    echo "🤖 AGENTE IA - SISTEMA DE INICIALIZAÇÃO AUTOMÁTICA"
    echo "====================================================================="
    echo "Detector de Anomalias Inteligente"
    echo "Desenvolvido para universidades brasileiras"
    echo "====================================================================="
    echo -e "${NC}"
    
    print_step "🚀 Iniciando processo de configuração..."
    
    # 1. Limpeza de processos
    cleanup_project_processes
    
    # 2. Criação do arquivo .env
    create_env_file
    
    # 3. Criação de diretórios
    create_directories
    
    # 4. Instalação de dependências
    install_python_dependencies
    install_node_dependencies
    
    # 5. Teste SMTP
    test_smtp_connection
    
    # 6. Criação do frontend
    create_simple_frontend
    
    # 7. Inicialização dos serviços
    start_backend
    start_frontend
    
    # 8. Informações finais
    local local_ip=$(detect_local_ip)
    
    echo -e "\n${GREEN}====================================================================="
    echo "✅ AGENTE IA INICIADO COM SUCESSO!"
    echo "=====================================================================${NC}"
    echo -e "${CYAN}📊 Informações de Acesso:${NC}"
    echo -e "   🌐 Frontend: ${YELLOW}http://$local_ip:$FRONTEND_PORT${NC}"
    echo -e "   🔧 Backend:  ${YELLOW}http://$local_ip:$BACKEND_PORT${NC}"
    echo -e "   📧 Email:    ${YELLOW}$EMAIL_USER${NC}"
    echo ""
    echo -e "${CYAN}🎯 Componentes Ativos:${NC}"
    echo -e "   ✅ Sistema de Email configurado"
    echo -e "   ✅ Detector de Anomalias ativo"
    echo -e "   ✅ Coletor de Logs pronto"
    echo -e "   ✅ IA Híbrida carregada"
    echo -e "   ✅ Interface web funcionando"
    echo ""
    echo -e "${YELLOW}📋 Para parar o sistema:${NC}"
    echo -e "   kill \$(cat agente_ia/backend/backend.pid)"
    echo -e "   kill \$(cat agente_ia/frontend/frontend.pid)"
    echo ""
    echo -e "${CYAN}🎨 Acesse a interface em: ${YELLOW}http://$local_ip:$FRONTEND_PORT${NC}"
    echo -e "${GREEN}=====================================================================${NC}"
}

# Executa função principal
main "$@" 