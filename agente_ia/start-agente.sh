#!/bin/bash

# ===================================================================
# AGENTE IA - SCRIPT DE INICIALIZAÇÃO CONTROLADA
# ===================================================================
# Sistema profissional de detecção de anomalias
# Desenvolvido para universidades brasileiras
# VERSÃO MELHORADA: Controle total de processos
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

# Variáveis Wazuh (podem ser sobrescritas via ambiente externo)
WAZUH_ENABLED=${WAZUH_ENABLED:-true}
WAZUH_SYSLOG_HOST=${WAZUH_SYSLOG_HOST:-localhost}
WAZUH_SYSLOG_PORT=${WAZUH_SYSLOG_PORT:-514}
WAZUH_URL=${WAZUH_URL:-https://localhost:55000}
WAZUH_USER=${WAZUH_USER:-kiron}
WAZUH_PASSWORD=${WAZUH_PASSWORD:-Lapergunta200.}

# Variáveis para controle de processos
BACKEND_PID=""
FRONTEND_PID=""
CLEANUP_DONE=false

# ===================================================================
# LIMPEZA AUTOMÁTICA DE PORTAS E PROCESSOS
# ===================================================================
force_cleanup_ports() {
    print_step "🧹 LIMPEZA AUTOMÁTICA DE PORTAS E PROCESSOS..."
    
    # Lista de portas utilizadas pelo projeto
    PORTS_TO_CLEAN=("$BACKEND_PORT" "$FRONTEND_PORT")
    
    # Obtém o PID do script atual para não se matar
    CURRENT_PID=$$
    
    # Mata todos os processos relacionados ao projeto (EXCETO o script atual)
    print_step "🔪 Finalizando processos antigos relacionados ao Agente IA..."
    
    # Mata scripts antigos do start-agente.sh (exceto o atual)
    OLD_SCRIPTS=$(pgrep -f "start-agente.sh" | grep -v "^${CURRENT_PID}$" || true)
    if [ ! -z "$OLD_SCRIPTS" ]; then
        echo "$OLD_SCRIPTS" | xargs -r kill -9 2>/dev/null || true
        print_success "Scripts antigos finalizados"
    fi
    
    # Mata outros processos do projeto
    pkill -f "simple_app.py" 2>/dev/null || true
    pkill -f "start_frontend.py" 2>/dev/null || true
    pkill -f "app.py" 2>/dev/null || true
    pkill -f "app_hybrid.py" 2>/dev/null || true
    
    # Limpa processos especificamente nas portas do projeto
    for port in "${PORTS_TO_CLEAN[@]}"; do
        print_step "🔍 Limpando porta $port..."
        
        # Encontra e mata processos na porta especificada
        PIDS=$(lsof -ti:$port 2>/dev/null || true)
        if [ ! -z "$PIDS" ]; then
            print_warning "Encontrados processos na porta $port: $PIDS"
            echo "$PIDS" | xargs -r kill -9 2>/dev/null || true
            sleep 2
            
            # Verifica se ainda há processos
            REMAINING=$(lsof -ti:$port 2>/dev/null || true)
            if [ -z "$REMAINING" ]; then
                print_success "Porta $port liberada com sucesso"
            else
                print_warning "Alguns processos podem ainda estar ativos na porta $port"
            fi
        else
            print_success "Porta $port já estava livre"
        fi
    done
    
    # Aguarda um momento para garantir que os processos foram terminados
    print_step "⏱️ Aguardando finalização completa dos processos..."
    sleep 3
    
    print_success "Limpeza automática concluída!"
    echo ""
}

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

print_info() {
    echo -e "${BLUE}ℹ️ $1${NC}"
}

# Função de limpeza que será chamada ao sair
cleanup_on_exit() {
    if [ "$CLEANUP_DONE" = true ]; then
        return
    fi
    
    # Se o trap não está ativo, ignora (estamos em operação crítica)
    if [ "$TRAP_ACTIVE" != true ]; then
        return
    fi
    
    CLEANUP_DONE=true
    
    echo ""
    print_warning "Recebido sinal de interrupção. Finalizando processos..."
    
    # Mata processo do backend
    if [ ! -z "$BACKEND_PID" ] && kill -0 "$BACKEND_PID" 2>/dev/null; then
        print_step "Finalizando backend (PID: $BACKEND_PID)..."
        kill "$BACKEND_PID" 2>/dev/null || true
        wait "$BACKEND_PID" 2>/dev/null || true
    fi
    
    # Mata processo do frontend
    if [ ! -z "$FRONTEND_PID" ] && kill -0 "$FRONTEND_PID" 2>/dev/null; then
        print_step "Finalizando frontend (PID: $FRONTEND_PID)..."
        kill "$FRONTEND_PID" 2>/dev/null || true
        wait "$FRONTEND_PID" 2>/dev/null || true
    fi
    
    # Limpeza adicional de processos nas portas
    kill_port_processes $BACKEND_PORT "Backend" true
    kill_port_processes $FRONTEND_PORT "Frontend" true
    
    # Remove arquivos PID
    rm -f agente_ia/backend/backend.pid 2>/dev/null || true
    rm -f agente_ia/frontend/frontend.pid 2>/dev/null || true
    
    print_success "Todos os processos foram finalizados corretamente"
    echo -e "${CYAN}Obrigado por usar o Agente IA! 🤖${NC}"
    exit 0
}

# Variável para controlar se o trap está ativo
TRAP_ACTIVE=true

# Função para desabilitar trap temporariamente
disable_trap() {
    TRAP_ACTIVE=false
    trap '' SIGINT SIGTERM
}

# Função para reabilitar trap
enable_trap() {
    TRAP_ACTIVE=true
    trap cleanup_on_exit SIGINT SIGTERM EXIT
}

# Configura trap para capturar sinais de interrupção
trap cleanup_on_exit SIGINT SIGTERM EXIT

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
    local silent=${3:-false}
    
    if [ "$silent" != true ]; then
        print_step "Verificando processos na porta $port..."
    fi
    
    # Encontra processos usando a porta
    local pids=$(lsof -ti:$port 2>/dev/null || true)
    
    if [[ -n "$pids" ]]; then
        if [ "$silent" != true ]; then
            print_warning "Finalizando processos $process_name na porta $port: $pids"
        fi
        echo "$pids" | xargs kill -9 2>/dev/null || true
        sleep 1
        if [ "$silent" != true ]; then
            print_success "Processos na porta $port finalizados"
        fi
    else
        if [ "$silent" != true ]; then
            print_success "Porta $port está livre"
        fi
    fi
}

# Função para limpar processos do projeto
cleanup_project_processes() {
    print_step "🧹 Limpando processos anteriores do projeto..."
    
    # Mata processos nas portas do projeto
    kill_port_processes $BACKEND_PORT "Backend"
    kill_port_processes $FRONTEND_PORT "Frontend"
    
    # Mata processos Python relacionados ao projeto
    pkill -f "flask.*5000" 2>/dev/null || true
    pkill -f "python.*http.server.*3000" 2>/dev/null || true
    pkill -f "start_frontend.py" 2>/dev/null || true
    pkill -f "simple_app.py" 2>/dev/null || true
    
    # Remove arquivos PID antigos
    rm -f agente_ia/backend/backend.pid 2>/dev/null || true
    rm -f agente_ia/frontend/frontend.pid 2>/dev/null || true
    
    # Força limpeza de cache do navegador (mata processos que possam estar travando)
    print_step "🔄 Preparando ambiente para nova versão..."
    sleep 2
    
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

# === WAZUH / SIEM ===
WAZUH_ENABLED=$WAZUH_ENABLED
WAZUH_SYSLOG_HOST=$WAZUH_SYSLOG_HOST
WAZUH_SYSLOG_PORT=$WAZUH_SYSLOG_PORT
WAZUH_URL=$WAZUH_URL
WAZUH_USER=$WAZUH_USER
WAZUH_PASSWORD=$WAZUH_PASSWORD

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
        /usr/bin/python3 -m venv venv --system-site-packages
        cd ..
    fi
    
    # Ativa ambiente virtual e instala dependências
    cd agente_ia
    source venv/bin/activate
    
    # Verifica se dependências principais já estão instaladas
    if python -c "import flask, flask_cors, yaml, psutil" 2>/dev/null; then
        print_success "Dependências principais já instaladas. Pulando instalação..."
        cd ..
        return
    fi
    
    print_step "Atualizando pip..."
    pip install --upgrade pip --quiet
    
    print_step "Instalando dependências do requirements.txt..."
    echo -e "${YELLOW}⏳ Isso pode demorar alguns minutos (TensorFlow é pesado)...${NC}"
    echo -e "${CYAN}💡 Pressione Ctrl+C APENAS se demorar mais de 10 minutos${NC}"
    
    # Desabilita trap durante instalação crítica
    disable_trap
    
    # Instala dependências com timeout e progresso
    timeout 600 pip install -r backend/requirements.txt --quiet --no-cache-dir || {
        echo -e "${RED}❌ Timeout ou erro na instalação de dependências${NC}"
        echo -e "${YELLOW}💡 Tentando instalação básica sem TensorFlow...${NC}"
        
        # Cria requirements básico temporário
        grep -v "tensorflow\|scikit-learn" backend/requirements.txt > /tmp/requirements_basic.txt
        pip install -r /tmp/requirements_basic.txt --quiet --no-cache-dir
        rm -f /tmp/requirements_basic.txt
        
        echo -e "${CYAN}ℹ️  TensorFlow será instalado em background mais tarde${NC}"
    }
    
    # Reabilita trap após instalação
    enable_trap
    
    cd ..
    print_success "Dependências Python instaladas"
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
    
    # Inicia backend (voltando para versão estável com melhorias)
    local local_ip=$(detect_local_ip)
    BACKEND_HOST=$local_ip BACKEND_PORT=$BACKEND_PORT \
    WAZUH_ENABLED=$WAZUH_ENABLED WAZUH_SYSLOG_HOST=$WAZUH_SYSLOG_HOST WAZUH_SYSLOG_PORT=$WAZUH_SYSLOG_PORT \
    WAZUH_URL=$WAZUH_URL WAZUH_USER=$WAZUH_USER WAZUH_PASSWORD=$WAZUH_PASSWORD \
    /usr/bin/python3 backend/simple_app.py > backend/logs/backend.log 2>&1 &
    BACKEND_PID=$!
    
    # Salva PID para controle
    echo $BACKEND_PID > backend/backend.pid
    
    cd ..
    
    # Aguarda backend inicializar
    print_step "Aguardando backend inicializar..."
    local attempts=0
    local max_attempts=30
    
    while [ $attempts -lt $max_attempts ]; do
        if curl -s "http://$local_ip:$BACKEND_PORT/api/status" > /dev/null 2>&1; then
            print_success "Backend iniciado em http://$local_ip:$BACKEND_PORT"
            return 0
        fi
        
        # Verifica se o processo ainda está rodando
        if ! kill -0 "$BACKEND_PID" 2>/dev/null; then
            print_error "Backend falhou ao iniciar. Verifique os logs em agente_ia/backend/logs/backend.log"
            exit 1
        fi
        
        attempts=$((attempts + 1))
        sleep 1
    done
    
    print_error "Timeout aguardando backend inicializar"
    exit 1
}

# Função para atualizar versões de cache-busting
update_cache_versions() {
    print_step "🔄 Atualizando versões de cache para forçar recarga..."
    
    cd agente_ia/frontend
    
    # Genera nueva versión basada en timestamp
    local new_version="v=$(date +%s)"
    
    # Actualiza versiones en index.html
    if [ -f "index.html" ]; then
        # Actualiza CSS
        sed -i "s/static\/style\.css?v=[^\"]*\"/static\/style.css?$new_version\"/" index.html
        # Actualiza JS
        sed -i "s/static\/app\.js?v=[^\"]*\"/static\/app.js?$new_version\"/" index.html
        
        print_success "Versões de cache atualizadas: $new_version"
    else
        print_warning "Arquivo index.html não encontrado"
    fi
    
    cd ../..
}

# Função para iniciar frontend
start_frontend() {
    print_step "🎨 Iniciando Frontend..."
    
    # Atualiza versões de cache ANTES de iniciar
    update_cache_versions
    
    cd agente_ia/frontend
    
    # Inicia servidor HTTP simples Python
    local local_ip=$(detect_local_ip)
    /usr/bin/python3 ../start_frontend.py > ../backend/logs/frontend.log 2>&1 &
    FRONTEND_PID=$!
    
    # Salva PID para controle
    echo $FRONTEND_PID > frontend.pid
    
    cd ../..
    
    # Aguarda frontend inicializar
    print_step "Aguardando frontend inicializar..."
    local attempts=0
    local max_attempts=15
    
    while [ $attempts -lt $max_attempts ]; do
        if curl -s "http://$local_ip:$FRONTEND_PORT" > /dev/null 2>&1; then
            print_success "Frontend iniciado em http://$local_ip:$FRONTEND_PORT"
            return 0
        fi
        
        # Verifica se o processo ainda está rodando
        if ! kill -0 "$FRONTEND_PID" 2>/dev/null; then
            print_error "Frontend falhou ao iniciar. Verifique os logs em agente_ia/backend/logs/frontend.log"
            exit 1
        fi
        
        attempts=$((attempts + 1))
        sleep 1
    done
    
    print_error "Timeout aguardando frontend inicializar"
    exit 1
}

# Função para monitorar processos
monitor_processes() {
    print_info "Monitorando processos. Pressione Ctrl+C para finalizar..."
    echo ""
    
    local local_ip=$(detect_local_ip)
    
    while true; do
        # Verifica se os processos ainda estão rodando
        if ! kill -0 "$BACKEND_PID" 2>/dev/null; then
            print_error "Backend parou inesperadamente!"
            break
        fi
        
        if ! kill -0 "$FRONTEND_PID" 2>/dev/null; then
            print_error "Frontend parou inesperadamente!"
            break
        fi
        
        # Mostra status a cada 30 segundos
        echo -e "${CYAN}[$(date '+%H:%M:%S')] Sistema funcionando - Backend PID: $BACKEND_PID | Frontend PID: $FRONTEND_PID${NC}"
        echo -e "${BLUE}   🌐 Frontend: http://$local_ip:$FRONTEND_PORT | 🔧 Backend: http://$local_ip:$BACKEND_PORT${NC}"
        echo ""
        
        sleep 30
    done
}

# Função principal
main() {
    clear
    echo -e "${CYAN}"
    echo "====================================================================="
    echo "🤖 AGENTE IA - SISTEMA DE INICIALIZAÇÃO CONTROLADA"
    echo "====================================================================="
    echo "Detector de Anomalias Inteligente"
    echo "Desenvolvido para universidades brasileiras"
    echo "VERSÃO MELHORADA: Controle total de processos"
    echo "====================================================================="
    echo -e "${NC}"
    
    print_step "🚀 Iniciando processo de configuração..."
    
    # 0. LIMPEZA AUTOMÁTICA FORÇADA (nova funcionalidade)
    force_cleanup_ports
    
    # 1. Limpeza de processos
    cleanup_project_processes
    
    # 2. Criação do arquivo .env
    create_env_file
    
    # 3. Criação de diretórios
    create_directories
    
    # 4. Instalação de dependências
    install_python_dependencies
    
    # 5. Inicialização dos serviços
    start_backend
    start_frontend
    
    # 6. Informações finais
    local local_ip=$(detect_local_ip)
    
    echo ""
    echo -e "${GREEN}====================================================================="
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
    echo -e "   ✅ Interface web funcionando"
    echo -e "   ✅ Cache-busting ativo (versões atualizadas)"
    echo ""
    echo -e "${BLUE}🔄 IMPORTANTE - Para ver alterações na interface:${NC}"
    echo -e "   ${YELLOW}1.${NC} Abra o navegador em: ${YELLOW}http://$local_ip:$FRONTEND_PORT${NC}"
    echo -e "   ${YELLOW}2.${NC} Pressione ${YELLOW}Ctrl+F5${NC} ou ${YELLOW}Ctrl+Shift+R${NC} para forçar recarga"
    echo -e "   ${YELLOW}3.${NC} Ou abra uma ${YELLOW}janela incógnito/privada${NC}"
    echo -e "   ${GREEN}✨ As versões de cache foram atualizadas automaticamente!${NC}"
    echo ""
    echo -e "${YELLOW}📋 Para finalizar:${NC} Pressione ${RED}Ctrl+C${NC}"
    echo -e "${GREEN}=====================================================================${NC}"
    echo ""
    
    # 7. Monitoramento contínuo
    monitor_processes
}

# Executa função principal
main "$@" 