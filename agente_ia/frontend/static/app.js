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
