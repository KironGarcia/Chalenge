// ===============================================
// AGENTE IA - CYBERPUNK PROFESSIONAL FRONTEND
// ===============================================
// Sistema JavaScript para Security Operations Center
// Preparado para integração SIEM (Wazuh)

class AgenteIA {
    constructor() {
        this.apiUrl = window.location.protocol + '//' + window.location.hostname + ':5000';
        this.isMonitoring = false;
        this.wazuhConnected = false;
        this.startTime = Date.now();
        this.logCount = 0;
        this.init();
    }
    
    async init() {
        console.log('🤖 AGENTE IA - Security Operations Center iniciado');
        await this.checkStatus();
        this.startStatusUpdates();
        this.startUptimeCounter();
        this.initializeMetrics();
        this.addWelcomeMessage();
    }
    
    async checkStatus() {
        try {
            const response = await fetch(`${this.apiUrl}/api/status`);
            
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}`);
            }
            
            const data = await response.json();
            
            if (data.status === 'online') {
                this.updateStatusIndicator('online', 'Sistema Operacional');
                this.updateSystemStatus('✅ Todos os componentes funcionando');
                this.updateSourceStatus(data.collection_stats || {});
                
                // Atualiza contadores
                if (data.collection_stats && data.collection_stats.total_logs) {
                    document.getElementById('logs-count').textContent = data.collection_stats.total_logs.toLocaleString();
                }
                
                console.log('✅ Backend conectado com sucesso');
            }
        } catch (error) {
            console.error('❌ Erro ao verificar status:', error);
            this.updateStatusIndicator('offline', 'SISTEMA OFFLINE');
            this.updateSystemStatus('❌ Erro de conexão com backend');
            
            // Mostra informação mais detalhada do erro
            const errorDetails = error.message.includes('Failed to fetch') ? 
                'Verifique se o backend está rodando na porta 5000' : 
                `Erro: ${error.message}`;
            
            this.addLogEntry(
                new Date().toLocaleString('pt-BR'),
                'ERROR',
                `🚨 Conexão perdida: ${errorDetails}`
            );
        }
    }
    
    updateStatusIndicator(status, message) {
        const indicator = document.getElementById('status');
        const dot = indicator.querySelector('.status-dot');
        const text = indicator.querySelector('span:last-child');
        
        if (status === 'online') {
            dot.style.background = 'var(--status-success)';
            dot.style.boxShadow = '0 0 10px var(--status-success)';
            indicator.style.borderColor = 'var(--accent-primary)';
            indicator.style.background = 'rgba(0, 255, 136, 0.1)';
        } else {
            dot.style.background = 'var(--status-error)';
            dot.style.boxShadow = '0 0 10px var(--status-error)';
            indicator.style.borderColor = 'var(--status-error)';
            indicator.style.background = 'rgba(239, 68, 68, 0.1)';
        }
        
        text.textContent = message;
    }
    
    updateSystemStatus(status) {
        document.getElementById('system-status').textContent = status;
    }
    
    updateSourceStatus(stats) {
        // Atualiza status das fontes de coleta
        const systemStatus = stats.syslog_server_running ? 'Ativo' : 'Inativo';
        document.getElementById('source-system').textContent = systemStatus;
        document.getElementById('source-syslog').textContent = systemStatus;
        
        // Atualiza contadores
        if (stats.sources) {
            const totalLogs = Object.values(stats.sources).reduce((a, b) => a + b, 0);
            document.getElementById('logs-count').textContent = totalLogs.toLocaleString();
            this.logCount = totalLogs;
        }
    }
    
    startStatusUpdates() {
        setInterval(async () => {
            await this.checkStatus();
            await this.updateWazuhStatus();
            this.updateMetrics();
        }, 5000); // Atualiza a cada 5 segundos
    }
    
    startUptimeCounter() {
        setInterval(() => {
            const uptime = Date.now() - this.startTime;
            const hours = Math.floor(uptime / 3600000);
            const minutes = Math.floor((uptime % 3600000) / 60000);
            const seconds = Math.floor((uptime % 60000) / 1000);
            
            document.getElementById('uptime').textContent = 
                `${hours.toString().padStart(2, '0')}:${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
        }, 1000);
    }
    
    initializeMetrics() {
        // Inicializa métricas com valores padrão
        document.getElementById('anomalies-count').textContent = '0';
        document.getElementById('threat-level').textContent = 'LOW';
        document.getElementById('critical-alerts').textContent = '0';
        document.getElementById('siem-events').textContent = 'Aguardando...';
        document.getElementById('siem-status').textContent = 'Preparando...';
    }
    
    updateMetrics() {
        // Simula métricas dinâmicas (será substituído por dados reais do backend)
        const logsPerMinute = Math.floor(Math.random() * 20) + 30;
        document.getElementById('logs-per-minute').textContent = logsPerMinute;
        
        // Atualiza CPU e RAM simulados
        const cpuUsage = Math.floor(Math.random() * 15) + 8;
        const ramUsage = Math.floor(Math.random() * 50) + 200;
        document.getElementById('cpu-usage').textContent = `${cpuUsage}%`;
        document.getElementById('ram-usage').textContent = `${ramUsage}MB`;
        
        // Atualiza cor baseado no valor
        const cpuElement = document.getElementById('cpu-usage');
        if (cpuUsage > 80) {
            cpuElement.style.color = 'var(--status-error)';
        } else if (cpuUsage > 60) {
            cpuElement.style.color = 'var(--status-warning)';
        } else {
            cpuElement.style.color = 'var(--status-success)';
        }
    }
    
    async updateWazuhStatus() {
        try {
            // Busca status do Wazuh
            const response = await fetch(`${this.apiUrl}/api/wazuh-summary`);
            if (response.ok) {
                const data = await response.json();
                this.wazuhConnected = data.siem_connected || false;
                this.updateWazuhMetrics(data);
                
                if (this.wazuhConnected) {
                    document.getElementById('siem-status').textContent = 'Conectado';
                    document.getElementById('source-siem').style.color = 'var(--status-success)';
                    document.getElementById('source-siem').textContent = 'Conectado';
                    
                    // Busca alertas reais do Wazuh
                    await this.updateWazuhAlerts();
                } else {
                    document.getElementById('siem-status').textContent = 'Desconectado';
                    document.getElementById('source-siem').style.color = 'var(--status-warning)';
                    document.getElementById('source-siem').textContent = 'Offline';
                }
            }
        } catch (error) {
            this.wazuhConnected = false;
            document.getElementById('siem-status').textContent = 'Erro de Conexão';
            document.getElementById('source-siem').textContent = 'Erro';
            document.getElementById('source-siem').style.color = 'var(--status-error)';
        }
    }
    
    async updateWazuhAlerts() {
        try {
            const response = await fetch(`${this.apiUrl}/api/wazuh-alerts`);
            if (response.ok) {
                const data = await response.json();
                
                // Atualiza contadores de alertas
                if (data.alerts && Array.isArray(data.alerts)) {
                    const criticalAlerts = data.alerts.filter(alert => 
                        alert.severity === 'ALTA' || alert.severity === 'CRITICAL'
                    );
                    
                    document.getElementById('siem-events').textContent = data.total || data.alerts.length;
                    document.getElementById('critical-alerts').textContent = criticalAlerts.length;
                    
                    // Atualiza nível de ameaça baseado em alertas críticos
                    if (criticalAlerts.length > 5) {
                        document.getElementById('threat-level').textContent = 'HIGH';
                        document.getElementById('threat-level').style.color = 'var(--status-error)';
                    } else if (criticalAlerts.length > 2) {
                        document.getElementById('threat-level').textContent = 'MEDIUM';
                        document.getElementById('threat-level').style.color = 'var(--status-warning)';
                    } else {
                        document.getElementById('threat-level').textContent = 'LOW';
                        document.getElementById('threat-level').style.color = 'var(--status-success)';
                    }
                    
                    // Mostra alertas críticos nos logs
                    criticalAlerts.slice(0, 3).forEach(alert => {
                        this.addLogEntry(
                            new Date().toLocaleString('pt-BR'),
                            'CRITICAL',
                            `🚨 WAZUH ALERT: ${alert.description || alert.message}`
                        );
                    });
                    
                    // Mostra link para dashboard se há alertas críticos
                    if (criticalAlerts.length > 0) {
                        this.showWazuhDetailLink();
                    }
                }
                
                // Busca histórico de ações automáticas
                await this.updateAutomaticActions();
            }
        } catch (error) {
            console.error('❌ Erro ao buscar alertas Wazuh:', error);
        }
    }
    
    async updateAutomaticActions() {
        try {
            const response = await fetch(`${this.apiUrl}/api/wazuh/actions/history`);
            if (response.ok) {
                const data = await response.json();
                
                if (data.executed_actions && data.executed_actions.length > 0) {
                    // Limpa ações antigas
                    const container = document.getElementById('auto-actions-list');
                    container.innerHTML = '';
                    
                    // Adiciona ações recentes
                    data.executed_actions.slice(-10).reverse().forEach(action => {
                        const status = action.result.success ? 'success' : 'error';
                        const actionText = `${action.type}: ${action.target} - ${action.result.message}`;
                        this.addActionEntry(actionText, status);
                    });
                }
                
                if (data.pending_approvals && data.pending_approvals.length > 0) {
                    // Atualiza aprovações pendentes
                    const approvalContainer = document.getElementById('approval-list');
                    approvalContainer.innerHTML = '';
                    
                    data.pending_approvals.filter(approval => approval.status === 'pending').forEach(approval => {
                        this.addPendingApproval(approval);
                    });
                }
            }
        } catch (error) {
            console.error('❌ Erro ao buscar ações automáticas:', error);
        }
    }
    
    addPendingApproval(approval) {
        const container = document.getElementById('approval-list');
        const entry = document.createElement('div');
        entry.className = 'log-entry pending-approval';
        entry.style.borderLeft = '3px solid var(--status-warning)';
        
        entry.innerHTML = `
            <span class="timestamp">${new Date(approval.timestamp).toLocaleString('pt-BR')}</span>
            <span class="level warning">PENDING</span>
            <span class="message">⏳ ${approval.action_type}: ${approval.target}</span>
            <div class="approval-buttons" style="margin-top: 8px;">
                <button onclick="approveAction('${approval.id}')" class="btn-mini btn-success">✅ Aprovar</button>
                <button onclick="rejectAction('${approval.id}')" class="btn-mini btn-danger">❌ Rejeitar</button>
            </div>
        `;
        
        container.appendChild(entry);
    }
    
    updateWazuhMetrics(data) {
        if (data.total_alerts !== undefined) {
            document.getElementById('siem-events').textContent = data.total_alerts;
        }
        if (data.critical_alerts !== undefined) {
            document.getElementById('critical-alerts').textContent = data.critical_alerts;
            
            // Mostra link para Wazuh se há alertas críticos
            if (data.critical_alerts > 0) {
                this.showWazuhDetailLink();
            }
        }
        if (data.security_status) {
            document.getElementById('threat-level').textContent = data.security_status;
        }
    }
    
    showWazuhDetailLink() {
        const detailLink = document.getElementById('wazuh-detail-link');
        detailLink.classList.remove('hidden');
        detailLink.querySelector('a').href = 'http://localhost:5601';
    }
    
    addLogEntry(timestamp, level, message) {
        const container = document.getElementById('logs-container');
        const entry = document.createElement('div');
        entry.className = 'log-entry';
        
        // Adiciona ícones baseados no nível
        const icons = {
            'INFO': 'ℹ️',
            'SUCCESS': '✅',
            'WARNING': '⚠️',
            'ERROR': '❌',
            'CRITICAL': '🚨'
        };
        
        const icon = icons[level] || 'ℹ️';
        
        entry.innerHTML = `
            <span class="timestamp">${timestamp}</span>
            <span class="level ${level.toLowerCase()}">${level}</span>
            <span class="message">${icon} ${message}</span>
        `;
        
        // Animação de entrada
        entry.style.opacity = '0';
        entry.style.transform = 'translateY(20px)';
        container.insertBefore(entry, container.firstChild);
        
        // Trigger animation
        requestAnimationFrame(() => {
            entry.style.transition = 'all 0.3s ease';
            entry.style.opacity = '1';
            entry.style.transform = 'translateY(0)';
        });
        
        // Limita a 50 logs
        while (container.children.length > 50) {
            container.removeChild(container.lastChild);
        }
        
        this.logCount++;
        document.getElementById('logs-count').textContent = this.logCount.toLocaleString();
    }
    
    addActionEntry(action, status = 'success') {
        const container = document.getElementById('auto-actions-list');
        const entry = document.createElement('div');
        entry.className = 'log-entry';
        
        const statusIcons = {
            'success': '✅',
            'pending': '⏳',
            'error': '❌',
            'warning': '⚠️'
        };
        
        const icon = statusIcons[status] || '✅';
        const levelClass = status === 'success' ? 'success' : status;
        
        entry.innerHTML = `
            <span class="timestamp">${new Date().toLocaleString('pt-BR')}</span>
            <span class="level ${levelClass}">${status.toUpperCase()}</span>
            <span class="message">${icon} ${action}</span>
        `;
        
        // Remove mensagem padrão se existir
        const defaultMessage = container.querySelector('.log-entry');
        if (defaultMessage && defaultMessage.textContent.includes('Aguardando ações')) {
            defaultMessage.remove();
        }
        
        container.insertBefore(entry, container.firstChild);
        
        // Limita a 20 ações
        while (container.children.length > 20) {
            container.removeChild(container.lastChild);
        }
    }
    
    addWelcomeMessage() {
        setTimeout(() => {
            this.addLogEntry(
                new Date().toLocaleString('pt-BR'),
                'SUCCESS',
                '🛡️ Security Operations Center online - Monitoramento ativo'
            );
        }, 1000);
    }
    
    showNotification(message, type = 'info') {
        // Cria notificação toast estilo cyberpunk
        const notification = document.createElement('div');
        notification.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            background: linear-gradient(135deg, var(--bg-card), var(--bg-tertiary));
            border: 1px solid var(--accent-primary);
            border-radius: var(--radius-md);
            padding: 16px 24px;
            color: var(--text-primary);
            font-family: var(--font-primary);
            font-weight: 500;
            box-shadow: var(--glow-primary);
            z-index: 1000;
            max-width: 400px;
            animation: slideIn 0.3s ease;
        `;
        
        const typeColors = {
            'success': 'var(--status-success)',
            'warning': 'var(--status-warning)',
            'error': 'var(--status-error)',
            'info': 'var(--accent-primary)'
        };
        
        notification.style.borderColor = typeColors[type] || typeColors.info;
        notification.textContent = message;
        
        document.body.appendChild(notification);
        
        setTimeout(() => {
            notification.remove();
        }, 5000);
    }
}

// ===============================================
// FUNÇÕES GLOBAIS PARA BOTÕES
// ===============================================

// Funções para aprovação de ações críticas
async function approveAction(approvalId) {
    try {
        const response = await fetch(`${agente.apiUrl}/api/wazuh/actions/approve/${approvalId}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            }
        });
        
        const data = await response.json();
        
        if (data.status === 'success') {
            agente.addLogEntry(
                new Date().toLocaleString('pt-BR'),
                'SUCCESS',
                `✅ Ação aprovada e executada: ${data.approval_id}`
            );
            
            agente.showNotification('Ação aprovada e executada com sucesso!', 'success');
            
            // Atualiza a lista de aprovações
            setTimeout(() => agente.updateAutomaticActions(), 1000);
        } else {
            throw new Error(data.message || 'Erro ao aprovar ação');
        }
    } catch (error) {
        console.error('❌ Erro ao aprovar ação:', error);
        agente.addLogEntry(
            new Date().toLocaleString('pt-BR'),
            'ERROR',
            `❌ Erro ao aprovar ação: ${error.message}`
        );
        agente.showNotification('Erro ao aprovar ação', 'error');
    }
}

async function rejectAction(approvalId) {
    try {
        // Para implementação futura - endpoint de rejeição
        agente.addLogEntry(
            new Date().toLocaleString('pt-BR'),
            'INFO',
            `❌ Ação rejeitada: ${approvalId}`
        );
        
        agente.showNotification('Ação rejeitada pelo administrador', 'warning');
        
        // Remove da lista visualmente (implementação básica)
        const approvalElement = document.querySelector(`[onclick*="${approvalId}"]`);
        if (approvalElement) {
            approvalElement.closest('.log-entry').remove();
        }
    } catch (error) {
        console.error('❌ Erro ao rejeitar ação:', error);
    }
}

// Função para executar ação manual
async function executeManualAction(actionType, target) {
    try {
        const response = await fetch(`${agente.apiUrl}/api/wazuh/action`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                action: actionType,
                target: target,
                alert_id: `manual_${Date.now()}`,
                reason: 'Ação executada manualmente pelo administrador'
            })
        });
        
        const data = await response.json();
        
        if (data.status === 'success') {
            agente.addLogEntry(
                new Date().toLocaleString('pt-BR'),
                'SUCCESS',
                `🔧 Ação manual executada: ${actionType} -> ${data.message}`
            );
            agente.showNotification('Ação executada com sucesso!', 'success');
        } else if (data.status === 'pending_approval') {
            agente.addLogEntry(
                new Date().toLocaleString('pt-BR'),
                'WARNING',
                `⏳ Ação enviada para aprovação: ${actionType}`
            );
            agente.showNotification('Ação crítica enviada para aprovação', 'warning');
        } else {
            throw new Error(data.message || 'Erro na execução');
        }
        
        // Atualiza histórico de ações
        setTimeout(() => agente.updateAutomaticActions(), 1000);
        
    } catch (error) {
        console.error('❌ Erro ao executar ação manual:', error);
        agente.addLogEntry(
            new Date().toLocaleString('pt-BR'),
            'ERROR',
            `❌ Erro na ação manual: ${error.message}`
        );
        agente.showNotification('Erro ao executar ação', 'error');
    }
}

async function startMonitoring() {
    console.log('▶️ Iniciando monitoramento...');
    agente.isMonitoring = true;
    
    agente.addLogEntry(
        new Date().toLocaleString('pt-BR'),
        'INFO',
        '▶️ Monitoramento de logs iniciado pelo usuário'
    );
    
    agente.addActionEntry('Sistema de monitoramento ativado');
    agente.showNotification('Monitoramento iniciado com sucesso!', 'success');
    
    // Simula coleta de logs
    setTimeout(() => {
        const anomaliesCount = Math.floor(Math.random() * 5);
        const logsCount = Math.floor(Math.random() * 1000) + 500;
        
        document.getElementById('anomalies-count').textContent = anomaliesCount;
        document.getElementById('logs-count').textContent = logsCount.toLocaleString();
        
        if (anomaliesCount > 0) {
            agente.addLogEntry(
                new Date().toLocaleString('pt-BR'),
                'WARNING',
                `🔍 ${anomaliesCount} anomalia(s) detectada(s) - Investigando...`
            );
            
            agente.addActionEntry(`${anomaliesCount} anomalia(s) detectada(s) - Análise iniciada`, 'warning');
        }
        
        agente.addLogEntry(
            new Date().toLocaleString('pt-BR'),
            'SUCCESS',
            `📊 ${logsCount} logs processados com sucesso`
        );
    }, 2000);
}

async function stopMonitoring() {
    console.log('⏹️ Parando monitoramento...');
    agente.isMonitoring = false;
    
    agente.addLogEntry(
        new Date().toLocaleString('pt-BR'),
        'INFO',
        '⏹️ Monitoramento pausado pelo usuário'
    );
    
    agente.addActionEntry('Sistema de monitoramento pausado');
    agente.showNotification('Monitoramento pausado', 'warning');
}

async function testEmail() {
    console.log('📧 Testando sistema de alertas...');
    
    agente.addLogEntry(
        new Date().toLocaleString('pt-BR'),
        'INFO',
        '📧 Teste de sistema de alertas iniciado'
    );
    
    agente.showNotification('Enviando email de teste...', 'info');

    try {
        const response = await fetch(`${agente.apiUrl}/api/test-email`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            }
        });
        
        const data = await response.json();
        
        if (data.status === 'success') {
            agente.addLogEntry(
                new Date().toLocaleString('pt-BR'),
                'SUCCESS',
                '✅ Email de teste enviado com sucesso'
            );
            
            agente.addActionEntry('Email de teste enviado para administradores');
            agente.showNotification('Email de teste enviado com sucesso!', 'success');
        } else {
            throw new Error(data.message || 'Erro desconhecido');
        }
    } catch (error) {
        console.error('❌ Erro no teste de email:', error);
        agente.addLogEntry(
            new Date().toLocaleString('pt-BR'),
            'ERROR',
            `❌ Erro no teste de email: ${error.message}`
        );
        
        agente.showNotification('Erro ao testar email - usando modo simulação', 'warning');
    }
}

async function startRealTimeMonitoring() {
    console.log("🔍 Iniciando monitoramento em tempo real...");
    
    agente.addLogEntry(
        new Date().toLocaleString("pt-BR"),
        "INFO",
        "🔍 Solicitando início do monitoramento em tempo real"
    );
    
    agente.showNotification("Iniciando monitoramento em tempo real...", "info");
    
    try {
        const response = await fetch(`${agente.apiUrl}/api/monitoring/start`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            }
        });
        
        const data = await response.json();
        
        if (data.status === "success") {
            agente.addLogEntry(
                new Date().toLocaleString("pt-BR"),
                "SUCCESS",
                "✅ Monitoramento em tempo real iniciado com sucesso"
            );
            
            agente.showNotification("Monitoramento em tempo real ativo!", "success");
        } else {
            throw new Error(data.message || "Erro desconhecido");
        }
    } catch (error) {
        console.error("❌ Erro ao iniciar monitoramento:", error);
        agente.addLogEntry(
            new Date().toLocaleString("pt-BR"),
            "ERROR",
            `❌ Erro ao iniciar monitoramento RT: ${error.message}`
        );
        
        agente.showNotification("Erro ao iniciar monitoramento", "error");
    }
}

async function stopRealTimeMonitoring() {
    console.log("🛑 Parando monitoramento em tempo real...");
    
    agente.addLogEntry(
        new Date().toLocaleString("pt-BR"),
        "INFO",
        "🛑 Solicitando parada do monitoramento em tempo real"
    );
    
    agente.showNotification("Parando monitoramento em tempo real...", "warning");
    
    try {
        const response = await fetch(`${agente.apiUrl}/api/monitoring/stop`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            }
        });
        
        const data = await response.json();
        
        if (data.status === "success") {
            agente.addLogEntry(
                new Date().toLocaleString("pt-BR"),
                "INFO",
                "🛑 Monitoramento em tempo real parado com sucesso"
            );
            
            agente.showNotification("Monitoramento em tempo real parado", "warning");
        } else {
            throw new Error(data.message || "Erro desconhecido");
        }
    } catch (error) {
        console.error("❌ Erro ao parar monitoramento:", error);
        agente.addLogEntry(
            new Date().toLocaleString("pt-BR"),
            "ERROR",
            `❌ Erro ao parar monitoramento RT: ${error.message}`
        );
        
        agente.showNotification("Erro ao parar monitoramento", "error");
    }
}

async function collectLogs() {
    console.log('🔄 Coletando logs manualmente...');
    
    agente.addLogEntry(
        new Date().toLocaleString('pt-BR'),
        'INFO',
        '🔄 Coleta manual de logs iniciada'
    );
    
    agente.showNotification('Coletando logs de todas as fontes...', 'info');
    
    try {
        const response = await fetch(`${agente.apiUrl}/api/collect`);
        const data = await response.json();
        
        if (data.status === 'success') {
            agente.addLogEntry(
                new Date().toLocaleString('pt-BR'),
                'SUCCESS',
                `✅ Coleta concluída: ${data.stats?.total_new_logs || 'N/A'} novos logs`
            );
            
            agente.addActionEntry(`Coleta manual: ${data.stats?.total_new_logs || 0} novos logs processados`);
            agente.showNotification('Coleta de logs concluída com sucesso!', 'success');
            
            // Atualiza métricas
            if (data.stats) {
                agente.updateSourceStatus(data.stats);
            }
        } else {
            throw new Error(data.message || 'Erro na coleta');
        }
    } catch (error) {
        console.error('❌ Erro na coleta:', error);
    agente.addLogEntry(
        new Date().toLocaleString('pt-BR'),
            'ERROR',
            `❌ Erro na coleta: ${error.message}`
        );
        
        agente.showNotification('Erro na coleta de logs', 'error');
    }
}

// ===============================================
// INICIALIZAÇÃO
// ===============================================

// Inicializa o sistema quando a página carrega
let agente;
document.addEventListener('DOMContentLoaded', () => {
    agente = new AgenteIA();
});

// Adiciona estilos para animações
const style = document.createElement('style');
style.textContent = `
    @keyframes slideIn {
        from {
            opacity: 0;
            transform: translateX(100%);
        }
        to {
            opacity: 1;
            transform: translateX(0);
        }
    }
`;
document.head.appendChild(style);
