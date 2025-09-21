// ===============================================
// AGENTE IA - CYBERPUNK PROFESSIONAL FRONTEND
// ===============================================
// Sistema JavaScript para Security Operations Center
// Preparado para integração SIEM (Wazuh)

class AgenteIA {
    constructor() {
        this.apiUrl = window.location.protocol + '//' + window.location.hostname + ':5000';
        console.log('🚀 SHILD IA iniciado - API URL:', this.apiUrl);
        this.isMonitoring = false;
        this.wazuhConnected = false;
        this.startTime = Date.now();
        this.logCount = 0;
        this.lastLogTimestamp = ''; // Para evitar parpadeo en logs
        this.init();
    }
    
    // Función segura para obtener elementos que pueden no existir
    safeGetElement(id) {
        const element = document.getElementById(id);
        if (!element) {
            console.warn(`⚠️ Elemento não encontrado: ${id}`);
        }
        return element;
    }
    
    // Función segura para actualizar texto de elementos
    safeUpdateText(id, text) {
        const element = this.safeGetElement(id);
        if (element) {
            element.textContent = text;
            return true;
        }
        return false;
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
            console.log('🔍 Tentando conectar ao backend:', this.apiUrl);
            const response = await fetch(`${this.apiUrl}/api/status`);
            console.log('📡 Response recebido:', response.status, response.statusText);
            
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}`);
            }
            
            const data = await response.json();
            console.log('📊 Dados do backend:', data);
            console.log('🎯 Status do backend:', data.status);
            
            if (data.status === 'online') {
                console.log('✅ Status é online, atualizando interface...');
                this.updateStatusIndicator('online', 'Sistema Operacional');
                this.updateSystemStatus('✅ Todos os componentes funcionando');
                this.updateSourceStatus(data.collection_stats || {});
                
                // Atualiza contadores
                if (data.collection_stats && data.collection_stats.total_logs) {
                    this.safeUpdateText('logs-count', data.collection_stats.total_logs.toLocaleString());
                }
                
                console.log('✅ Backend conectado com sucesso');
            } else {
                console.warn('⚠️ Status não é online:', data.status);
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
        this.safeUpdateText('system-status', status);
    }
    
    updateSourceStatus(stats) {
        // Atualiza status das fontes de coleta
        const systemStatus = stats.syslog_server_running ? 'Ativo' : 'Inativo';
        this.safeUpdateText('source-system', systemStatus);
        this.safeUpdateText('source-syslog', systemStatus);
        
        // Atualiza contadores
        if (stats.sources) {
            const totalLogs = Object.values(stats.sources).reduce((a, b) => a + b, 0);
            this.safeUpdateText('logs-count', totalLogs.toLocaleString());
            this.logCount = totalLogs;
        }
    }
    
    startStatusUpdates() {
        setInterval(async () => {
            await this.checkStatus();
            await this.updateWazuhStatus();
            this.updateMetrics();
        }, 5000); // Status general cada 5 segundos
        
        // Logs en tiempo real MAS FRECUENTES solo cuando monitoreando
        setInterval(async () => {
            if (this.isMonitoring) {
                await this.updateRealtimeLogs();
            }
        }, 3000); // Logs cada 3 segundos solo si está monitoreando
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
        this.safeUpdateText('anomalies-count', '0');
        this.safeUpdateText('threat-level', 'LOW');
        this.safeUpdateText('critical-alerts', '0');
        this.safeUpdateText('siem-events', 'Aguardando...');
        this.safeUpdateText('siem-status', 'Preparando...');
    }
    
    updateMetrics() {
        // Obtiene métricas reales del sistema via backend
        this.getRealSystemMetrics();
    }
    
    async getRealSystemMetrics() {
        try {
            const response = await fetch(`${this.apiUrl}/api/status`);
            if (response.ok) {
                const data = await response.json();
                
                // Actualiza métricas reales del sistema
                if (data.collection_stats) {
                    const stats = data.collection_stats;
                    
                    // Logs por minuto basado en datos reales
                    const totalLogs = stats.total_logs || 0;
                    const logsPerMinute = Math.max(1, Math.floor(totalLogs / 60)); // Estimación basada en total
                    document.getElementById('logs-per-minute').textContent = logsPerMinute;
                }
                
                // CPU y RAM reales del sistema (si están disponibles)
                this.updateRealSystemResources();
            }
        } catch (error) {
            console.error('Error obteniendo métricas reales:', error);
            // Fallback: mostrar valores estáticos en lugar de aleatorios
            document.getElementById('logs-per-minute').textContent = '--';
            document.getElementById('cpu-usage').textContent = '--';
            document.getElementById('ram-usage').textContent = '--';
        }
    }
    
    async updateRealSystemResources() {
        try {
            // Intenta obtener recursos reales del sistema
            const response = await fetch(`${this.apiUrl}/api/system-resources`);
            if (response.ok) {
                const data = await response.json();
                
                if (data.cpu_usage !== undefined) {
                    const cpuUsage = Math.round(data.cpu_usage);
                    document.getElementById('cpu-usage').textContent = `${cpuUsage}%`;
                    
                    // Actualiza color basado en valor real
                    const cpuElement = document.getElementById('cpu-usage');
                    if (cpuUsage > 80) {
                        cpuElement.style.color = 'var(--status-error)';
                    } else if (cpuUsage > 60) {
                        cpuElement.style.color = 'var(--status-warning)';
                    } else {
                        cpuElement.style.color = 'var(--status-success)';
                    }
                }
                
                if (data.memory_usage !== undefined) {
                    document.getElementById('ram-usage').textContent = `${Math.round(data.memory_usage)}MB`;
                }
            } else {
                // Si no hay endpoint, mostrar valores estáticos
                document.getElementById('cpu-usage').textContent = 'N/A';
                document.getElementById('ram-usage').textContent = 'N/A';
            }
        } catch (error) {
            // Error silencioso - mostrar N/A en lugar de datos falsos
            document.getElementById('cpu-usage').textContent = 'N/A';
            document.getElementById('ram-usage').textContent = 'N/A';
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
    
    async updateRealtimeLogs() {
        /**
         * Atualiza logs em tempo real durante o monitoramento SEM parpadeo
         */
        try {
            if (!this.isMonitoring) return;
            
            const response = await fetch(`${this.apiUrl}/api/logs`);
            if (response.ok) {
                const data = await response.json();
                
                if (data.logs && data.logs.length > 0) {
                    const container = document.getElementById('logs-container');
                    
                    // Guarda o último timestamp que temos
                    if (!this.lastLogTimestamp) {
                        this.lastLogTimestamp = '';
                    }
                    
                    // Filtra apenas logs NUEVOS que no tenemos aún
                    const newLogs = data.logs.filter(log => {
                        // Si no tenemos timestamp previo, tomar solo los primeros 5
                        if (!this.lastLogTimestamp) {
                            return true;
                        }
                        // Si ya tenemos timestamp, solo logs más recientes
                        return log.timestamp > this.lastLogTimestamp && 
                               !this.hasLogEntry(log.timestamp, log.message);
                    });
                    
                    // Solo agrega NUEVOS logs sin borrar los existentes
                    if (newLogs.length > 0) {
                        // Si es la primera carga, limitar a 5 logs para no spammar
                        const logsToAdd = !this.lastLogTimestamp ? newLogs.slice(0, 5) : newLogs;
                        
                        logsToAdd.forEach(log => {
                            this.addLogEntryDirect(log.timestamp, log.level, log.message, log.source);
                        });
                        
                        // Actualiza el último timestamp
                        if (data.logs.length > 0) {
                            this.lastLogTimestamp = data.logs[0].timestamp;
                        }
                    }
                    
                    // Atualiza contador de logs
                    this.safeUpdateText('logs-count', data.total_logs.toLocaleString());
                    
                    // Atualiza status do monitoramento
                    if (data.monitoring_active) {
                        this.isMonitoring = true;
                        this.safeUpdateText('monitoring-status', 'ATIVO');
                    }
                }
            }
        } catch (error) {
            console.error('❌ Erro ao atualizar logs em tempo real:', error);
        }
    }
    
    hasLogEntry(timestamp, message) {
        /**
         * Verifica se já temos um log com esse timestamp e mensagem
         */
        const container = document.getElementById('logs-container');
        const entries = container.querySelectorAll('.log-entry');
        
        for (let entry of entries) {
            const entryTimestamp = entry.querySelector('.timestamp')?.textContent;
            const entryMessage = entry.querySelector('.message')?.textContent;
            
            if (entryTimestamp === timestamp && entryMessage?.includes(message.substring(0, 50))) {
                return true;
            }
        }
        return false;
    }
    
    addLogEntryDirect(timestamp, level, message, source = '') {
        /**
         * Adiciona log diretamente SEM parpadeo - novos logs no topo
         */
        const container = document.getElementById('logs-container');
        const entry = document.createElement('div');
        entry.className = 'log-entry';
        
        // Adiciona classes especiais para diferentes tipos de fonte
        if (source && source.includes('wazuh')) {
            entry.classList.add('wazuh-log');
        }
        if (source && source.includes('anomaly')) {
            entry.classList.add('anomaly-log');
        }
        if (source && source.includes('auto-response')) {
            entry.classList.add('auto-response-log');
        }
        if (source && source.includes('ia-decision')) {
            entry.classList.add('ia-decision-log');
        }
        
        // Adiciona ícones baseados no nível e fonte
        const icons = {
            'INFO': '📊',
            'SUCCESS': '✅',
            'WARNING': '⚠️',
            'ERROR': '❌',
            'CRITICAL': '🚨'
        };
        
        // Ícones especiais para fontes específicas
        if (source && source.includes('wazuh')) {
            icons['INFO'] = '📡';
            icons['WARNING'] = '📥';
        }
        if (source && source.includes('anomaly')) {
            icons['CRITICAL'] = '🚨';
            icons['WARNING'] = '🔍';
        }
        if (source && source.includes('auto-response')) {
            icons['WARNING'] = '⚡';
        }
        
        const icon = icons[level] || '📊';
        
        entry.innerHTML = `
            <span class="timestamp">${timestamp}</span>
            <span class="level ${level.toLowerCase()}">${level}</span>
            <span class="message">${icon} ${message}</span>
        `;
        
        // INSERTAR NUEVOS LOGS AL PRINCIPIO (más recientes arriba)
        container.insertBefore(entry, container.firstChild);
        
        // Animación suave para nuevos logs
        entry.style.opacity = '0';
        entry.style.transform = 'translateY(-10px)';
        
        requestAnimationFrame(() => {
            entry.style.transition = 'all 0.3s ease';
            entry.style.opacity = '1';
            entry.style.transform = 'translateY(0)';
        });
        
        // Limita a 50 logs - remueve del final
        while (container.children.length > 50) {
            container.removeChild(container.lastChild);
        }
    }

    addWelcomeMessage() {
        setTimeout(() => {
            this.addLogEntry(
                new Date().toLocaleString('pt-BR'),
                'SUCCESS',
                'Security Operations Center online - Monitoramento ativo'
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

// Las funciones startMonitoring y stopMonitoring simuladas han sido eliminadas
// Ahora solo se usan las funciones reales: startRealTimeMonitoring y stopRealTimeMonitoring

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
    
    // Limpa logs estáticos iniciais para evitar confusão
    const container = document.getElementById('logs-container');
    container.innerHTML = '';
    
    agente.addLogEntry(
        new Date().toLocaleString("pt-BR"),
        "INFO",
        "🔍 Iniciando sistema de monitoramento em tempo real com integração Wazuh"
    );
    
    agente.showNotification("Iniciando monitoramento em tempo real...", "info");
    
    try {
        // 1. PRIMEIRO: Coleta automática de logs existentes
        agente.addLogEntry(
            new Date().toLocaleString("pt-BR"),
            "INFO",
            "📂 COLETA AUTOMÁTICA: Carregando logs existentes do sistema..."
        );
        
        const collectResponse = await fetch(`${agente.apiUrl}/api/collect`);
        const collectData = await collectResponse.json();
        
        if (collectData.status === 'success') {
            agente.addLogEntry(
                new Date().toLocaleString("pt-BR"),
                "SUCCESS",
                `✅ LOGS COLETADOS: ${collectData.stats?.total_new_logs || 'N/A'} logs processados automaticamente`
            );
        }
        
        // 2. SEGUNDO: Inicia monitoramento em tempo real
        const response = await fetch(`${agente.apiUrl}/api/monitoring/start`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            }
        });
        
        const data = await response.json();
        
        if (data.status === "success") {
            // Ativa flag de monitoramento
            agente.isMonitoring = true;
            
            agente.addLogEntry(
                new Date().toLocaleString("pt-BR"),
                "SUCCESS",
                `✅ MONITORAMENTO ATIVO - ${data.rules_active} regras de detecção carregadas`
            );
            
            agente.addLogEntry(
                new Date().toLocaleString("pt-BR"),
                "INFO",
                `📡 Integração SIEM: ${data.wazuh_enabled ? 'ATIVA' : 'DESABILITADA'} - Logs sendo enviados para análise`
            );
            
            agente.addLogEntry(
                new Date().toLocaleString("pt-BR"),
                "SUCCESS",
                "🎯 SISTEMA LISTO: Executando monitoramento de ameaças em tempo real!"
            );
            
            agente.showNotification("Sistema pronto para demonstração!", "success");
            
            // Atualiza botões
            const startBtn = document.querySelector('button[onclick="startRealTimeMonitoring()"]');
            const stopBtn = document.querySelector('button[onclick="stopRealTimeMonitoring()"]');
            if (startBtn) startBtn.style.opacity = '0.5';
            if (stopBtn) stopBtn.style.opacity = '1';
            
        } else {
            throw new Error(data.message || "Erro desconhecido");
        }
    } catch (error) {
        console.error("❌ Erro ao iniciar monitoramento:", error);
        agente.addLogEntry(
            new Date().toLocaleString("pt-BR"),
            "ERROR",
            `❌ ERRO NO MONITORAMENTO: ${error.message}`
        );
        
        agente.showNotification("Erro ao iniciar monitoramento", "error");
    }
}

async function stopRealTimeMonitoring() {
    console.log("🛑 Parando monitoramento em tempo real...");
    
    // Para el parpadeo inmediatamente
    agente.isMonitoring = false;
    
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
                "WARNING",
                "🛑 Monitoramento em tempo real PARADO - Sistema em modo passivo"
            );
            
            // Actualiza botones
            const startBtn = document.querySelector('button[onclick="startRealTimeMonitoring()"]');
            const stopBtn = document.querySelector('button[onclick="stopRealTimeMonitoring()"]');
            if (startBtn) startBtn.style.opacity = '1';
            if (stopBtn) stopBtn.style.opacity = '0.5';
            
            agente.showNotification("Monitoramento parado com sucesso", "info");
        } else {
            throw new Error(data.message || "Erro desconhecido");
        }
    } catch (error) {
        console.error("❌ Erro ao parar monitoramento:", error);
        agente.addLogEntry(
            new Date().toLocaleString("pt-BR"),
            "ERROR",
            `❌ Erro ao parar monitoramento: ${error.message}`
        );
        
        agente.showNotification("Erro ao parar monitoramento", "error");
    }
}

// ===============================================
// ANÁLISE DE ARQUIVOS DE LOG ESPECÍFICOS
// ===============================================

function handleLogFileSelection() {
    const fileInput = document.getElementById('logFileInput');
    const fileName = document.getElementById('selectedFileName');
    const analyzeBtn = document.getElementById('analyzeBtn');
    
    if (fileInput.files && fileInput.files[0]) {
        const file = fileInput.files[0];
        fileName.textContent = `📄 ${file.name}`;
        analyzeBtn.disabled = false;
        analyzeBtn.style.opacity = '1';
        
        agente.addLogEntry(
            new Date().toLocaleString('pt-BR'),
            'INFO',
            `📁 ARQUIVO SELECIONADO: ${file.name} (${(file.size / 1024).toFixed(2)} KB)`
        );
    } else {
        fileName.textContent = '';
        analyzeBtn.disabled = true;
        analyzeBtn.style.opacity = '0.5';
    }
}

async function analyzeSelectedLogFile() {
    const fileInput = document.getElementById('logFileInput');
    
    if (!fileInput.files || !fileInput.files[0]) {
        agente.showNotification('Nenhum arquivo selecionado!', 'error');
        return;
    }
    
    const file = fileInput.files[0];
    
    agente.addLogEntry(
        new Date().toLocaleString('pt-BR'),
        'INFO',
        `🔍 ANALISANDO ARQUIVO: ${file.name} - Processando conteúdo...`
    );
    
    agente.showNotification('Analisando arquivo de log...', 'info');
    
    try {
        // Lê o arquivo
        const fileContent = await readFileContent(file);
        
        // Envia para o backend para análise
        const response = await fetch(`${agente.apiUrl}/api/analyze-log-file`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                filename: file.name,
                content: fileContent,
                size: file.size
            })
        });
        
        const data = await response.json();
        
        if (data.status === 'success') {
            agente.addLogEntry(
                new Date().toLocaleString('pt-BR'),
                'SUCCESS',
                `✅ ANÁLISE CONCLUÍDA: ${data.stats?.total_lines || 0} linhas processadas`
            );
            
            if (data.stats?.anomalies_found > 0) {
                agente.addLogEntry(
                    new Date().toLocaleString('pt-BR'),
                    'WARNING',
                    `⚠️ ANOMALIAS ENCONTRADAS: ${data.stats.anomalies_found} padrões suspeitos detectados`
                );
            }
            
            if (data.stats?.errors_found > 0) {
                agente.addLogEntry(
                    new Date().toLocaleString('pt-BR'),
                    'ERROR',
                    `❌ ERROS DETECTADOS: ${data.stats.errors_found} erros críticos no arquivo`
                );
            }
            
            // Mostra resumo das descobertas
            agente.addLogEntry(
                new Date().toLocaleString('pt-BR'),
                'INFO',
                `📊 RESUMO: ${data.stats?.warnings || 0} warnings, ${data.stats?.info_logs || 0} logs informativos`
            );
            
            agente.showNotification('Análise de arquivo concluída!', 'success');
            
        } else {
            throw new Error(data.message || 'Erro na análise');
        }
        
    } catch (error) {
        console.error('❌ Erro na análise do arquivo:', error);
        agente.addLogEntry(
            new Date().toLocaleString('pt-BR'),
            'ERROR',
            `❌ ERRO NA ANÁLISE: ${error.message}`
        );
        agente.showNotification('Erro ao analisar arquivo', 'error');
    }
}

async function readFileContent(file) {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        
        reader.onload = function(e) {
            resolve(e.target.result);
        };
        
        reader.onerror = function(e) {
            reject(new Error('Erro ao ler arquivo'));
        };
        
        reader.readAsText(file);
    });
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
