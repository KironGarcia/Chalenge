# Agente IA - Coleta Independente de Logs

## 📋 Resposta às Questões Levantadas

**Pergunta do colega:** *"Achei que está muito bem estruturado, só acho que faltando mostrar onde o agente vai coletar os logs, Sistemas operacionais, aplicações, infraestrutura..."*

**Resposta:** ✅ **IMPLEMENTADO!** O Agente IA agora é **completamente independente** e coleta logs diretamente de múltiplas fontes sem depender de ferramentas SIEM externas.

---

## 🎯 Visão Geral

O **Agente IA** evoluiu de um simples leitor de arquivos para um **sistema completo de coleta multifonte**, capaz de:

- ✅ **Coletar logs do sistema operacional** (Linux, Windows, macOS)
- ✅ **Receber logs via rede** (servidor Syslog integrado)
- ✅ **Acessar servidores remotos** (coleta via SSH)
- ✅ **Monitorar arquivos locais** (em tempo real)
- ✅ **Funcionar 100% independente** (sem necessidade de SIEM)

---

## 🔧 Fontes de Coleta Implementadas

### 1. 🖥️ **Sistema Operacional Local**

O agente coleta logs diretamente do SO onde está executando:

#### **Linux:**
- **journalctl** (systemd logs)
- **/var/log/auth.log** (autenticação)
- **/var/log/syslog** (sistema geral)
- **/var/log/secure** (segurança)

#### **Windows:**
- **Event Log de Segurança**
- **Event Log do Sistema**
- **Event Log de Aplicações**

#### **macOS:**
- **System Log** (comando `log`)

### 2. 📡 **Servidor Syslog Integrado**

O agente **atua como um servidor Syslog**, recebendo logs de:
- Equipamentos de rede (firewalls, switches, routers)
- Servidores remotos
- Aplicações que suportam Syslog
- Qualquer dispositivo configurado para enviar logs via UDP

**Porta padrão:** 5140 (ou 514 se executado como root)

### 3. 🔗 **Coleta Remota via SSH**

O agente pode conectar-se a servidores remotos via SSH para:
- Ler arquivos de log remotos
- Executar comandos de coleta
- Monitorar múltiplos servidores simultaneamente

### 4. 📁 **Arquivos Locais**

Mantém a funcionalidade original:
- Monitoramento em tempo real de diretórios
- Processamento automático de novos arquivos
- Suporte a múltiplos formatos

---

## 🚀 Como Usar

### **1. Coleta Automática (Recomendado)**

```bash
# Inicia o backend com coleta automática
cd agente_ia/backend
python app.py
```

O agente automaticamente:
- Inicia o servidor Syslog
- Coleta logs do sistema a cada 5 minutos
- Monitora arquivos locais em tempo real

### **2. Demonstração Completa**

```bash
# Executa demonstração de todas as funcionalidades
cd agente_ia/backend
python demo_coleta_independente.py
```

### **3. API Endpoints**

```bash
# Status geral do sistema
GET http://localhost:5000/api/status

# Forçar coleta manual
GET http://localhost:5000/api/collect

# Obter logs coletados
GET http://localhost:5000/api/logs
```

---

## ⚙️ Configuração

### **Arquivo:** `config.yaml`

```yaml
coleta:
  # Coleta do sistema operacional
  sistema_operacional:
    ativo: true
    
  # Servidor Syslog
  syslog_server:
    ativo: true
    porta: 5140
    
  # Coleta SSH remota (opcional)
  ssh_remoto:
    ativo: false  # Habilitar se necessário
    hosts:
      - hostname: "servidor1.exemplo.com"
        username: "admin"
        password: "senha_secreta"
        log_paths: ["/var/log/auth.log"]
```

---

## 📊 Exemplo de Uso Real

### **Cenário:** Universidade com múltiplos servidores

1. **Servidor Principal** (onde roda o Agente IA):
   - Coleta seus próprios logs do sistema
   - Recebe logs de equipamentos de rede via Syslog
   - Monitora arquivos locais de aplicações

2. **Servidores Remotos** (via SSH):
   - Servidor Web (logs do Apache/Nginx)
   - Servidor de Email (logs do Postfix)
   - Servidor de Banco de Dados (logs do MySQL/PostgreSQL)

3. **Equipamentos de Rede** (via Syslog):
   - Firewall pfSense
   - Switches gerenciáveis
   - Access Points WiFi

### **Resultado:**
- **Centralização completa** de todos os logs
- **Detecção de anomalias** em tempo real
- **Zero dependência** de ferramentas externas

---

## 🔒 Segurança

- **SSH:** Suporte a autenticação por senha ou chave privada
- **Syslog:** Binding configurável (padrão: todas as interfaces)
- **Logs sensíveis:** Processamento local, sem envio para terceiros
- **Configuração:** Coleta SSH desabilitada por padrão

---

## 📈 Benefícios vs SIEM Tradicional

| Aspecto | SIEM Tradicional | Agente IA |
|---------|------------------|-----------|
| **Complexidade** | Alta (requer especialistas) | Baixa (configuração simples) |
| **Custo** | Alto (licenças + hardware) | Baixo (apenas servidor) |
| **Dependências** | Múltiplas ferramentas | Zero dependências |
| **Tempo de setup** | Semanas/Meses | Minutos |
| **Manutenção** | Alta | Mínima |
| **Customização** | Limitada | Total (código aberto) |

---

## 🧪 Testando a Implementação

### **1. Teste Básico**
```bash
# Verifica se está coletando logs do sistema
curl http://localhost:5000/api/status
```

### **2. Teste Syslog**
```bash
# Envia mensagem de teste
logger -n localhost -P 5140 "Teste do Agente IA"
```

### **3. Teste Completo**
```bash
# Executa demonstração completa
python demo_coleta_independente.py
```

---

## 💡 Próximos Passos

1. **Produção:** Configurar o `config.yaml` com suas fontes específicas
2. **Monitoramento:** Usar os endpoints da API para integração
3. **Alertas:** Configurar detecção de anomalias e notificações
4. **Escalabilidade:** Adicionar mais servidores SSH conforme necessário

---

## ✅ Conclusão

O **Agente IA** agora responde completamente à pergunta do colega:

> **"Onde o agente vai coletar os logs?"**

**Resposta:** Em **TODOS OS LUGARES** que importam:
- Sistema operacional local
- Servidores remotos via SSH  
- Equipamentos de rede via Syslog
- Arquivos e aplicações locais

**Resultado:** Um sistema **100% independente**, **fácil de configurar** e **altamente eficaz** para detecção de anomalias em ambientes universitários.

---

*Documentação técnica - Agente IA v2.0*  
*Implementação independente completa - Sem dependência de SIEM* 