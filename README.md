# Descobridor de Hosts (LAN Scanner em Python)

Script em Python para **descobrir máquinas ativas na sua rede local** (mesmo domínio de broadcast / sub-rede), registrando os resultados em um arquivo `.txt`.  
Funciona em **Windows, Linux e macOS** usando **apenas biblioteca padrão**.

> O script varre os IPs da sub-rede (auto-detectada ou informada via `--cidr`), executa **ping** em paralelo, cruza com a **tabela ARP** para obter **MAC addresses**, tenta **DNS reverso** (opcional) e salva tudo em um relatório no formato:  
> `IP; MAC; RTT(ms); HOSTNAME`.

---

## ✨ Recursos

- Auto-detecção da rede local (CIDR), quando possível.
- Varredura rápida com **muitas threads** (configurável).
- Coleta de **MAC address** via tabela ARP do sistema.
- **DNS reverso** opcional para obter nomes de host.
- Saída em `.txt` com cabeçalho, timestamp e ordenação por IP.
- **Sem dependências externas**.

---

## 🧰 Requisitos

- **Python 3.10+**
- Permissão para executar `ping` e ler a tabela ARP no seu sistema.

---

## 📥 Instalação

```bash
# via SSH (recomendado)
git clone git@github.com:GabrielMatiaszsz/descobridor-de-hosts.git
cd descobridor-de-hosts

# ou via HTTPS
# git clone https://github.com/GabrielMatiaszsz/descobridor-de-hosts.git
# cd descobridor-de-hosts
