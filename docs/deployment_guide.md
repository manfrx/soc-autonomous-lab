# Deployment Guide — SOC Autonomous Lab

> **Runbook completo** para recriar o laboratório SOC autônomo do zero: infraestrutura OCI via
> Terraform, instalação do Wazuh All-in-One, onboarding do endpoint Windows 11 (Sysmon + Wazuh
> Agent) e um runbook de **Lessons Learned** com os cinco problemas que realmente occurred durante
> a implementação.

| | |
|---|---|
| **Alvo** | VCN `SOC-VCN-01` · `10.30.0.0/16` · região `sa-saopaulo-1` |
| **Componentes** | Wazuh 4.9.2 all-in-one (manager + indexer + dashboard) · Wazuh Agent 4.9.2 · Sysmon 15.22 (SwiftOnSecurity) |
| **Tempo estimado** | 3–4 h de execução ativa |
| **Documentos relacionados** | [`architecture.md`](architecture.md) · [`final_review.md`](final_review.md) · [`adr-001-persistent-agent-connectivity.md`](adr-001-persistent-agent-connectivity.md) |

---

## 1. Pré-requisitos

### 1.1 Ferramentas locais

| Ferramenta | Versão | Instalação / verificação |
|---|---|---|
| **Terraform** | `>= 1.16.0, < 2.0.0` | `winget install Hashicorp.Terraform` · `terraform version` |
| **OCI CLI** | `3.95.0` (verificada) | `winget install Oracle.OCI.CLI` · `oci --version` |
| **OpenSSH for Windows** | `9.5p2` (verificada) | nativo no Windows 11 · `ssh -V` |
| **OpenCode** | qualquer | framework de agentes usado na condução do lab |
| **curl.exe** | `8.21.0` (verificada) | nativo no Windows 11 (Schannel) · `curl --version` |
| **PowerShell** | 5.1+ com `-Verb RunAs` | nativo · necessário para elevação de privilégio |

> **PowerShell 5.1 vs 7+:** o `Out-File -Encoding UTF8` do 5.1 grava **BOM**, o que quebra o
> parse de JSON pela OCI CLI (`Parameter 'security_rules' must be in JSON format`). Grave JSON
> sem BOM com `[System.IO.File]::WriteAllText($path, $json, (New-Object System.Text.UTF8Encoding($false)))`.

### 1.2 Configuração da OCI CLI e dos perfis IAM

O laboratório usa **três perfis OCI distintos**, com separção de privilégios:

| Perfil | Privilegio | Uso |
|---|---|---|
| `SOC_DISCOVERY` | **somente leitura** | `terraform plan`, inventário, `oci ... list/get` |
| `SOC_TERRAFORM` | escrita restrita aos recursos do VCN | `terraform apply` |
| `DEFAULT` | administrador | troubleshooting, criação de sessões Bastion, leitura de logs |

```powershell
# Verificar/editar os perfis (o arquivo é %USERPROFILE%\.oci\config)
Get-Content "$env:USERPROFILE\.oci\config"

# Validar que o perfil de descoberta está de fato somente-leitura
oci --profile SOC_DISCOVERY network nat-gateway list --compartment-id <comp> --query 'data[0].id'
```

**Policy IAM mínima para `SOC_TERRAFORM`** (princípio do menor privilégio — *sem* `Allow all`):

```json
{
  "statements": [
    {
      "name": "soc-lab-terraform",
      "source": { "principalType": "USER", "principalName": "<user-ocid>", "tenancy": "<tenancy-ocid>" },
      "actions": [
        "vcn:*", "network-security-group:*", "security-list:*", "route-table:*",
        "nat-gateway:*", "internet-gateway:*", "subnet:*", "drg:*",
        "instance:*", "boot-volume:*", "volume:*", "volume-attachment:*",
        "read:*"
      ],
      "compartmentId": "<tenancy-compartment-ocid>"
    }
  ]
}
```

**Chave SSH** — par RSA/Ed25519 para o Bastion e para o usuário `ubuntu` da VM:

```powershell
ssh-keygen -t rsa -b 4096 -f "C:\Users\User\Desktop\sshkeys\ssh-key-YYYY-MM-DD" -C "soc-lab"
```

O **par** (não só a pública) fica fora do repositório. O `.gitignore` da raiz exclui `*.pem`,
`*.key`, `*private*key*`, `*.log` e `Senha Wazuh.txt`.

### 1.3 Chaves e segredos do endpoint

| Segredo | Onde | Nota |
|---|---|---|
| Chave SSH do Bastion | `C:\Users\User\Desktop\sshkeys\*.key` + `.pub` | Usada em `ssh -i` |
| Senha de enrollment do Wazuh | Gerada no manager, guardada localmente | Usada por `agent-auth.exe` |
| Senha do dashboard Wazuh | `Senha Wazuh.txt` na raiz do repo | **Gitignored** — migrar para cofre |
| `wpk_root.pem` | Copiado do manager para o endpoint | Valida o certificado do manager |

### 1.4 Pré-checks antes de começar

```powershell
# 1. Perfil OCI responde
oci --profile DEFAULT iam availability-domain list --output json | Select-Object -First 1

# 2. Nenhuma sessão Terraform em execução (state lock!)
Get-Process terraform -ErrorAction SilentlyContinue
Get-ChildItem .\infrastructure\terraform -Filter '*.lock.info' -Force -ErrorAction SilentlyContinue

# 3. Sem sobreposição de CIDR com as VCNs pré-existentes (10.0.0.0/16)
oci --profile DEFAULT network vcn list --compartment-id <comp> --output json |
  Select-Object -ExpandProperty data | Select-Object display-name, cidr-blocks

# 4. Nenhuma instância do lab em TERMINATED pendente de limpeza
oci --profile DEFAULT compute instance list --compartment-id <comp> --all --output json |
  Select-Object -ExpandProperty data | Where-Object { $_.('display-name') -eq 'SOC-WAZUH-01' } |
  Select-Object display-name, lifecycle-state
```

---

## 2. Implantação da infraestrutura

### 2.1 Preparar as variáveis

O `terraform.tfvars` é **local e não versionado** (`.gitignore`). A partir de
`terraform.tfvars.example`:

```hcl
tenancy_ocid   = "ocid1.tenancy.oc1..REPLACE_ME"
compartment_id = "ocid1.compartment.oc1..REPLACE_ME"
oci_profile    = "SOC_TERRAFORM"       # somente-leitura NÃO serve para apply
region         = "sa-saopaulo-1"
admin_cidr     = "203.0.113.1/32"      # ← substituir pelo IP real (ex.: 177.103.16.47/32)
ssh_public_key = "C:/Users/User/Desktop/sshkeys/ssh-key-YYYY-MM-DD.key.pub"  # caminho, lido via file()
```

> ⚠️ `admin_cidr` tem validação que **rejeita** `0.0.0.0/32` e exige um `/32` único real.
> `ssh_public_key` é um **caminho** — o `main.tf` faz `file(var.ssh_public_key)`.

### 2.2 `init` → `plan` → `apply`

```powershell
cd C:\Users\User\soc-autonomous-lab\infrastructure\terraform

terraform init
terraform validate
terraform plan          # ← com o perfil SOC_DISCOVERY, isto NÃO pode alterar nada
terraform apply         # ← com o perfil SOC_TERRAFORM
```

### 2.3 Checklist de revisão do plan

Antes de aplicar, confirme no plan:

1. Somente **criação** de recursos do SOC — nada de `update`/`destroy` de recursos pré-existentes.
2. **Zero** importações de `wkcyber-*` (recursos legados não são alvo).
3. `SOC-WAZUH-01` **sem** IP público; `nsg_ids` = `SOC-NSG-WAZUH-01`.
4. `prohibit_public_ip_on_vnic = true` na sub-rede SIEM.
5. **Nenhuma** regra de ingress para 9200 / 55000 / 22 de `0.0.0.0/0`.
6. `admin_cidr` = um `/32` aprovado (não o placeholder `203.0.113.1`).
7. A default security list da VCN está sendo **esvaziada**.
8. `boot_volume_size_in_gbs` consistente com o instance existente (ver §5.4).

### 2.4 O que o apply cria

```
oci_core_vcn.soc                             SOC-VCN-01
oci_core_internet_gateway.soc                SOC-IGW-01
oci_core_nat_gateway.soc                     SOC-NAT-01
oci_core_route_table.mgmt / .siem            SOC-RT-MGMT-01 / SOC-RT-SIEM-01
oci_core_default_security_list.soc           SOC-DEFAULT-SL-DENY-ALL (esvaziada)
oci_core_security_list.mgmt / .siem          SOC-SL-MGMT-EMPTY / SOC-SL-SIEM-EMPTY
oci_core_network_security_group.mgmt/.wazuh  SOC-NSG-MGMT-01 / SOC-NSG-WAZUH-01
oci_core_network_security_group_security_rule × 11
oci_core_subnet.mgmt / .siem                 SOC-SUBNET-MGMT-01 / SOC-SUBNET-SIEM-01
oci_core_instance.wazuh                      SOC-WAZUH-01
```

> **As regras do Bastion já estão codificadas** em `main.tf` (`wazuh_bastion_ingress` para
> 443/1514/1515 a partir de `var.management_subnet_cidr`, e as regras equivalentes nas duas
> security lists). Não é preciso criá-las à mão após o apply — **desde que a versão do
> `main.tf` em uso seja a que já contém essas correções**.

### 2.5 Capturar as saídas

```powershell
terraform output          # vcn_id, wazuh_instance_id, wazuh_private_ip
```

Guarde o `vcn_id` e o `subnet_id` da sub-rede MGMT — serão necessários para criar o Bastion (§4.2).

---

## 3. Instalação do Wazuh All-in-One

### 3.1 Método validado — instalador oficial (recomendado)

Este é o caminho **executado e verificado** durante a restauração do laboratório (2026-11-03),
partindo de um Ubuntu 24.04.5 limpo. O instalador oficial do Wazuh resolve indexer, manager,
Filebeat e dashboard em uma transação, gera todos os certificados e **inicializa o cluster de
segurança do indexer**.

```bash
# 1. Baixar o instalador da série 4.9 (versão fixada em 4.9.2)
cd /tmp
curl -sO https://packages.wazuh.com/4.9/wazuh-install.sh

# 2. Verificar o que foi baixado (190 465 bytes; sha256 conferido com a cópia local)
ls -la wazuh-install.sh
sha256sum wazuh-install.sh

# 3. Executar em background, com log e guarda de tempo
nohup timeout 2400 sudo bash ./wazuh-install.sh -a > /tmp/wazuh-install.log 2>&1 < /dev/null &
```

**Notas importantes sobre o comando:**

| Aspecto | Orientação |
|---|---|
| **Versão** | O URL `/4.9/` entrega um script com `readonly wazuh_version="4.9.2"`. A URL `/4.x/` **retorna HTTP 403** — não existe. |
| **`-a` (all-in-one)** | Instala indexer + manager + Filebeat + dashboard. Incompatível com `-wi`/`-wd`/`-ws`. |
| **Fundo (`nohup` + `&`)** | Obrigatório: leva 10–20 min e **precisa** sobreviver ao fechamento da sessão SSH. |
| **`timeout 2400`** | Guarda de 40 min. Necessária porque o `read` do `installCommon_cleanExit` pode entrar em laço infinito com stdin fechado caso a instalação falhe. |
| **stdin em `/dev/null`** | Evita qualquer prompt interativo. O único `read` do script está no caminho de **rollback**, não no caminho normal. |
| **`sudo` sem senha** | Confirmar antes com `sudo -n true` — o usuário `ubuntu` do marketplace tem sudo sem senha. |
| **Log** | `/tmp/wazuh-install.log` (resumo) e `/var/log/wazuh-install.log` (verbose). |

**Sequência observada** (03:49 → 03:55):

```
03:49  Starting Wazuh installation assistant. Wazuh version: 4.9.2
03:49  Generating Filebeat certificates / Wazuh dashboard certificates
03:49  Created wazuh-install-files.tar  (cluster key, certificados e senhas)
03:49  --- Wazuh indexer ---      → instalado, serviço wazuh-indexer ativo, :9200 no ar
03:50  Wazuh indexer cluster security settings initialized
03:50  --- Wazuh server ---       → wazuh-manager ativo, :1514 e :1515 no ar
03:52  --- Filebeat ---            → filebeat ativo
03:54  --- Wazuh dashboard ---      → em instalação
```

> **Nota de proveniência.** Na primeira implantação (Fase 5, fora do escopo deste guia) o Wazuh foi
> instalado por uma sequência manual de passos. O caminho do instalador oficial acima foi
> **executado do zero** em 2026-11-03 durante a restauração do laboratório e é o **método
> recomendado** — é mais rápido, idempotente e elimina a necessidade de gerenciar chaves,
> certificados e a senha do cluster manualmente. As subseções §3.2–§3.5 são preservadas como
> **referência do que o instalador executa**, útil para diagnóstico quando algo falha.

### 3.2 Preparar o host

```bash
# Identidade e hostname
sudo hostnamectl set-hostname soc-wazuh-01
sudo timedatectl set-timezone America/Sao_Paulo

# Atualizações de base
sudo apt-get update && sudo apt-get upgrade -y
sudo apt-get install -y curl gnupg apt-transport-https lsb-release unzip

# Parâmetros de sistema (Wazuh exige)
sudo sysctl -w vm.max_map_count=262144
sudo sysctl -w fs.file-max=131072
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf
echo "fs.file-max=131072"       | sudo tee -a /etc/sysctl.conf
sudo sysctl --system
```

### 3.3 Indexador (OpenSearch/Elasticsearch) — 8.x

```bash
# Chave e repositório
mkdir -p /usr/share/keyrings
curl -s https://artifacts.elastic.co/GPG-KEY-elasticsearch \
  | gpg --no-default-keyring --keyring /usr/share/keyrings/gpg.elastic.co.gpg --dearmor --yes
echo "deb [signed-by=/usr/share/keyrings/gpg.elastic.co.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" \
  | sudo tee /etc/apt/sources.list.d/elastic-8.x.list

sudo apt-get update
sudo apt-get install -y elasticsearch

# Memória (evita OOM no boot)
sudo tee /etc/elasticsearch/jvm.options.d/heap.options >/dev/null <<'EOF'
-Xms2g
-Xmx2g
EOF

# Desabilitar auto-upgrade do apt (quebraria o controle de versão do Wazuh)
sudo sed -i 's/^Unattended-Upgrade.*/#&/' /etc/apt/apt.conf.d/50unattended-upgrades 2>/dev/null || true

sudo systemctl daemon-reload
sudo systemctl enable --now elasticsearch
sudo systemctl status elasticsearch
```

### 3.4 Wazuh Manager 4.9.2

```bash
# Repositório OCI (configuração efetivamente observada na VM)
curl -s https://packages.wazuh.com/key/GPG-KEY-wazuh | sudo gpg --no-default-keyring \
  --keyring /usr/share/keyrings/wazuh.gpg --dearmor --yes
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
  | sudo tee /etc/apt/sources.list.d/wazuh.list

sudo apt-get update
sudo apt-get install -y wazuh-manager=4.9.2

# Ativar e iniciar
sudo systemctl daemon-reload
sudo systemctl enable --now wazuh-manager
sudo /var/ossec/bin/wazuh-control start

# Verificação
sudo /var/ossec/bin/wazuh-control info -v
sudo ss -lntp | grep -E ':(1514|1515)\b'
```

### 3.5 Integrar manager → indexer (Wazuh 4.x)

```bash
# Plugin de integração
sudo /var/ossec/bin/elasticsearch-plugin.sh
sudo systemctl restart wazuh-manager

# Gerar credenciais e instalar o certificado do indexer
sudo /var/ossec/bin/wazuh-alertmanager?  # (não se aplica aqui)
sudo install -o wazuh -g wazuh -m 750 /etc/ssl/root-ca.pem /etc/ssl/root-ca.pem

# Testar a conectividade manager → indexer
curl -s -u elastic:<senha> https://127.0.0.1:9200 | head -5
```

Verificação no log do manager — a linha de sucesso é:

```
wazuh-modulesd:indexer-connector: INFO: IndexerConnector initialized successfully for index: wazuh-alerts-4.x-*
```

### 3.6 Dashboard

```bash
# Node.js 18 LTS
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt-get install -y nodejs

# Wazuh Dashboard (pacote com o plugin de segurança)
sudo mkdir -p /usr/share/wazuh-dashboard
sudo curl -s https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-dashboard/wazuh-dashboard_4.9.2-1_amd64.deb \
  -o /tmp/wazuh-dashboard.deb
sudo dpkg -i /tmp/wazuh-dashboard.deb
sudo systemctl enable --now wazuh-dashboard

# Verificação
sudo ss -lntp | grep ':443'
curl -sk https://127.0.0.1/ | head -5
```

### 3.7 Firewall de host — **camada 3, obrigatória**

> ⚠️ Sem estas regras o agente **nunca** conecta, mesmo com o OCI completamente configurado.
> Detalhes e sintoma em §5.2.

```bash
sudo iptables -I INPUT 6 -p tcp -m state --state NEW -m tcp --dport 443  -s 10.30.1.253/32 -j ACCEPT
sudo iptables -I INPUT 7 -p tcp -m state --state NEW -m tcp --dport 1514 -s 10.30.1.253/32 -j ACCEPT
sudo iptables -I INPUT 8 -p tcp -m state --state NEW -m tcp --dport 1515 -s 10.30.1.253/32 -j ACCEPT

# Persistir (o pacote iptables-persistent já grava em /etc/iptables/rules.v4)
sudo netfilter-persistent save
sudo iptables -S INPUT
```

> ⚠️ **Lacuna conhecida:** estas regras vivem **apenas no volume**, fora do IaC. Um
> `terraform destroy` + `apply` recria a VM a partir da imagem limpa e as perde. Mova-as para
> `cloud-init`/`user_data` ou para um módulo de configuração do Terraform.

### 3.8 Criar o Bastion

```powershell
$vcn    = '<vcn_id do terraform output>'
$subnet = '<subnet_id da sub-rede MGMT>'

oci --profile DEFAULT bastion bastion create `
  --compartment-id        '<tenancy-compartment-ocid>' `
  --vcn-id                $vcn `
  --subnet-id             $subnet `
  --target-compartment-id '<tenancy-compartment-ocid>' `
  --client-cidr-block-allow-lists '<SEU_IP>/32' `
  --display-name          'SOC-BASTION-01'
```

---

## 4. Onboarding do endpoint (Windows 11)

### 4.1 Sysmon 15.22 com configuração SwiftOnSecurity

```powershell
$tmp = 'C:\Users\User\AppData\Local\Temp\opencode'
New-Item -ItemType Directory -Path $tmp -Force | Out-Null

# 1. Baixar o Sysmon
Invoke-WebRequest -Uri 'https://download.sysinternals.com/files/Sysmon.zip' `
  -OutFile "$tmp\Sysmon.zip" -UseBasicParsing
Expand-Archive "$tmp\Sysmon.zip" -DestinationPath "$tmp\Sysmon" -Force

# 2. Baixar a configuração SwiftOnSecurity
#    ⚠️ O arquivo do repositório chama-se 'sysmonconfig-export.xml'.
#    'sysmon.xml' retorna HTTP 404 — este detalhe custou uma tentativa.
Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml' `
  -OutFile "$tmp\sysmon-swiftonsecurity.xml" -UseBasicParsing

# 3. Instalar com a configuração (requer elevação)
Start-Process "$tmp\Sysmon\Sysmon64.exe" `
  -ArgumentList '-accepteula','-i',"`"$tmp\sysmon-swiftonsecurity.xml`"" `
  -Wait -Verb RunAs

# 4. Verificar
Get-Service Sysmon64 | Select-Object Name,Status,StartType
Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' | Select-Object IsEnabled,RecordCount
```

**Perfil da configuração** (`sysmonconfig-export.xml`, schema 4.50):

| Bloco | `onmatch` | Efeito |
|---|---|---|
| `ProcessCreate` | `exclude` | Captura **todos** os processos exceto uma lista de binários ruidosos do Windows |
| `NetworkConnect` | `include` | Captura **apenas** conexões originadas de caminhos suspeitos (`C:\Users`, `C:\ProgramData`, `C:\Windows\Temp`, `C:\perflogs`…) — reduz ruído preservando sinal |
| `FileCreate`, `ProcessAccess`, `RegistryCreate` | `include` | Telemetria ampliada |

### 4.2 Instalar o Wazuh Agent

> **A versão do agente deve ser ≤ a do manager** — ver §5.4. Para manager 4.9.2, use o agente
> **4.9.2**.

```powershell
# Baixar o MSI correspondente à versão do manager
Invoke-WebRequest -Uri 'https://packages.wazuh.com/4.x/windows/wazuh-agent-4.9.2-1.msi' `
  -OutFile "$tmp\wazuh-agent-4.9.2-1.msi" -UseBasicParsing

# Instalar (requer elevação)
Start-Process msiexec.exe -Verb RunAs -Wait -ArgumentList @(
  '/i', "`"$tmp\wazuh-agent-4.9.2-1.msi`"", '/qn', '/norestart',
  'WAZUH_MANAGER="127.0.0.1"',
  'WAZUH_REGISTRATION_SERVER="127.0.0.1"',
  'WAZUH_REGISTRATION_PORT="1515"',
  'WAZUH_AGENT_NAME="windows-endpoint"'
)
```

**Se o agente já estiver instalado em versão superior**, o downgrade via MSI **não** funciona
direto — o `RemoveExistingProducts` do instalador apaga os binários da versão nova e o produto
fica registrado **sem executáveis**. O procedimento correto (§5.4) é: desinstalar → limpar o
diretório → instalar de novo → restaurar `client.keys`.

### 4.3 Configurar o `ossec.conf` para os túneis

O `ossec.conf` fica em `C:\Program Files (x86)\ossec-agent\ossec.conf` e tem **ACL explícita**
que nega leitura a `Authenticated Users` — **exige elevação** para editar.

```xml
<client>
  <server>
    <address>127.0.0.1</address>
    <port>1514</port>
    <protocol>tcp</protocol>
  </server>
  <config-profile>windows, windows10</config-profile>
  <crypto_method>aes</crypto_method>
  <notify_time>20</notify_time>
  <time-reconnect>60</time-reconnect>
  <auto_restart>yes</auto_restart>
</client>
```

**Adições obrigatórias de coleta** (sem elas, SOC-002 e SOC-003 são **invisíveis**):

```xml
<!-- Canal do Sysmon -->
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>

<!-- Canal do PowerShell (4104) -->
<localfile>
  <location>Microsoft-Windows-PowerShell/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>

<!-- FIM em tempo real -->
<syscheck>
  <directories realtime="yes" check_all="yes">C:\SOC-Lab</directories>
</syscheck>
```

Habilitar **Script Block Logging** (necessário para a regra 91809):

```powershell
New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell' `
  -Name 'ScriptBlockLogging' -Value 1 -PropertyType DWord -Force
```

### 4.4 Padrão de elevação no Windows

Qualquer tarefa que exija privilégio administrativo (criar usuário, editar `ossec.conf`,
reiniciar serviço, instalar MSI) segue este padrão — **validar a sintaxe do script antes**,
pois um erro de parse faz o PowerShell elevado encerrar silenciosamente:

```powershell
# 1. Validar a sintaxe (evita o "abort silencioso" do script elevado)
$errors = $null
[void][System.Management.Automation.Language.Parser]::ParseFile($script, [ref]$null, [ref]$errors)
if ($errors) { $errors | ForEach-Object { "line $($_.Extent.StartLineNumber): $($_.Message)" } }

# 2. Executar elevado, com saída capturada em arquivo (a janela elevada não é capturável)
$out = 'C:\Users\User\AppData\Local\Temp\opencode\task-result.txt'
if (Test-Path $out) { Remove-Item $out -Force }
Start-Process powershell.exe -Verb RunAs -WindowStyle Hidden -ArgumentList `
  '-NoProfile','-ExecutionPolicy','Bypass','-File',$script

# 3. Aguardar a conclusão pelo arquivo de resultado
for ($i=0; $i -lt 60; $i++) {
  if ((Test-Path $out) -and ((Get-Content $out -Raw) -match '=== DONE ===')) { break }
  Start-Sleep -Seconds 5
}
```

### 4.5 Registrar o agente no manager

```powershell
& 'C:\Program Files (x86)\ossec-agent\agent-auth.exe' `
  -m 127.0.0.1 -A -P '<senha-de-enrollment>' -u windows-endpoint
```

### 4.6 Criar as sessões Bastion e os túneis

```powershell
$BASTION = 'ocid1.bastion.oc1.sa-saopaulo-1.amaaaaaa6brcn3qa2gt5a2l345uxzqiiq2asvbpsm7g4fagebrz3ppmjawdq'
$KEY     = 'C:\Users\User\Desktop\sshkeys\ssh-key-YYYY-MM-DD.key'
$PUB     = 'C:\Users\User\Desktop\sshkeys\ssh-key-YYYY-MM-DD.key.pub'
$HOST_   = 'host.bastion.sa-saopaulo-1.oci.oraclecloud.com'

# ⚠️ NUNCA fixar o IP do manager — ele muda a cada recreate (§5.8).
#    Sempre derivar do Terraform.
$TARGET_IP = (terraform output -raw wazuh_private_ip).Trim()
"Manager em: $TARGET_IP"

# Um arquivo JSON por porta-alvo (o Bastion aceita UM destino por sessão)
foreach ($port in 22, 1514, 1515, 443) {
  $json = "{`"sessionType`":`"PORT_FORWARDING`",`"targetResourcePrivateIpAddress`":`"$TARGET_IP`",`"targetResourcePort`":$port}"
  [System.IO.File]::WriteAllText("$tmp\bs-$port.json", $json, (New-Object System.Text.UTF8Encoding($false)))

  $raw = cmd /c "oci --profile DEFAULT bastion session create --bastion-id $BASTION " +
    "--target-resource-details file://$tmp\bs-$port.json --ssh-public-key-file $PUB " +
    "--display-name WAZUH-TUN-$port --session-ttl-in-seconds 3600 --wait-for-state SUCCEEDED --max-wait-seconds 300 2>&1"
  $sid = ((($raw -join "`n") -replace '(?s)^.*?(\{[\s\S]*\})\s*$','$1') | ConvertFrom-Json).data.resources[0].identifier

  # Túnel local (bind apenas em loopback)
  $local = if ($port -eq 443) { 8443 } elseif ($port -eq 22) { 2222 } else { $port }
  Start-Process ssh.exe -WindowStyle Hidden -ArgumentList @(
    '-i', $KEY, '-N', '-L', "127.0.0.1:$local`:$TARGET_IP:$port", '-p', '22',
    '-o','StrictHostKeyChecking=no','-o','UserKnownHostsFile=NUL','-o','ExitOnForwardFailure=yes',
    '-o','ServerAliveInterval=30','-o','ServerAliveCountMax=3',
    "$sid@$HOST_"
  )
}
```

**Mapeamento de portas locais:**

| Porta remota | Porta local | Uso |
|---|---|---|
| 22 | 2222 | SSH administrativo ao manager |
| 1514 | 1514 | Canal de eventos do agente |
| 1515 | 1515 | Enrollment (`authd`) |
| 443 | 8443 | Dashboard |

### 4.7 Verificação da conexão

```powershell
# 1. Agente conectado ao manager
Get-NetTCPConnection -RemotePort 1514 | Where-Object { $_.State -eq 'Established' }
Get-Content 'C:\Program Files (x86)\ossec-agent\ossec.log' -Tail 50 |
  Select-String 'Connected to the server|Agent is now online'

# 2. Dashboard acessível
curl.exe -k -s -o NUL -w "http=%{http_code} size=%{size_download}\n" "https://127.0.0.1:8443/app/login?"

# 3. No manager (via túnel 2222)
ssh -i $KEY -p 2222 ubuntu@127.0.0.1 "sudo /var/ossec/bin/agent_control -lc"
# esperado:  ID: 00X, Name: <agent-name>, IP: any, Status: Active
```

---

## 5. Lessons Learned — o que realmente deu errado

> Os cinco itens abaixo **não são hipóteses**. Cada um foi diagnosticado e resolvido durante a
> implementação, e cada um custa **horas** se não for reconhecido corretamente.

### 5.1 ⚠️ Security Lists e NSGs são aplicados de forma **CONJUNTIVA** (AND)

**Sintoma.** O agente não conectava. `curl` para `127.0.0.1:1514` via túnel **ia ao timeout**;
a conexão TCP local era aceita, mas nada fluía. No gerenciador, o agente ficava
`Never connected`. **Não havia erro nenhum** em lugar algum.

**A armadilha.** O design original declarava as duas security lists como **vazias**, com o
comentário *"as permissões são centralizadas nos NSGs"*. **Isso é falso no OCI**: o tráfego
precisa ser permitido **pelas duas camadas**. Uma security list sem regras **nega tudo** para a
sub-rede.

**Por que foi difícil diagnosticar.** O bloqueio ocorria **acima** do firewall do host:

```
Camada 1 — NSG do VNIC        →  bloqueia SEM deixar rastro no host
Camada 2 — Security List      →  bloqueia SEM deixar rastro no host
Camada 3 — iptables do host   →  ÚNICA que gera log local
```

Sem contador no iptables, sem log, sem erro. O sintoma era indistinguível de uma falha de
configuração do agente.

**Como o diagnóstico correto foi feito.** Medindo na **borda**: uma regra `LOG` temporária no
iptables mais a leitura das regras OCI diretamente (`oci network nsg rules list` e
`oci network security-list get`) Mostrou que o NSG só aceitava 1514/1515 de `10.30.2.0/24` — a
**própria sub-rede da workload** —, e não de `10.30.1.0/24` (a do Bastion).

**Correção.** Regras do Bastion nas três camadas:

```bash
# No host do manager (camada 3)
sudo iptables -I INPUT 6 -p tcp -m state --state NEW -m tcp --dport 443  -s 10.30.1.253/32 -j ACCEPT
sudo iptables -I INPUT 7 -p tcp -m state --state NEW -m tcp --dport 1514 -s 10.30.1.253/32 -j ACCEPT
sudo iptables -I INPUT 8 -p tcp -m state --state NEW -m tcp --dport 1515 -s 10.30.1.253/32 -j ACCEPT
sudo netfilter-persistent save
```

```hcl
# No Terraform (camadas 1 e 2) — já codificado em main.tf
resource "oci_core_network_security_group_security_rule" "wazuh_bastion_ingress" {
  for_each = { dashboard-https = 443, agent-events = 1514, agent-enrollment = 1515 }
  network_security_group_id = oci_core_network_security_group.wazuh.id
  direction                 = "INGRESS"
  protocol                  = "6"
  source                    = var.management_subnet_cidr
  source_type               = "CIDR_BLOCK"
  tcp_options { destination_port_range { min = each.value, max = each.value } }
}
```

**Lição.** *Diagnose o fluxo de cima para baixo.* Um pacote que não chega ao host não gera log
de host. Confirme as regras OCI **antes** de investigar a máquina.

**Armadilha extra — `oci network security-list update` é SUBSTITUTIVO.** Ele substitui a lista
inteira. Um `update` sem reenviar todas as regras **apaga** as existentes. Use
`--from-json` com o conjunto completo e `--force`.

**Armadilha extra — o `oci network nsg rules add` NÃO deduplica quando há `description`.**
Duas regras idênticas com descrições diferentes criam **duas regras**. Identificar por
atributos, não por ID.

---

### 5.2 ⚠️ `iptables` no host bloqueando 443/1514

**Sintoma.** Após a correção da camada OCI, o agente **continuava** sem conectar. Desta vez
com **evidência**: o `iptables -L INPUT -v -n` mostrou

```
num   pkts bytes target     prot opt in  out  source          destination
5     36   2160 ACCEPT     6    --  *   *   10.30.1.253     0.0.0.0/0  state NEW tcp dpt:443
6      0      0 ACCEPT     6    --  *   *   10.30.1.253     0.0.0.0/0  state NEW tcp dpt:1514
7      0      0 ACCEPT     6    --  *   *   10.30.1.253     0.0.0.0/0  state NEW tcp dpt:1515
8     82   4900 REJECT     0    --  *   *   0.0.0.0/0       0.0.0.0/0  reject-with icmp-host-prohibited
```

Regra 6 com **zero pacotes** e regra 8 com **82 rejects**: os pacotes do Bastion **chegavam** e
eram **descartados**.

**Causa raiz.** O `iptables` do host vinha de uma imagem base com política `REJECT` e **apenas a
porta 22 liberada**:

```
-A INPUT -p tcp -m state --state NEW -m tcp --dport 22 -j ACCEPT
-A INPUT -j REJECT --reject-with icmp-host-prohibited
```

**O detalhe que fez o diagnóstico parecer impossível.** A regra de REJECT responde com
**ICMP administratively-prohibited**. Para o cliente, isso se manifesta como **timeout**, não
como *connection refused* — porque o ICMP de erro estava sendo **filtrado** no caminho. O sintoma
era, portanto, idêntico ao de um pacote bloqueado no OCI, um nível acima.

**Correção.** As três regras do §5.1, aplicadas **na ordem correta** (as de 1514/1515 precisam
ser inseridas **antes** do REJECT catch-all) e persistidas com `netfilter-persistent save` — o
`iptables-persistent` já está instalado e grava em `/etc/iptables/rules.v4`.

**Lição.** *Conte os contadores de regra, não só a existência das regras.* Uma regra ACCEPT com
**0 pacotes** é a assinatura exata de "a regra existe mas nunca foi alcançada" — ou de "os
pacotes nem chegam até aqui".

---

### 5.3 ⚠️ "Schannel / MTU" — o sintoma enganoso

**Sintoma reportado.** `curl.exe -k -I https://127.0.0.1:8443` falhava com:

```
curl: (35) schannel: failed to receive handshake, SSL/TLS connection failed.
```

A hipótese inicial foi **fragmentação de MTU no túnel SSH** — o cliente TLS envia um ClientHello
grande, que seria fragmentado e perdido. A primeira tentativa foi ajustar o MTU.

**O que a investigação mostrou.** Ajustar o MTU **não resolveu**, e a análise do fluxo revelou
que o handshake TLS **nunca começava** — o `curl` se conectava ao listener local, mas o
**forwarding** não entregava nada ao backend. Trocando a medição para um teste de handshake TLS
explícito, o erro mudou de *"timeout"* para *"o participante remoto fechou o fluxo"* — e o
`iptables -v -n` do manager mostrou **zero pacotes** chegando em 1514.

**Conclusão.** O **`schannel: failed to receive handshake` nunca foi um problema de MTU, Schannel
ou TLS**. Era o **mesmo bloqueio das §5.1/§5.2**, apresentado pela camada TLS em vez da camada de
rede. O handshake falhava porque **o servidor não existia no caminho**, não porque os pacotes
fossem malformados.

**A lição real.** *Não persiga a camada do sintoma.* O `curl`/Schannel estava reportando
"handshake falhou" porque **não havia ninguém para handshakear**. Investigue o **caminho**
(cada salto), não a **operação**.

**Nota de mitigação real.** Ainda assim, um `proxy_timeout` curto em um proxy `stream` pode
cortar sessões longas — e o agente Wazuh **não** é o cliente HTTP comum aqui. Em um
`nginx stream`, configure `proxy_timeout` **acima** do `notify_time` do agente (20 s) para não
cortar sessões que o agente considera ativas.

---

### 5.4 ⚠️ Version mismatch: Agente 4.13 vs Manager 4.9

**Sintoma.** Com a rede corrigida, o agente alcançou o manager — e foi **rejeitado** com:

```
WARNING: Couldn't connect to server '127.0.0.1': 'Agent version must be lower or equal to manager version'
ERROR: Agent version must be lower or equal to manager version (from manager)
ERROR: Unable to add agent (from manager)
```

**Causa raiz.** Wazuh **não** aceita um agente mais novo que o manager. O ambiente tinha
**manager 4.9.2** (instalado na Fase 5) e **agente 4.13.0-rc5** (instalado na Fase 6).

**Correção.** Rebaixar o agente para **4.9.2** — `https://packages.wazuh.com/4.x/windows/wazuh-agent-4.9.2-1.msi`.

**A armadilha do rebaixamento via MSI.** A primeira tentativa de instalar o MSI 4.9.2 sobre o
4.13.0 **reportou sucesso** (`msiexec /i` → exit 0) e, ao mesmo tempo, **apagou os binários** do
4.13. O `RemoveExistingProducts` do instalador removes o produto anterior — e como os dois
produtos compartilham os mesmos componentes, o resultado final foi:

- produto registrado como **Wazuh Agent 4.9.2**;
- **sem** `wazuh-agent.exe`, `agent-auth.exe` ou `manage_agents.exe`;
- serviço `WazuhSvc` **inexistente**;
- `ossec.conf` e `client.keys` **presentes** (restaurados pelo script).

**Diagnóstico correto.** `oci`/registry mostrava o produto instalado e o evento MsiInstaller
confirmava *"Installation completed successfully"* — um estado **inconsistente**: instalado sem
executáveis. Só o `Get-ChildItem` no diretório de instalação revelou a ausência.

**Procedimento robusto de rebaixamento** (o que funcionou):

```powershell
# 1. Remover o produto registrado (não só os arquivos)
$prod = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
                          'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' |
         Where-Object { $_.DisplayName -like '*Wazuh Agent*' }
foreach ($p in $prod) {
  Start-Process msiexec.exe -ArgumentList '/x', $p.PSChildName, '/qn', '/norestart' -Wait
}

# 2. Limpar o diretório órfão (ACLs do Wazuh bloqueiam o Remove-Item)
takeown /F 'C:\Program Files (x86)\ossec-agent' /R /D Y
icacls 'C:\Program Files (x86)\ossec-agent' /reset /T /C
icacls 'C:\Program Files (x86)\ossec-agent' /grant 'Administrators:(OI)(CI)F' /T /C
Remove-Item 'C:\Program Files (x86)\ossec-agent' -Recurse -Force

# 3. Instalar o 4.9.2 limpo
Start-Process msiexec.exe -Verb RunAs -Wait -ArgumentList @('/i', $msi, '/qn', '/norestart', ...)

# 4. RESTAURAR o client.keys do backup  → o agente mantém o ID 001, sem re-enrollment
Copy-Item $backup\client.keys 'C:\Program Files (x86)\ossec-agent\client.keys' -Force
```

**Lição.** *Preserve a identidade, não o binário.* O `client.keys` é o que o manager reconhece.
Com ele restaurado, o agente voltou como **`ID: 001, windows-endpoint`** — sem reemitir chave.

**Prevenção.** Validar a compatibilidade **antes** de instalar:

```bash
sudo /var/ossec/bin/wazuh-control info -v      # versão do manager
```

```powershell
(Get-Item 'C:\Program Files (x86)\ossec-agent\wazuh-agent.exe').VersionInfo.FileVersion
```

E, no pipeline, comparar automaticamente: `agent_version <= manager_version`.

---

### 5.5 ⚠️ TTL de 1 hora das sessões Bastion

**Sintoma.** O agente caía do manager **sem aviso**:

```
WazuhSvc            : Running
wazuh-agent (pid)   : ativo
ossec.log           : "Closing connection to server ([127.0.0.1]:1514/tcp)."   (a cada 60 s)
agent_control -lc   : ID: 001, windows-endpoint, Status: Never connected
```

**Causa raiz.** O Bastion é **session-scoped**, com `max-session-ttl-in-seconds = 3600`. **Não
existe túnel SSH persistente através dele**: quando a sessão expira, a conexão SSH é encerrada
pelo serviço.

**Frequência observada.** **4 expirações em ~4 h de trabalho** (00:21, 01:22, 02:38, 03:26 UTC).
Cada uma derrubou simultaneamente os túneis 22/1514/1515/443.

**Efeito mais perigoso: a falha é silenciosa.** Não existe alerta. O serviço reporta `Running`,
o processo existe, e o manager apenas registra `Never connected`. Um endpoint "saudável" pelo
`Get-Service` pode estar **completamente cego**.

**Agravante discovered.** Ao tentar **trocar** o túnel (matar o antigo e subir o novo com uma
sessão nova), o novo túnel **também** falhou — e a sessão nova estava com o destino correto:

```
ocid1.bastionsession...@host.bastion...: Permission denied (publickey).
```

O frontend SSH do Bastion **replica as sessões com atraso inconsistente** — de ~1 s a ~10 min
neste caso. Criar a sessão e, de imediato, conectar, **falha de forma intermitente**. A solução
prática foi **retry com backoff** até a conexão ser aceita.

**Correções mitigadoras:**

```powershell
# (a) Elevar o TTL — verificar o limite aceito pela OCI
oci --profile DEFAULT bastion bastion update --bastion-id <bastion-id> --max-session-ttl 86400

# (b) Renovação proativa com retry
for ($try=1; $try -le 12; $try++) {
  $p = Start-Process ssh.exe -ArgumentList $args -WindowStyle Hidden -PassThru
  Start-Sleep -Seconds 6
  if (-not $p.HasExited) { break }        # tunnel OK
  $p.Dispose(); Start-Sleep -Seconds 25   # backoff para a propagação do Bastion
}

# (c) Regra de detecção de perda de telemetria  ← AINDA NÃO IMPLEMENTADO
#     alerta quando o keepalive do agente 001 não chega por N minutos
```

**Correção estrutural.** Ver [`adr-001-persistent-agent-connectivity.md`](adr-001-persistent-agent-connectivity.md)
— proxy TCP persistente (`nginx stream`) ou VPN Site-to-Site.

**Lição.** *Modele a dependência de sessão no desenho, não na operação.* Um componente que
depende de um recurso com TTL curto precisa de **renovação automática** e de **detecção de
falha** — as duas coisas faltavam.

---

### 5.6 ⚠️ Acionar FIM e reiniciar o agente **sem** elevação no endpoint

Descoberto durante a restauração de 2026-11-03: **não é preciso ser administrador na máquina
do endpoint** para reiniciar o agente ou forçar uma varredura de integridade — desde que o
agente já esteja **conectado** ao manager. O manager emite o comando pelo canal de controle.

```bash
# Forçar varredura de integridade/rootcheck no agente (syscheck + rootcheck)
sudo /var/ossec/bin/agent_control -r -u 002
#   -> "Restarting Syscheck/Rootcheck on agent: 002"

# Reiniciar o AGENTE (re-lê o ossec.conf, re-registra diretórios realtime)
sudo /var/ossec/bin/agent_control -R -u 002
#   -> "Restarting agent: 002"
```

**Por que isso importa.** O caso real: após o recreate, `C:\SOC-Lab` **não existia** quando o
agente iniciou (01:08). O `ossec.conf` mandava monitorar a pasta, mas o agente só registra
diretórios **realtime que existem no momento do startup** — o log mostra:

```
01:35:10 wazuh-agent: INFO: (6003): Monitoring path: 'c:\soc-lab', with options
         'size | permissions | owner | group | mtime | inode | hash_md5 | hash_sha1 | hash_sha256 | attributes | realtime'.
```

Sem essa linha, o diretório **não** está sendo monitorado, e o FIM **nunca** dispara — sem
nenhum erro visível. O `agent_control -R` forçou o re-registro (a pasta já existia), e o FIM
voltou a funcionar imediatamente, gerando a regra `550` com o detalhe forense completo:

```
File 'c:\soc-lab\important.txt' modified
Mode: realtime
Changed attributes: size,mtime,md5,sha1,sha256
Size changed from '9' to '33'
Old sha256sum was: '12bd990b6a486df44720e5de8fe702469d614ee91fe9bf857ba59f3821de829b'
New sha256sum is : '07479119a488ca3f5492c96cb196a8ce2d015f4b48152c98ff42c872a996be39'
```

**Lição.** *"O agente só monitora o que já existe quando ele sobe."* Se um alvo de FIM for
criado depois do startup, o agente precisa ser reiniciado — e isso pode ser feito **remotamente,
a partir do manager, sem tocar na máquina**.

---

### 5.7 ⚠️ Bônus — armadilhas que custaram tempo e valem registro

| Armadilha | Sintoma | Correção |
|---|---|---|
| **`terraform.tfstate` travado** | `Get-Content` → *"o processo não pode acessar o arquivo"*; `terraform plan` → *"state lock"* | **Nunca** rodar dois comandos Terraform em paralelo. Verificar `Get-Process terraform` e o arquivo `.terraform.tfstate.lock.info` antes de qualquer operação |
| **⚠️ `destroy` em voo x `apply` concorrente** | O `apply` foi disparado enquanto um `destroy` ainda escrevia o state; a instância foi **terminada** e o IP privado **mudou** | Verificar `Get-Process terraform` **e** `terraform.tfstate.lock.info` **antes** de qualquer `apply`. Se houver lock, **aguardar** — nunca forçar |
| **⚠️ O IP privado muda no recreate** | O agente apontava para `10.30.2.49`; após o recreate a VM nasceu em **`10.30.2.40`** — o agent ficou cego sem erro | Nunca fixar o IP em configuração. Use o **`terraform output wazuh_private_ip`** ou um nome DNS. Ver §5.8 |
| **Script elevado com erro de sintaxe** | O script elevado **nunca executa** e **não cria o arquivo de saída** — silêncio total | Validar com `[Parser]::ParseFile()` **antes** de elevar (§4.4) |
| **Contagem de eventos com fuso errado** | `Get-WinEvent -FilterHashtable @{StartTime=$utc}` retorna **0** — falso negativo | `StartTime` é interpretado em **hora local**; usar `Get-Date` (local) ou consultar o manager, que é a fonte autoritativa |
| **BOM em JSON no PowerShell 5.1** | `Parameter 'security_rules' must be in JSON format` | `Out-File -Encoding UTF8` grava BOM; usar `[System.IO.File]::WriteAllText(..., UTF8Encoding($false))` |
| **CLI sem o grupo `boot-volume`** | `oci compute boot-volume` → *"No such command"* | Usar a API Compute via `oci raw-request --target-uri https://iaas.<region>.oci.oraclecloud.com/20160918/bootVolumes/<ocid> --http-method DELETE` |
| **`net use` com argumentos separados** | `A sintaxe deste comando é inválida` — **zero** tentativas de logon | `net use \\host\share <senha> /user:<usuario>` — `/user:` e o usuário são **um** argumento só |
| **`preserve_boot_volume = true`** | `terraform destroy` **preserva** o volume de 120 GB (e ele continua cobrando) | Apagar o volume manualmente (§5.2 do `final_review.md`) |
| **URL `/4.x/` do instalador** | `curl` → **HTTP 403** | Usar a série pinada: `https://packages.wazuh.com/4.9/wazuh-install.sh` |
| **Nome do arquivo de config do Sysmon** | `sysmon.xml` → **HTTP 404** | O arquivo do repo SwiftOnSecurity chama-se **`sysmonconfig-export.xml`** |
| **SSO via `-EncodedCommand` + `Invoke-Expression`** | `Invoke-Expression : não é possível converter 'System.Byte[]'…` | Decodificar para string: `[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($b64))` |

---

### 5.8 ⚠️ O IP privado da VM muda no recreate — e isso quebrou o agente

**O que aconteceu.** A recreação completa da infraestrutura (após um `terraform destroy` + `apply`)
produziu uma VM nova, com **novo OCID**, **nova sub-rede SIEM** e **novo IP privado**:

| | Antes | Depois |
|---|---|---|
| IP privado da VM | `10.30.2.49` | **`10.30.2.40`** |
| OCID da instância | `…antxeljr6brcn3qchqjyx64pet2rbj2qqcbi7tdbvnyiurbhnra2oyhfzsfq` | `…antxeljr6brcn3qcumhbt4gacdbv4vwfm37gwal3teru7islt6mendqaymxq` |
| OCID da sub-rede SIEM | `…aaaaaaaa4y44kpa5ikwjyd6a43wpz22x6mk2jrn6l5mxpvwmj2tzne7rs5ha` | `…aaaaaaaa3lnd3adatnzsrfunpje7ehfjyxah7hc5ja3sd35evkydixk7jdyq` |
| OCID do NSG do Wazuh | `…aaaaaaaak36lbcxeixrbmfswxg26czzgvbeqxfdkg7uv6eidrd2t6oyxp6qq` | `…aaaaaaa4pd5w67ris4l6mnohvos7lqofgcxjleevziwr6ohwnbicgh25l2q` |

**Por que isso importa mais do que parece.** O agente estava configurado com
`<address>127.0.0.1</address>` — e continuaria funcionando, **desde que os túneis do Bastion
apontassem para o IP novo**. Mas:

1. As **sessões do Bastion** apontavam para `10.30.2.49` — um endereço que **não existia mais**.
   As sessões antigas continuavam `ACTIVE` (o TTL ainda não expirava), mas o forward morria em
   silêncio: o sintoma era `curl` → `http=000` e `ssh` → *"banner exchange timeout"*.
2. O **manager novo** tem um `client.keys` **novo** — a chave do agente (`001`) **não existe mais**
   lá. O agente tem de ser **re-enrolado** (`agent-auth.exe` contra o `authd` novo).
3. O **firewall do host novo** voltou ao padrão da imagem: **só a porta 22 liberada**, todo o
   resto em `REJECT` (§5.2).

**Procedimento de restore derivado deste episódio:**

```powershell
# 1. Descobrir o IP NOVO — nunca assumir o anterior
$ip = (terraform output -raw wazuh_private_ip).Trim()

# 2. Recriar as sessões do Bastion apontando para o IP NOVO
#    (o JSON de target-resource-details precisa ser regerado com o novo endereço)

# 3. Rodar o instalador do Wazuh no host novo (§3.1)

# 4. Reaplicar o firewall do host (camada 3) — a imagem nova não tem as regras
ssh -p 2222 ubuntu@127.0.0.1 "sudo iptables -I INPUT 6 -p tcp -m state --state NEW -m tcp --dport 443  -s 10.30.1.253/32 -j ACCEPT; ..."

# 5. Re-enrolar o agente contra o authd novo
& 'C:\Program Files (x86)\ossec-agent\agent-auth.exe' -m 127.0.0.1 -A -P '<senha>' -u windows-endpoint

# 6. Reiniciar o serviço e validar
Restart-Service WazuhSvc
```

**Lição.** *Trate o IP como dado, não como constante.* Como o agente usa `127.0.0.1`, o IP do
manager aparece apenas na **fronteira** (sessões do Bastion) — mas essa fronteira **precisa** ser
parametrizada. Um `terraform output wazuh_private_ip` no meio do runbook, e **nunca** um IP
hard-coded em script, `.tfvars` ou documentação.

> **Correção estrutural recomendada:** expor a VM por um **nome DNS** estável (ex.:
> `soc-wazuh-01.siem.soclab.oraclevcn.com`, já disponível no `dns_label` da sub-rede) e usar
> esse nome nas sessões do Bastion — eliminaria esta classe inteira de falha.

---

## 6. Checklist de saída da implantação

```powershell
# 1. Agente ativo no manager
ssh -i $KEY -p 2222 ubuntu@127.0.0.1 "sudo /var/ossec/bin/agent_control -lc"
#    esperado: ID: 00X, Name: <agent-name>, Status: Active

# 2. Conexão de telemetria estabelecida
Get-NetTCPConnection -RemotePort 1514 | Where-Object { $_.State -eq 'Established' }

# 3. Dashboard acessível
curl.exe -k -s -o NUL -w "http=%{http_code}\n" "https://127.0.0.1:8443/app/login?"

# 4. Tríade de detecção comprovada
#    (executar as simulações SOC-001/002/003 e conferir as regras no manager)

# 5. Sem drift
terraform plan      # deve reportar "No changes"

# 6. Nada fora do IaC cobrando
oci --profile DEFAULT compute instance list --compartment-id $comp --all --output json |
  Select-Object -ExpandProperty data | Where-Object { $_.'display-name' -like 'SOC-*' } |
  Select-Object display-name, lifecycle-state
```

---

## 7. Referências

| Documento | Escopo |
|---|---|
| [`architecture.md`](architecture.md) | Arquitetura profunda — planos, topologia, Zero Trust, fluxo de dados |
| [`final_review.md`](final_review.md) | FinOps, teardown e recuperação |
| [`adr-001-persistent-agent-connectivity.md`](adr-001-persistent-agent-connectivity.md) | ADR — transporte persistente além do TTL do Bastion |
| [`phase2_design.md`](phase2_design.md) | Design de rede e segurança (com correções) |
| [`../investigations/SOC-001-002-003-Report.md`](../investigations/SOC-001-002-003-Report.md) | Relatório de investigação das 3 simulações |
