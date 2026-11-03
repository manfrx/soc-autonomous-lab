# Revisão Final — SOC Autonomous Lab

| Campo | Valor |
|---|---|
| **Documento** | `docs/final_review.md` |
| **Data** | 2026-11-03 |
| **Escopo** | `soc-autonomous-lab` — VCN `SOC-VCN-01` (10.30.0.0/16), região `sa-saopaulo-1` |
| **Estado** | Lab em execução e validado. Fases 7 e 8 (Elastic/Suricata/Zeek) não executadas — adiadas. |
| **Estado do Terraform** | `serial 46` — `terraform plan` sem diferenças (configuração e infraestrutura em sincronia) |
| **Documentos relacionados** | `docs/phase1_discovery.md`, `docs/phase2_design.md`, `docs/adr-001-persistent-agent-connectivity.md`, `investigations/SOC-001-002-003-Report.md` |

---

## 1. Sumário executivo

O laboratório implementa uma plataforma SOC mínima, porém **funcional de ponta a ponta**, sobre
uma VCN OCI isolada e sem exposição pública:

- **Uma VM Wazuh all-in-one** (`SOC-WAZUH-01`, 10.30.2.49) com manager, indexer e dashboard,
  **sem IP público**.
- **Um endpoint Windows 11** (`DESKTOP-0U2NKV7`) reportando para o manager via
  **OCI Bastion** (port-forwarding 1514/1515 e 443).
- **Telemetria de processo, rede e arquivo** via **Sysmon 15.22** com configuração SwiftOnSecurity,
  integrada ao canal de eventos do agente Wazuh.
- **Cadeia de detecção comprovada**: 3 simulações de ataque (SOC-001/002/003) produziram
  **24 alertas** classified como ataque, com 8 regras Wazuh distintas, incluindo regra de
  nível 12 para execução de PowerShell codificada em base64.

Os objetivos de design foram cumpridos com uma ressalva estrutural já documentada em
**ADR-001**: o transporte do agente depende de sessões do Bastion com **TTL de 1 hora**, o que
impede conectividade persistente sem intervenção.

**Custo mensal estimado do lab em execução: ~USD 101,63** (BRL ~532). UmaDestruição
incompleta deixa **~USD 9,28/mês** de recursos residuais cobrando — ver §3.3.

---

## 2. Arquitetura

### 2.1 Zero Trust — como foi aplicado

O termo "Zero Trust" é invocado aqui no sentido **operacional e verificável** (não como rótulo):
nenhuma comunicação entre zone de confiança é implícita; cada fluxo é explícito, autenticado e
restringido à origem legítima.

| Princípio | Implementação | Evidência |
|---|---|---|
| **Nenhuma superfície pública de serviço** | `SOC-WAZUH-01` sem IP público; `prohibit_public_ip_on_vnic = true` na sub-rede SIEM | `terraform.tfstate` → `oci_core_subnet.siem` |
| **Ingresso único e autenticado** | OCI Bastion é o **único** caminho de entrada; cada sessão exige chave SSH (`ssh-ed25519`/`rsa`) | `client-cidr-block-allow-list = 177.103.16.47/32` |
| **Restrição por origem, não por sub-rede** | NSG + security list restringem 22/443/1514/1515 a `10.30.1.0/24`; nada de `0.0.0.0/0` para SSH | §3 de `phase2_design.md` (corrigido) |
| **Defesa em profundidade na rede** | 3 camadas independentes: **NSG** (VCN) → **security list** (sub-rede) → **iptables** no host (padrão `REJECT`) | `iptables -S INPUT` no manager |
| **Separação de responsabilidades** | NSG `SOC-NSG-MGMT-01` (bastion/admin) ≠ NSG `SOC-NSG-WAZUH-01` (workload) | 2 NSGs no state |
| **Identidade de workload, sem senha em trânsito** | Agente registrado com chave pré-compartilhada (`client.keys`); `IP: any` (sem pin de IP) | `001 windows-endpoint any 92d84918…` |
| **Mínimo privilégio operacional** | Bastion = STANDARD, sessão de 1 h, max 20 sessões; admin do host via `ubuntu`+`sudo` | `oci bastion bastion get` |
| **Nenhuma porta de administration no path do agente** | `9200` (indexer) e `55000` (API) **ausentes** de toda regra de ingress | §3 de `phase2_design.md` |

**Limites honestos do modelo implementado:**

- A **transporte** da telemetria ainda depende de renovação manual (§2.6 e ADR-001).
- A credencial do agente é uma **chave estática de longa duração**, não mTLS por sessão.
- A porta `1515` (authd/enrollment) permanece **aberta para o Bastion** após o registro — deveria
  ser removida do path após o registro do endpoint.
- O endpoint é uma **estação de trabalho doméstica não gerenciada** — não há MDM, patching ou
  hardening corporativo sobre ela.

### 2.2 Plano de dados do endpoint (Wazuh + Sysmon)

```
┌─ Endpoint Windows 11 ────────────────────────────────────────┐
│  DESKTOP-0U2NKV7 · 192.168.15.9 · NAT doméstico              │
│                                                              │
│  ┌───────────────┐   ┌────────────────────────────────────┐  │
│  │ Sysmon 15.22  │   │ Wazuh Agent 4.9.2 (WazuhSvc)      │  │
│  │ SwiftOnSecurity│   │  ossec-agentd → 127.0.0.1:1514    │  │
│  │  EID1 Create  │   │  logcollector → eventchannel       │  │
│  │  EID3 Connect │   │   · Application / Security / System│  │
│  │  EID11 File   │   │   · Microsoft-Windows-Sysmon/      │  │
│  │  EID13 Reg    │   │     Operational                    │  │
│  │  EID22 DNS    │   │   · Microsoft-Windows-PowerShell/ │  │
│  └───────┬───────┘   │     Operational (4104)             │  │
│          │           │  syscheck (FIM, realtime)          │  │
│          ▼           └──────────────┬─────────────────────┘  │
│  Microsoft-Windows-Sysmon/Operational                        │
└──────────────────────────────┬───────────────────────────────┘
                               │ TLS (AES), chave pré-compartilhada
                               ▼
```

**Fontes de telemetria efetivamente coletadas** (verificado no `ossec.log` do agente):

| Canal | Evento | Regra Wazuh resultante |
|---|---|---|
| Security | 4625 / 4738 | `60122` *Logon Failure*, `60110` *User account changed* |
| PowerShell/Operational | 4104 (script block) | `91809` *may be using Base64 decoding method* |
| Sysmon EID 1 | Process Create | `92057` *base64 encoded command*, `92004`, `92029` |
| Sysmon EID 3 | Network Connect | `92037` *net.exe connection to a remote resource* |
| Sysmon EID 11 | FileCreate | `92213` *Executable file dropped…* |
| Syscheck (FIM) | realtime | `550` *Integrity checksum changed* |

### 2.3 Topologia de rede

```
                      Internet
                          │
              ┌───────────┴────────────┐
              │  SOC-IGW-01            │   (sub-rede MGMT pública)
              │  Bastion SOC-BASTION-01│   client CIDR 177.103.16.47/32
              └───────────┬────────────┘
                          │  10.30.1.0/24
        ┌─────────────────┴──────────────────┐
        │  SOC-SL-MGMT-EMPTY / NSG-MGMT      │
        │  egress → 10.30.2.0/24 : 22,443,  │
        │                                 1514,1515
        └─────────────────┬──────────────────┘
                          │
        ══════ VCN 10.30.0.0/16 ══════
                          │
        ┌─────────────────┴──────────────────┐
        │  SOC-SL-SIEM-EMPTY / NSG-WAZUH      │
        │  ingress ← 10.30.1.0/24 :           │
        │                        22,443,1514,1515│
        │  ┌────────────────────────────────┐  │
        │  │ SOC-WAZUH-01  10.30.2.49      │  │
        │  │  remoted :1514  authd :1515    │  │
        │  │  dashboard :443  indexer:9200 │  │
        │  │  route default → SOC-NAT-01    │  │
        │  └────────────────────────────────┘  │
        └────────────────────────────────────┘
```

### 2.4 Cadeia de detecção validada

O pipeline completo foi exercitado com 3 simulações controladas em 2026-11-03 (02:01–02:04 UTC):

| Cenário | Ação | Alertas | Regras |
|---|---|---|---|
| SOC-001 | 7 logons de rede com senha incorreta contra `soc-test-user` | 12 | `60122` ×4, `60110` ×1, `92037` ×7 |
| SOC-002 | PowerShell `-EncodedCommand` → `cmd.exe` oculto + `Invoke-WebRequest` | 7 | `92057` ×2, `91809` ×1, `92004` ×2, `92032` ×2 |
| SOC-003 | `echo hacked > C:\SOC-Lab\important.txt` | 5 | `550` ×3, `92004` ×2 |

**24 alertas** atribuíveis ao ataque + 55 artefatos de atividade do analista (PAM/sudo/SSH),
separados na análise. Detalhe completo em `investigations/SOC-001-002-003-Report.md`.

### 2.5 Estado final verificado

| Item | Valor | Verificação |
|---|---|---|
| Agente | `001 windows-endpoint`, **Active** | `agent_control -lc` |
| Serviço | `WazuhSvc` Running / Automatic | `Get-Service` |
| Conectividade | TCP **Established** → `127.0.0.1:1514` | `Get-NetTCPConnection` |
| Dashboard | `http=200`, 94 649 bytes | `curl -k https://127.0.0.1:8443/app/login?` |
| Versões | Manager 4.9.2 · Agente 4.9.2 · Sysmon 15.22 | `wazuh-control info -v` |
| Terraform | `Plan: No changes` | `terraform plan` |
| NSG | 11 regras (6 ingress + 5 egress), sem duplicatas | `oci network nsg rules list` |

### 2.6 Ressalva estrutural conhecida

O canal do agente depende de sessão do Bastion com TTL de 1 h. Em ~4 h de trabalho a expiração
foi observada **3 vezes**, cada vez derrubando a telemetria **em silêncio** (o serviço reporta
`Running`, mas o agente aparece `Never connected` no manager, sem alerta). A análise completa,
as duas opções de resolução (proxy TCP persistente `nginx stream` vs. VPN Site-to-Site) e o
plano de migração estão em **`docs/adr-001-persistent-agent-connectivity.md`**.

---

## 3. FinOps

### 3.1 Custo mensal do lab em execução

Base de cálculo: 730 h/mês (24×7), PAYG on-demand, região `sa-saopaulo-1`.

| Recurso | Especificação | Tarifa unitária | Mensal (USD) | Mensal (BRL) |
|---|---|---|---:|---:|
| **Compute** | `VM.Standard.E4.Flex`, 4 OCPU, 16 GB | ≈ 0,1240/h | **90,52** | 473,94 |
| **Boot volume (ativo)** | 120 GB, Balanced (10 VPU/GB) | 0,0426/GB·mês | **5,11** | 26,82 |
| **NAT Gateway** | `SOC-NAT-01` | 0,0025/h | **1,83** | 9,58 |
| **Bastion (STANDARD)** | `SOC-BASTION-01` | 0,0028/h bastion + 0,0028/h·sessão | **2,04** (+~0,03) | 10,68 |
| | | **Subtotal (Terraform-managed)** | **99,50** | **521,02** |
| **Boot volume órfão** ⚠ | 50 GB, Balanced — 1ª instância, já terminada | 0,0426/GB·mês | **2,13** | 11,13 |
| | | **Total atribuível ao lab** | **101,63** | **532,15** |

Cotação BRL a **5,2356 USD/BRL**, a mesma taxa usada em `phase2_design.md` §6 (indicativa, não
cotação de mercado).

**Não incluídos:** recursos legados pré-existentes da tenancy (`wkcyber-nat`, `wkcyber-igw`,
volumes e VMs de不爱 anteriores — fora do escopo deste lab e fora do Terraform), ICLI local,
impostos, backups e o custo do `Secure Access` da Opção C do ADR-001.

### 3.2 Recursos fora do Terraform

Este é o ponto de maior risco de custo, porque `terraform destroy` **não os toca**:

| Recurso | OCID | Motivo de estar fora do Terraform | Custo residual |
|---|---|---|---|
| Bastion `SOC-BASTION-01` | `ocid1.bastion.oc1.sa-saopaulo-1.amaaaaaa6brcn3qa2gt5a2l345uxzqiiq2asvbpsm7g4fagebrz3ppmjawdq` | Criado **out-of-band**; o provider OCI não expõe o recurso Bastion no `main.tf` | ~USD 2,04/mês |
| Boot volume 50 GB | `ocid1.bootvolume.oc1.sa-saopaulo-1.abtxeljrvo4wgrkdlhf2xnhgzzkkef2tao6b6oske3mgecru2z5pj7ts573a` | Volume da **1ª instância** (terminada em 2026-11-02T14:06); nunca entrou no state | USD 2,13/mês |

O volume de 50 GB é particularly enganoso: tem o **mesmo `display-name`** do volume ativo
(`SOC-WAZUH-01 (Boot Volume)`), então uma verificação manual por nome podedestroy o volume errado.
**Identificar sempre por OCID.**

### 3.3 O que `terraform destroy` NÃO interrompe

`oci_core_instance.wazuh` está declarado com `preserve_boot_volume = true`. Portanto, um
`terraform destroy` **preserva o volume de 120 GB** (apenas o desliga) e **não toca** nos dois
recursos da §3.2:

| Resíduo após `terraform destroy` | USD/mês |
|---|---:|
| Boot volume 120 GB (preservado, destacado) | 5,11 |
| Boot volume 50 GB (órfão, nunca no state) | 2,13 |
| Bastion `SOC-BASTION-01` (fora do Terraform) | 2,04 |
| **Resíduo total** | **9,28** |

**Isto é ~9 % do custo do lab continuando a ser cobrado com a infra "destruída".** O §4.4
descreve o procedimento que zera esse valor.

### 3.4 Alavancas de controle de custo

| Alavanca | Custo residual | Impacto na capacidade de recuperação |
|---|---:|---|
| **Stop da VM** (`oci compute instance action --action stop`) | ~USD 7,28/mês (volumes + bastion) | **Total** — o volume com a instalação do Wazuh permanece intacto |
| **Stop da VM + delete do Bastion** | ~USD 7,24/mês | Total |
| **`terraform destroy` apenas** | ~USD 9,28/mês | Parcial — Wazuh **perdido** (volume preservado, mas a instância é recriada do zero na próxima `apply`) |
| **Teardown completo** (§4.4) | **USD 0,00** | **Nenhum** — requer snapshot antes (§4.6) |

> O **Stop da VM é a alavanca correta** para pausar um lab entre sessões de trabalho: o compute
> (USD 90,52) deixa de ser cobrado imediatamente, e o volume de 120 GB preserva
> Wazuh + indexer + dashboard + regras de iptables. Nunca destruir a instância para "economizar"
> sem antes ter feito snapshot.

### 3.5 Procedência das tarifas e ressalvas

| Item | Fonte | Confiança |
|---|---|---|
| Compute E4 Flex 4 OCPU/16 GB = **USD 90,52/mês** | `phase2_design.md` §6 — *Oracle public PAYG list rates*, obtido em 2026-11-02 | **Alta** — reaproveitado do mesmo projeto |
| Boot volume Balanced 10 VPU/GB = **0,0426/GB·mês** | Derivado do mesmo conjunto de tarifas (50 GB → USD 2,13 ÷ 50 = 0,0426) | **Alta** — a aritmética fecha exatamente |
| NAT Gateway = **0,0025/h** | Tarifa pública da OCI | **Média** |
| Bastion = **0,0028/h** bastion + **0,0028/h·sessão** | Tarifa pública da OCI | **Média** |

> ⚠️ **As tarifas de NAT Gateway e Bastion não puderam ser reconfirmadas contra a price list
> pública da Oracle durante esta sessão** — `oracle.com/cloud/networking/pricing/` retornou
> HTTP 403 e a API `apexapps.oracle.com/pls/apex/cetools/api/v1/products` retornou HTTP 400.
> Os valores acima refletem as tarifas de listagem conhecidas e Impactam o total em menos de
> USD 4/mês, mas **devem ser reconfirmados antes de usar este documento para orçamento**.

---

## 4. Teardown e Recuperação

> **Nenhum comando Terraform foi executado na geração deste documento.** Tudo abaixo é
> procedimento documentado, não operação realizada.

### 4.1 Decisão: pausar ou destruir

```
                    Precisa do Wazuh de volta depois?
                              │
                ┌─────────────┴─────────────┐
                │ SIM                        │ NÃO
                ▼                           ▼
      ┌───────────────────┐      ┌────────────────────────┐
      │ Stop da VM        │      │ Teardown completo      │
      │ (USD 7,28/mês)    │      │ (USD 0,00)             │
      │ §4.3              │      │ §4.4                   │
      └───────────────────┘      └────────────────────────┘
```

### 4.2 Pré-condições (obrigatórias antes de qualquer destroy)

1. **Preservar o estado do Terraform.** O backend é **local** (`terraform.tfstate`, ignorado pelo
   Git). Sem ele, a recreate só é possível recriando tudo à mão. Copie para fora do repo:
   ```powershell
   Copy-Item .\terraform.tfstate "$env:USERPROFILE\Desktop\soc-lab-state-$(Get-Date -Format yyyyMMdd).json"
   Copy-Item .\terraform.tfstate.backup "$env:USERPROFILE\Desktop\soc-lab-state-backup-$(Get-Date -Format yyyyMMdd).json"
   ```
2. **Exportar a evidência** que não pode ser regenerada: `investigations/`, `detections/`,
   `wazuh/` e os logs do manager. As regras Wazuh e as detecções **são** regeneráveis a partir
   do repo; os **alerts** do período de simulação não são.
3. **Snapshot do boot volume** (se a recuperação com dados for desejada — §4.6).
4. Confirmar que `terraform plan` está limpo, para que o destroy não apague nada inesperado.

### 4.3 Procedimento A — pausa segura (recomendado para interromper o trabalho)

```powershell
# 1. Parar a VM — o compute (USD 90,52/mês) deixa de ser cobrado
oci --profile DEFAULT compute instance action `
  --instance-id ocid1.instance.oc1.sa-saopaulo-1.antxeljr6brcn3qchqjyx64pet2rbj2qqcbi7tdbvnyiurbhnra2oyhfzsfq `
  --action stop

# 2. (opcional) Encerrar as sessões do Bastion para não consumir session-hours
foreach ($sid in (oci --profile DEFAULT bastion session list `
    --bastion-id ocid1.bastion.oc1.sa-saopaulo-1.amaaaaaa6brcn3qa2gt5a2l345uxzqiiq2asvbpsm7g4fagebrz3ppmjawdq `
    --all --output json | ConvertFrom-Json).data | Where-Object { $_.'lifecycle-state' -eq 'ACTIVE' })) {
  oci --profile DEFAULT bastion session delete --session-id $sid.id --wait-for-state DELETED
}

# 3. Encerrar os túneis SSH locais
Get-CimInstance Win32_Process -Filter "Name='ssh.exe'" | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }
```

**Resultado:** compute = USD 0 · boot volume 120 GB = USD 5,11 · volume 50 GB = USD 2,13 ·
bastion = USD 2,04 → **≈ USD 7,28/mês**. Wazuh, indexer, dashboard, regras de iptables e
`client.keys` **intactos**.

### 4.4 Procedimento B — teardown completo (USD 0,00)

> ⚠️ **A ordem importa.** O `terraform destroy` vai remover a VCN e, com ela, as sub-redes. O
> Bastion e os volumes precisam ser tratados **antes** ou **depois** de forma explícita, porque
> não estão no state.

**Passo 1 — Snapshot do boot volume (opcional mas recomendado)**

```powershell
oci --profile DEFAULT compute volume snapshot create  # ver §4.6 para o comando equivalente
```

**Passo 2 — Destroy da infraestrutura Terraform**

```powershell
cd infrastructure\terraform
terraform plan        # deve mostrar apenas destruições — CONFIRME antes de seguir
terraform destroy     # remove VCN, subnets, route tables, SLs, NSGs, IGW, NAT gateway e a instância
```

**Passo 3 — Remover os volumes (fora do Terraform)**

> `preserve_boot_volume = true` deixa o volume de 120 GB **destacado, mas existente**.
> Identifique-os **por OCID**, nunca por `display-name` (ambos se chamam
> `SOC-WAZUH-01 (Boot Volume)`).

```powershell
# Volume ativo de 120 GB (preservado pelo destroy)
oci --profile DEFAULT compute boot-volume delete `
  --boot-volume-id ocid1.bootvolume.oc1.sa-saopaulo-1.abtxeljrahvtqy32db2zepwehuvqgqutog7tk7kyctyuufknfpv7mjio6woq

# Volume órfão de 50 GB (nunca entrou no state)
oci --profile DEFAULT compute boot-volume delete `
  --boot-volume-id ocid1.bootvolume.oc1.sa-saopaulo-1.abtxeljrvo4wgrkdlhf2xnhgzzkkef2tao6b6oske3mgecru2z5pj7ts573a
```

**Passo 4 — Remover o Bastion (fora do Terraform)**

```powershell
oci --profile DEFAULT bastion bastion delete `
  --bastion-id ocid1.bastion.oc1.sa-saopaulo-1.amaaaaaa6brcn3qa2gt5a2l345uxzqiiq2asvbpsm7g4fagebrz3ppmjawdq
```

**Passo 5 — Limpar o state local** (para que um `apply` posterior não tente gerenciar recursos
inexistentes)

```powershell
Remove-Item .\terraform.tfstate, .\terraform.tfstate.backup, .\soc.tfplan, .\soc-drift.tfplan -ErrorAction SilentlyContinue
```

**Passo 6 — Verificar que nada está cobrando** (§4.5)

### 4.5 Verificação de que nada está cobrando

```powershell
$comp = 'ocid1.tenancy.oc1..aaaaaaaazux2rh4z6kzy7n3dasqvxh3amxi7h4weinrhqpfrawb5e7bv4jbq'

# 1) Nenhuma instância RUNNING do lab
oci --profile DEFAULT compute instance list --compartment-id $comp --all --output json |
  ConvertFrom-Json | ForEach-Object { $_.data } |
  Where-Object { $_.'display-name' -eq 'SOC-WAZUH-01' -and $_.'lifecycle-state' -eq 'RUNNING' }

# 2) Nenhum NAT gateway do lab
oci --profile DEFAULT network nat-gateway list --compartment-id $comp --all --output json |
  ConvertFrom-Json | ForEach-Object { $_.data } |
  Where-Object { $_.'display-name' -eq 'SOC-NAT-01' }

# 3) Nenhum volume do lab
#    (via API — ver §5)

# 4) Bastion removido
oci --profile DEFAULT bastion bastion get `
  --bastion-id ocid1.bastion.oc1.sa-saopaulo-1.amaaaaaa6brcn3qa2gt5a2l345uxzqiiq2asvbpsm7g4fagebrz3ppmjawdq
```

Critério de aceite: **todos os quatro retornos vazios** (o item 4 deve retornar 404).
A verificação final de fato deve ser o **Faturamento** (Billing → Cost Analysis), filtrado por
`Project = soc-autonomous-lab`.

### 4.6 Recuperação

#### 4.6.1 Recriar a infraestrutura (a partir do zero)

```powershell
cd infrastructure\terraform

# 1. state e variáveis
Copy-Item "$env:USERPROFILE\Desktop\soc-lab-state-<data>.json" .\terraform.tfstate
Copy-Item "$env:USERPROFILE\Desktop\soc-lab-state-<data>.json" .\terraform.tfstate
#    (ou, partindo do zero: terraform init e um terraform.tfvars completo)

# 2. planejar e revisar ANTES de aplicar
terraform plan
terraform apply
```

O `apply` recria VCN, sub-redes, route tables, security lists (com as regras do Bastion já
codificadas — §3 de `phase2_design.md`), NSGs (incluindo
`wazuh_bastion_ingress` para 443/1514/1515), IGW, NAT gateway e a instância.

#### 4.6.2 Recriar o Bastion (não está no Terraform)

```powershell
oci --profile DEFAULT bastion bastion create \
  --compartment-id ocid1.tenancy.oc1..aaaaaaaazux2rh4z6kzy7n3dasqvxh3amxi7h4weinrhqpfrawb5e7bv4jbq \
  --vcn-id ocid1.vcn.oc1.sa-saopaulo-1.amaaaaaa6brcn3qaq4kzk5jb6r4fhecij26axttkui4g2girm5jrvs2nj6la \
  --subnet-id ocid1.subnet.oc1.sa-saopaulo-1.aaaaaaaa4nyc4rxtwd77zvadtjngqm55izk3fwdzqez6w2ne3vrd64vomq6a \
  --target-compartment-id ocid1.tenancy.oc1..aaaaaaaazux2rh4z6kzy7n3dasqvxh3amxi7h4weinrhqpfrawb5e7bv4jbq \
  --client-cidr-block-allow-lists 177.103.16.47/32
```

#### 4.6.3 Reaplicar as regras de host que **não** estão no Terraform

As regras de iptables do manager (permitir 443/1514/1515 a partir de `10.30.1.253/32`) vivem
**apenas no volume**, em `/etc/iptables/rules.v4`. Elas sobrevivem a um `stop`/`start` da VM, mas
**não** a um destroy + apply com volume novo.

```bash
sudo iptables -I INPUT 6 -p tcp -m state --state NEW -m tcp --dport 443  -s 10.30.1.253/32 -j ACCEPT
sudo iptables -I INPUT 7 -p tcp -m state --state NEW -m tcp --dport 1514 -s 10.30.1.253/32 -j ACCEPT
sudo iptables -I INPUT 8 -p tcp -m state --state NEW -m tcp --dport 1515 -s 10.30.1.253/32 -j ACCEPT
sudo netfilter-persistent save
```

> **Lacuna de IaC recomendada:** mover estas três regras para um `user_data`/`cloud-init` ou para
> um módulo de configuração no Terraform, para que a recuperação não dependa de passo manual.

#### 4.6.4 Reinstalar o Wazuh (se o volume foi destruído)

O `apply` cria a instância a partir da **imagem Ubuntu 24.04 limpa** — o Wazuh, o indexer, o
dashboard e o `client.keys` **não** voltam sozinhos. Duas alternativas:

| Alternativa | Esforço | Resultado |
|---|---|---|
| **Snapshot do volume** antes do destroy | Baixo | `apply` → restaurar o snapshot como boot volume → Wazuh intacto |
| **Reinstalar do zero** | Alto | Reexecutar a instalação do Wazuh 4.9.2 + indexer + dashboard, reemitir `client.keys`, re-enrolar o endpoint |

Com o snapshot, a restauração conceitual é: `apply` →_instance criada com volume novo_ →
destruir o volume novo → **criar a instância a partir do snapshot** → reanexar os OCIDs de
subnet/NSG → confirmar que `nsg_ids` e `subnet_id` do VNIC apontam para os recursos novos
(que têm **OCIDs diferentes** após o recreate).

#### 4.6.5 Re-enrolar o endpoint

```powershell
# No endpoint, apontar o agente para o manager e re-registrar
$conf = 'C:\Program Files (x86)\ossec-agent\ossec.conf'
# <server><address>10.30.2.49</address><port>1514</port>
# <enrollment><manager_address>10.30.2.49</manager_address><port>1515</port>

# Registrar via authd (senha de enrollment do manager)
& 'C:\Program Files (x86)\ossec-agent\agent-auth.exe' -m 10.30.2.49 -A -u soc-test-user -P <senha>
```

#### 4.6.6 Reconstruir os túneis do Bastion

```powershell
# Para cada porta (22, 1514, 1515, 443): criar sessão, esperar ACTIVE, iniciar túnel
# Ver docs/adr-001-persistent-agent-connectivity.md §3 e as sessões em phase 9/10
```

### 4.7 Riscos e limitações da recuperação

| Risco | Impacto | Mitigação |
|---|---|---|
| **State local sem backend remoto** | Perda do state = perda da capacidade de gerenciar o lab | Snapshot do `terraform.tfstate` fora do repo (§4.2); adotar backend remoto (S3 + DynamoDB) |
| **Bastion fora do Terraform** | `destroy` não o remove; `apply` não o recria | Automatizar a criação (§4.6.2) ou incluir no code review |
| **Regras de iptables fora do IaC** | Recuperação incompleta | `cloud-init` ou módulo de config (§4.6.3) |
| **OCIDs mudam após o recreate** | VNIC/NSG/subnet precisam ser religados manualmente | Registrar os OCIDs do §5 e mapear os novos após o `apply` |
| **Volume preservado x. recriado** | Confusão entre "volume do destroy" e "volume novo do apply" | Identificar **sempre por OCID**, nunca por `display-name` (§3.2) |
| **Perda de telemetria histórica** | Alertas do período de simulação não são regeneráveis | Exportar `alerts.json` / `alerts.log` antes (§4.2) |

### 4.8 RTO / RPO esperados

| Cenário | RTO | RPO |
|---|---|---|
| Pausa (stop da VM) | ~2 min | 0 |
| Recreate completo da infra (sem dados) | ~30 min | Total (telemetria perdida) |
| Recreate **com** snapshot | ~45 min | Desde o último snapshot |
| Recreate com reinstall do Wazuh | ~4–6 h | Total |

---

## 5. Inventário de referência (OCIDs)

Recursos do lab na tenancy `ocid1.tenancy.oc1..aaaaaaaazux2rh4z6kzy7n3dasqvxh3amxi7h4weinrhqpfrawb5e7bv4jbq`.

| Recurso | OCID | Terraform? |
|---|---|---|
| VCN `SOC-VCN-01` | `ocid1.vcn.oc1.sa-saopaulo-1.amaaaaaa6brcn3qaq4kzk5jb6r4fhecij26axttkui4g2girm5jrvs2nj6la` | ✅ |
| Sub-rede MGMT | `ocid1.subnet.oc1.sa-saopaulo-1.aaaaaaaa4nyc4rxtwd77zvadtjngqm55izk3fwdzqez6w2ne3vrd64vomq6a` | ✅ |
| Sub-rede SIEM | `ocid1.subnet.oc1.sa-saopaulo-1.aaaaaaaa4y44kpa5ikwjyd6a43wpz22x6mk2jrn6l5mxpvwmj2tzne7rs5ha` | ✅ |
| NAT Gateway | `ocid1.natgateway.oc1.sa-saopaulo-1.aaaaaaaaunaipf4nzgsnaziuybi3w5t6kzprud7iqkfbl6euxpsep3qhlvdq` | ✅ |
| Internet Gateway | `ocid1.internetgateway.oc1.sa-saopaulo-1.aaaaaaaarzgpicixr2ckesekg56iveis3w2wvsopg7gxt2pjkkv5diz4koda` | ✅ |
| Instância `SOC-WAZUH-01` | `ocid1.instance.oc1.sa-saopaulo-1.antxeljr6brcn3qchqjyx64pet2rbj2qqcbi7tdbvnyiurbhnra2oyhfzsfq` | ✅ |
| Boot volume 120 GB (ativo) | `ocid1.bootvolume.oc1.sa-saopaulo-1.abtxeljrahvtqy32db2zepwehuvqgqutog7tk7kyctyuufknfpv7mjio6woq` | ⚠️ apenas via `source_details` |
| Boot volume 50 GB (órfão) | `ocid1.bootvolume.oc1.sa-saopaulo-1.abtxeljrvo4wgrkdlhf2xnhgzzkkef2tao6b6oske3mgecru2z5pj7ts573a` | ❌ não |
| Bastion `SOC-BASTION-01` | `ocid1.bastion.oc1.sa-saopaulo-1.amaaaaaa6brcn3qa2gt5a2l345uxzqiiq2asvbpsm7g4fagebrz3ppmjawdq` | ❌ não |

---

## 6. Achados em aberto (não bloqueiam o encerramento do lab)

1. **ADR-001 em aberto** — o transporte do agente depende de sessões de 1 h do Bastion; a
   existência de隧道 permanente continua pendente (§2.6).
2. **Regras de iptables do manager fora do IaC** (§4.6.3).
3. **Bastion e volume órfão fora do Terraform** (§3.2).
4. **Manager Wazuh 4.9.2 é EOL** — o agente teve de ser rebaixado de 4.13.0-rc5 para 4.9.2
   (`ERROR: Agent version must be lower or equal to manager version`). Planejar o upgrade
   manager → indexer → dashboard → agente.
5. **Detecção de perda de telemetria inexistente** — a queda do canal é silenciosa; criar regra
   de "keepalive ausente" para o agente 001.
6. **Sem monitoramento do próprio laboratório** — não há alerta se a VM, o Bastion ou o agente
   pararem. Um health check do próprio lab é o próximo incremento natural.
7. **Fases 7 e 8 adiadas** — Elastic, Suricata e Zeek têm diretórios no repo
   (`elastic/`, `network/`) mas **nenhum recurso foi implantado**; não há custo associado.
8. **Segredos no diretório raiz do repo** — `Senha Wazuh.txt` e dois arquivos `.pem` estão
   presentes e **ignorados pelo Git** (`.gitignore`), mas convém migrá-los para um cofre de
   segredos ou para um keystore local.

---

*Fim da revisão final — `docs/final_review.md`, 2026-11-03.*
