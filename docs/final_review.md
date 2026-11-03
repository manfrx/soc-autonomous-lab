# Revisão Final — SOC Autonomous Lab

| Campo | Valor |
|---|---|
| **Documento** | `docs/final_review.md` |
| **Data** | 2026-11-03 |
| **Escopo** | `soc-autonomous-lab` — VCN `SOC-VCN-01` (10.30.0.0/16), região `sa-saopaulo-1` |
| **Estado** | Lab em execução e validado. Fases 7 e 8 (Elastic/Suricata/Zeek) **não implantadas** — adiadas, sem custo associado. |
| **Terraform** | provider `oracle/oci ~> 7.0`, CLI `v1.16.6`, state `serial 46` — `plan` sem diferenças |
| **Documentos relacionados** | `docs/phase1_discovery.md` · `docs/phase2_design.md` · `docs/adr-001-persistent-agent-connectivity.md` · `investigations/SOC-001-002-003-Report.md` |

---

## 1. Sumário executivo

Plataforma SOC mínima porém **funcional de ponta a ponta**, sobre uma VCN OCI isolada e sem
exposição pública:

- **VM Wazuh all-in-one** `SOC-WAZUH-01` (10.30.2.40) — manager, indexer e dashboard, **sem IP público**.
- **Endpoint Windows 11** `DESKTOP-0U2NKV7` reportando via **OCI Bastion** (port-forwarding 1514/1515 e 443).
- **Telemetria de processo, rede e arquivo** via **Sysmon 15.22** (config SwiftOnSecurity), integrada ao canal de eventos do agente.
- **Cadeia de detecção comprovada**: 3 simulações (SOC-001/002/003) → **24 alertas** de ataque, **8 regras Wazuh** distintas, com nível máximo **12**.

**Custo do lab em execução: ≈ USD 89,70/mês.** Ressalva estrutural conhecida: o transporte do
agente depende de sessões do Bastion com **TTL de 1 h** (ver ADR-001).

**⚠️ Atenção — `terraform destroy` NÃO zera o custo.** Por `preserve_boot_volume = true` e por
recursos fora do state, sobram **≈ USD 4,87/mês** cobrando. Ver §4.3 e §5.

---

## 2. Arquitetura

### 2.1 Modelo Zero Trust aplicado

Aqui "Zero Trust" é invocado no sentido **operacional e verificável** — nenhuma comunicação entre
zonas de confiança é implícita; todo fluxo é explícito, autenticado e restrito à origem legítima.

| Princípio | Implementação | Evidência |
|---|---|---|
| **Nenhuma superfície pública de serviço** | `SOC-WAZUH-01` sem IP público; `prohibit_public_ip_on_vnic = true` na sub-rede SIEM | `oci_core_subnet.siem` no state |
| **Ingresso único e autenticado** | OCI Bastion é o **único** caminho de entrada; cada sessão exige chave SSH | `client-cidr-block-allow-list = 177.103.16.47/32` |
| **Restrição por origem** | NSG + security list restringem 22/443/1514/1515 a `10.30.1.0/24`; nada de `0.0.0.0/0` para SSH | `phase2_design.md` §3 (corrigido) |
| **Defesa em profundidade** | 3 camadas independentes: **NSG** (VCN) → **security list** (sub-rede) → **iptables** no host (padrão `REJECT`) | `iptables -S INPUT` no manager |
| **Separação de responsabilidades** | `SOC-NSG-MGMT-01` (bastion/admin) ≠ `SOC-NSG-WAZUH-01` (workload) | 2 NSGs no state |
| **Identidade de workload** | Agente registrado com chave pré-compartilhada; `IP: any` (sem pin de IP) | `001 windows-endpoint any 92d84918…` |
| **Mínimo privilégio** | Bastion STANDARD, TTL 1 h, máx. 20 sessões; admin do host via `ubuntu`+`sudo` | `oci bastion bastion get` |
| **Sem porta de administração no path do agente** | `9200` (indexer) e `55000` (API) **ausentes** de toda regra de ingress | `phase2_design.md` §3 |

**Limites honestos do modelo implementado:** o transporte ainda exige renovação manual (§2.6);
a credencial do agente é chave estática de longa duração, não mTLS por sessão; a porta `1515`
(authd) permanece aberta após o registro — deveria ser fechada; o endpoint é uma estação
doméstica **não gerenciada** (sem MDM, patching ou hardening corporativo).

### 2.2 Plano de dados do endpoint (Wazuh + Sysmon)

```
┌─ Endpoint Windows 11 ────────────────────────────────────────┐
│  DESKTOP-0U2NKV7 · 192.168.15.9 · NAT doméstico              │
│                                                              │
│  ┌───────────────┐   ┌────────────────────────────────────┐  │
│  │ Sysmon 15.22  │   │ Wazuh Agent 4.9.2 (WazuhSvc)      │  │
│  │ SwiftOnSec.   │   │  ossec-agentd → 127.0.0.1:1514    │  │
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
| Security | 4625 / 4738 | `60122` *Logon Failure* · `60110` *User account changed* |
| PowerShell/Operational | 4104 (script block) | `91809` *may be using Base64 decoding method* |
| Sysmon EID 1 | Process Create | `92057` *base64 encoded command* · `92004` · `92029` |
| Sysmon EID 3 | Network Connect | `92037` *net.exe connection to a remote resource* |
| Sysmon EID 11 | FileCreate | `92213` *Executable file dropped…* |
| Syscheck (FIM) | realtime | `550` *Integrity checksum changed* |

### 2.3 Topologia de rede

```
                      Internet
                          │
              ┌───────────┴────────────┐
              │  SOC-IGW-01            │  sub-rede MGMT (pública)
              │  Bastion SOC-BASTION-01│  client CIDR 177.103.16.47/32
              └───────────┬────────────┘
                          │  10.30.1.0/24
        ┌─────────────────┴──────────────────┐
        │  SOC-SL-MGMT-EMPTY / SOC-NSG-MGMT  │
        │  egress → 10.30.2.0/24 : 22,443,   │
        │                                 1514,1515
        └─────────────────┬──────────────────┘
                          │
        ══════ VCN 10.30.0.0/16 ══════
                          │
        ┌─────────────────┴──────────────────┐
        │  SOC-SL-SIEM-EMPTY / SOC-NSG-WAZUH │
        │  ingress ← 10.30.1.0/24 :          │
        │                        22,443,1514,1515│
        │  ┌────────────────────────────────┐  │
        │  │ SOC-WAZUH-01  10.30.2.40      │  │
        │  │  remoted :1514  authd :1515    │  │
        │  │  dashboard :443  indexer:9200 │  │
        │  │  route default → SOC-NAT-01    │  │
        │  └────────────────────────────────┘  │
        └────────────────────────────────────┘
```

### 2.4 Cadeia de detecção validada

2026-11-03, 02:01–02:04 UTC:

| Cenário | Ação | Alertas | Regras |
|---|---|---|---|
| SOC-001 | 7 logons de rede com senha incorreta contra `soc-test-user` | 12 | `60122` ×4 · `60110` ×1 · `92037` ×7 |
| SOC-002 | PowerShell `-EncodedCommand` → `cmd.exe` oculto + `Invoke-WebRequest` | 7 | `92057` ×2 · `91809` ×1 · `92004` ×2 · `92032` ×2 |
| SOC-003 | `echo hacked > C:\SOC-Lab\important.txt` | 5 | `550` ×3 · `92004` ×2 |

**24 alertas** atribuíveis ao ataque + 55 artefatos de atividade do analista (PAM/sudo/SSH),
separados na análise. Detalhe em `investigations/SOC-001-002-003-Report.md`.

### 2.5 Estado final verificado

| Item | Valor | Verificação |
|---|---|---|
| Agente | `001 windows-endpoint`, **Active** | `agent_control -lc` |
| Serviço | `WazuhSvc` Running / Automatic | `Get-Service` |
| Conectividade | TCP **Established** → `127.0.0.1:1514` | `Get-NetTCPConnection` |
| Dashboard | `http=200`, 94 649 bytes | `curl -k https://127.0.0.1:8443/app/login?` |
| Versões | Manager 4.9.2 · Agente 4.9.2 · Sysmon 15.22 | `wazuh-control info -v` |
| Terraform | `Plan: No changes` | `terraform plan` |
| NSG do Wazuh | 11 regras (6 ingress + 5 egress), sem duplicatas | `oci network nsg rules list` |

### 2.6 Ressalva estrutural conhecida

O canal do agente depende de sessão do Bastion com TTL de 1 h. Em ~4 h de trabalho a expiração foi
observada **3 vezes**, cada vez derrubando a telemetria **em silêncio** — o serviço reporta
`Running`, mas o agente aparece `Never connected` no manager, **sem alerta**. Análise completa,
as duas opções de resolução (proxy TCP persistente `nginx stream` vs. VPN Site-to-Site) e o plano
de migração em **`docs/adr-001-persistent-agent-connectivity.md`**.

---

## 3. FinOps — especificação real dos recursos

### 3.1 Recursos gerenciados pelo Terraform

Extraído de `infrastructure/terraform/terraform.tfstate` (`serial 46`).

> ⚠️ **Os OCIDs abaixo são da primeira construção e NÃO são estáveis.** Um `terraform destroy` +
> `apply` recria a instância, a sub-rede SIEM e o NSG com **novos OCIDs** e **novo IP privado** —
> o lab foi efetivamente recriado em **2026-11-03** com o IP `10.30.2.40`. Esta tabela é
> **referência histórica**; a **fonte de verdade** em tempo de execução é
> `terraform output` / `terraform state show`. Detalhes em `docs/architecture.md` §2.4.

| Recurso | Nome | Especificação real | OCID |
|---|---|---|---|
| VCN | `SOC-VCN-01` | CIDR `10.30.0.0/16` | `ocid1.vcn.oc1.sa-saopaulo-1.amaaaaaa6brcn3qaq4kzk5jb6r4fhecij26axttkui4g2girm5jrvs2nj6la` |
| Sub-rede MGMT | `SOC-SUBNET-MGMT-01` | `10.30.1.0/24`, pública, RT→IGW | `ocid1.subnet.oc1.sa-saopaulo-1.aaaaaaaa4nyc4rxtwd77zvadtjngqm55izk3fwdzqez6w2ne3vrd64vomq6a` |
| Sub-rede SIEM | `SOC-SUBNET-SIEM-01` | `10.30.2.0/24`, privada, RT→NAT, `prohibit_public_ip_on_vnic=true` | `ocid1.subnet.oc1.sa-saopaulo-1.aaaaaaaa4y44kpa5ikwjyd6a43wpz22x6mk2jrn6l5mxpvwmj2tzne7rs5ha` |
| Internet Gateway | `SOC-IGW-01` | habilitado | `ocid1.internetgateway.oc1.sa-saopaulo-1.aaaaaaaarzgpicixr2ckesekg56iveis3w2wvsopg7gxt2pjkkv5diz4koda` |
| NAT Gateway | `SOC-NAT-01` | 1 gateway | `ocid1.natgateway.oc1.sa-saopaulo-1.aaaaaaaaunaipf4nzgsnaziuybi3w5t6kzprud7iqkfbl6euxpsep3qhlvdq` |
| Default Security List | `SOC-DEFAULT-SL-DENY-ALL` | gerenciada e esvaziada | — |
| Security List MGMT | `SOC-SL-MGMT-EMPTY` | egress → `10.30.2.0/24` : 22, 443, 1514, 1515 | — |
| Security List SIEM | `SOC-SL-SIEM-EMPTY` | ingress ← `10.30.1.0/24` : 22, 443, 1514, 1515 · egress → `10.30.1.0/24` : 443, 1514, 1515 | — |
| NSG MGMT | `SOC-NSG-MGMT-01` | 1 ingress (22 do `/32` admin) + 6 egress | — |
| NSG WAZUH | `SOC-NSG-WAZUH-01` | **11 regras de segurança** (6 ingress + 5 egress) | — |
| Instância | `SOC-WAZUH-01` | `VM.Standard.E4.Flex` · **4 OCPU** · **16 GB RAM** · AD `YvZu:SA-SAOPAULO-1-AD-1` | `ocid1.instance.oc1.sa-saopaulo-1.antxeljr6brcn3qchqjyx64pet2rbj2qqcbi7tdbvnyiurbhnra2oyhfzsfq` |
| Boot volume (inline) | `SOC-WAZUH-01 (Boot Volume)` | **120 GB** · **Balanced (10 VPU/GB)** · ⚠️ **`preserve_boot_volume = true`** | `ocid1.bootvolume.oc1.sa-saopaulo-1.abtxeljrahvtqy32db2zepwehuvqgqutog7tk7kyctyuufknfpv7mjio6woq` |
| Route tables | `SOC-RT-MGMT-01`, `SOC-RT-SIEM-01` | `0.0.0.0/0` → IGW / → NAT | — |

**Recurso fora do Terraform (criado out-of-band):**

| Recurso | Especificação real | OCID |
|---|---|---|
| Bastion | `SOC-BASTION-01` · STANDARD · TTL 3600 s · máx. 20 sessões · client CIDR `177.103.16.47/32` | `ocid1.bastion.oc1.sa-saopaulo-1.amaaaaaa6brcn3qa2gt5a2l345uxzqiiq2asvbpsm7g4fagebrz3ppmjawdq` |

**Volume órfão (nunca entrou no state):**

| Volume | Tamanho | OCID |
|---|---|---|
| `SOC-WAZUH-01 (Boot Volume)` — da **1ª instância**, já terminada | 50 GB · Balanced (10 VPU/GB) | `ocid1.bootvolume.oc1.sa-saopaulo-1.abtxeljrvo4wgrkdlhf2xnhgzzkkef2tao6b6oske3mgecru2z5pj7ts573a` |

> ⚠️ Os dois volumes têm o **mesmo `display-name`**. Identificar **sempre por OCID**.

### 3.2 Custo mensal estimado

Base: 730 h/mês (24×7), PAYG on-demand, `sa-saopaulo-1`.

| Item | Especificação | Cálculo | USD/mês |
|---|---|---|---:|
| **Compute** | `VM.Standard.E4.Flex` · 4 OCPU · 16 GB | tarifa padrão OCI | **83,00** |
| **Block volume (ativo)** | 120 GB · Balanced | tarifa padrão OCI | **2,00** |
| **NAT Gateway** | `SOC-NAT-01` | ~USD 0,0025/h × 730 h | **1,83** |
| **Bastion** | `SOC-BASTION-01` | ~USD 0,0028/h × 730 h (+ session-hours desprezíveis) | **2,04** |
| | | **Subtotal (Terraform-managed)** | **88,87** |
| **Block volume órfão** | 50 GB · Balanced | pro-rata de 120 GB | **0,83** |
| | | **Total atribuível ao lab** | **≈ 89,70** |

**Não incluídos:** recursos legados pré-existentes da tenancy (`wkcyber-nat`, `wkcyber-igw`,
volumes e VMs anteriores — fora do escopo deste lab e fora do Terraform), OCI CLI local,
impostos, backups e o `Secure Access` da Opção C do ADR-001.

### 3.3 O que `terraform destroy` NÃO interrompe

`oci_core_instance.wazuh` está declarado com **`preserve_boot_volume = true`**. Um
`terraform destroy` **preserva o volume de 120 GB** (apenas o desliga) e **não emite nenhum
comando de delete** para o Bastion nem para o volume órfão de 50 GB — nenhum dos dois está no
state.

| Resíduo após `terraform destroy` | USD/mês |
|---|---:|
| Boot volume 120 GB (preservado, destacado) | 2,00 |
| Boot volume 50 GB (órfão, nunca no state) | 0,83 |
| Bastion `SOC-BASTION-01` (fora do Terraform) | 2,04 |
| **Resíduo total** | **4,87** |

**Isto é ≈ 5,4 % do custo do lab continuando a ser cobrado com a infra "destruída".** O §5
descreve o procedimento que zera esse valor.

### 3.4 Alavancas de controle de custo

| Alavanca | Residual | Impacto na recuperação |
|---|---:|---|
| **Stop da VM** | ≈ 4,87 USD/mês | **Total** — o volume com a instalação do Wazuh permanece intacto |
| **`terraform destroy` apenas** | ≈ 4,87 USD/mês | Parcial — Wazuh **perdido** (o `apply` recria a instância a partir da imagem limpa) |
| **Teardown completo** (§5) | **0,00 USD/mês** | Nenhum — requer snapshot antes (§6.4) |

> O **Stop da VM** é a alavanca correta para pausar o lab entre sessões de trabalho: o compute
> (USD 83,00) deixa de ser cobrado imediatamente e o volume de 120 GB preserva Wazuh + indexer +
> dashboard + regras de iptables + `client.keys`. **Nunca destruir a instância para economizar sem
> antes ter feito snapshot.**

---

## 4. O que `terraform destroy` faz — e o que ele NÃO faz

### 4.1 O que é destruído

| Recurso | Destruído pelo `terraform destroy`? |
|---|---|
| VCN `SOC-VCN-01` | ✅ sim |
| Sub-redes MGMT e SIEM | ✅ sim |
| Route tables (2) | ✅ sim |
| Default security list + 2 security lists customizadas | ✅ sim |
| NSGs (2) e as 11 regras de segurança | ✅ sim |
| Internet Gateway `SOC-IGW-01` | ✅ sim |
| NAT Gateway `SOC-NAT-01` | ✅ sim |
| Instância `SOC-WAZUH-01` | ✅ sim (o volume é **preservado**) |

### 4.2 ⚠️ O que NÃO é destruído

| Recurso | Motivo | Como eliminar |
|---|---|---|
| **Boot volume de 120 GB** | `preserve_boot_volume = true` → o Terraform **preserva** o volume ao destruir a instância | **Manual** — §5.2 |
| **Boot volume órfão de 50 GB** | Nunca entrou no state; o Terraform nem sabe que ele existe | **Manual** — §5.2 |
| **Bastion `SOC-BASTION-01`** | **Não está no state** — o provider OCI do Terraform não gerencia o recurso Bastion, que foi criado out-of-band | **Manual** — §5.3 |

### 4.3 O Bastion e a VCN

O Bastion é um **recurso regional do serviço OCI Bastion** que referencia a VCN e a sub-rede
alvo (`target-vcn-id` / `target-subnet-id`). Ele **não é gerenciado pelo Terraform** e, por isso,
o `terraform destroy` **não emite nenhum comando de delete para ele**.

Na prática, destruir a VCN **invalida o Bastion** — a sub-rede alvo deixa de existir e ele se torna
inoperante (não consegue mais encaminhar para lugar nenhum). **Mas um recurso inoperante ainda
consome `bastion-hour`**, e o Terraform **não o remove**. Ele permanece listado e cobrando até
que seja deletado explicitamente.

> **Consequência prática da ordem das operações:** a deleção da VCN pode ser **rejeitada** pelo
> OCI enquanto o Bastion ainda a referenciar. A ordem segura é **deletar o Bastion ANTES** de
> destruir a VCN. O §5.3 faz isso.

### 4.4 Preservar o que é irrecuperável

Antes de qualquer destroy:

1. **Exportar a evidência** que não pode ser regenerada: `investigations/`, `detections/`,
   `wazuh/` e os logs do manager. As *regras* são regeneráveis a partir do repo; os *alerts* do
   período de simulação **não são**.
2. **Copiar o state do Terraform para fora do repo** — o backend é **local**
   (`terraform.tfstate`, ignorado pelo Git). Sem ele, a recreate só é possível refazendo tudo à mão:
   ```powershell
   Copy-Item .\terraform.tfstate "$env:USERPROFILE\Desktop\soc-lab-state-$(Get-Date -Format yyyyMMdd).json"
   Copy-Item .\terraform.tfstate.backup "$env:USERPROFILE\Desktop\soc-lab-state-backup-$(Get-Date -Format yyyyMMdd).json"
   ```
3. **Snapshot do boot volume** se a recuperação com dados for desejada (§6.4).

---

## 5. Teardown — procedimento completo

> **Nenhum comando Terraform foi executado na geração deste documento.** Tudo abaixo é
> procedimento documentado, não operação realizada.

### 5.1 Decisão: pausar ou destruir

```
                Precisa do Wazuh de volta depois?
                          │
            ┌─────────────┴─────────────┐
            │ SIM                        │ NÃO
            ▼                           ▼
   ┌───────────────────┐     ┌────────────────────────┐
   │ Stop da VM        │     │ Teardown completo      │
   │ (≈ USD 4,87/mês)  │     │ (USD 0,00)             │
   │ §5.5              │     │ §5.2 → §5.3 → §5.4    │
   └───────────────────┘     └────────────────────────┘
```

### 5.2 Passo 1 — Destruir a infraestrutura e eliminar os volumes órfãos

```powershell
cd infrastructure\terraform

# 1a. Revisar ANTES de executar
terraform plan          # deve mostrar apenas destruições

# 1b. Destruir (VCN, subnets, route tables, SLs, NSGs, IGW, NAT gateway e a instância)
terraform destroy

# ⚠️ 1c. O boot volume de 120 GB PERMANECE (preserve_boot_volume = true).
#        O volume de 50 GB NUNCA foi gerenciado pelo Terraform.
#        Ambos precisam ser apagados manualmente.
```

#### Como apagar o volume órfão — OCI CLI

> O volume precisa estar **desconectado** de qualquer instância para ser apagado. Após o
> `terraform destroy` a instância já não existe e o volume de 120 GB fica **destacado**
> automaticamente.

**Forma padrão (CLI OCI com o grupo `compute boot-volume`):**

```powershell
# Volume de 120 GB — preservado pelo destroy
oci --profile DEFAULT compute boot-volume delete `
  --boot-volume-id ocid1.bootvolume.oc1.sa-saopaulo-1.abtxeljrahvtqy32db2zepwehuvqgqutog7tk7kyctyuufknfpv7mjio6woq `
  --force

# Volume órfão de 50 GB — da 1ª instância, nunca entrou no state
oci --profile DEFAULT compute boot-volume delete `
  --boot-volume-id ocid1.bootvolume.oc1.sa-saopaulo-1.abtxeljrvo4wgrkdlhf2xnhgzzkkef2tao6b6oske3mgecru2z5pj7ts573a `
  --force
```

**Forma alternativa — API Compute via `oci raw-request` (validada neste ambiente):**

> O OCI CLI **3.95.0** instalado nesta máquina expõe apenas `oci compute boot-volume-attachment`
> e `oci compute volume-attachment` — **não** possui o grupo `oci compute boot-volume`, e
> `oci bv volume` não cobre boot volumes. Nesses builds, o caminho que funciona é a API Compute
> direta:

```powershell
# Listar os volumes do lab (identificar por OCID, nunca por display-name)
$comp = 'ocid1.tenancy.oc1..aaaaaaaazux2rh4z6kzy7n3dasqvxh3amxi7h4weinrhqpfrawb5e7bv4jbq'
$r = oci --profile DEFAULT raw-request `
       --target-uri "https://iaas.sa-saopaulo-1.oci.oraclecloud.com/20160918/bootVolumes?compartmentId=$comp" `
       --http-method GET | ConvertFrom-Json
$r.data | Where-Object { $_.freeformTags -match 'soc-autonomous-lab' } |
         Select-Object displayName, sizeInGBs, vpusPerGB, lifecycleState, id

# Apagar cada volume órfão
oci --profile DEFAULT raw-request `
  --target-uri "https://iaas.sa-saopaulo-1.oci.oraclecloud.com/20160918/bootVolumes/ocid1.bootvolume.oc1.sa-saopaulo-1.abtxeljrahvtqy32db2zepwehuvqgqutog7tk7kyctyuufknfpv7mjio6woq" `
  --http-method DELETE

oci --profile DEFAULT raw-request `
  --target-uri "https://iaas.sa-saopaulo-1.oci.oraclecloud.com/20160918/bootVolumes/ocid1.bootvolume.oc1.sa-saopaulo-1.abtxeljrvo4wgrkdlhf2xnhgzzkkef2tao6b6oske3mgecru2z5pj7ts573a" `
  --http-method DELETE
```

> Use exatamente `sa-saopaulo-1` (região) nos dois segmentos da URI. Os OCIDs completos estão na
> tabela do §3.1 — **copie-os de lá** em vez de digitá-los.

#### Como apagar o volume órfão — Console

1. **Compute → Block Volumes** (menu lateral) ou **Compute → Storage → Block Volumes**.
2. Alternar o filtro de exibição para **All Compartments** / o compartment da tenancy.
3. Localizar os volumes com `display-name` = `SOC-WAZUH-01 (Boot Volume)`.
   **Verificar `sizeInGBs`**: são **120 GB** (ativo) e **50 GB** (órfão) — ambos com o mesmo nome.
   Confirme pelo **OCID** na aba de detalhes.
4. Se algum ainda estiver **attached**, ir em **Compute → Instances → SOC-WAZUH-01** →
   *Disconnect block volume*, ou usar a aba **Attached volumes** do próprio volume.
5. **More Actions → Delete** → confirmar *Delete permanent*. Uma confirmação adicional
   ("Are you sure you want to delete this resource?") pode aparecer.
6. Repetir para o segundo volume.

### 5.3 Passo 2 — Remover o Bastion (fora do state)

> **Faça isto ANTES de `terraform destroy`** — a VCN pode ter a deleção rejeitada enquanto o
> Bastion ainda a referenciar (§4.3).

```powershell
# Listar as sessões ativas antes (para documentar o histórico)
oci --profile DEFAULT bastion session list `
  --bastion-id ocid1.bastion.oc1.sa-saopaulo-1.amaaaaaa6brcn3qa2gt5a2l345uxzqiiq2asvbpsm7g4fagebrz3ppmjawdq `
  --all --output json

# Encerrar as sessões ativas
foreach ($sid in (oci --profile DEFAULT bastion session list `
    --bastion-id ocid1.bastion.oc1.sa-saopaulo-1.amaaaaaa6brcn3qa2gt5a2l345uxzqiiq2asvbpsm7g4fagebrz3ppmjawdq `
    --all --output json | ConvertFrom-Json).data | Where-Object { $_.'lifecycle-state' -eq 'ACTIVE' })) {
  oci --profile DEFAULT bastion session delete --session-id $sid.id --wait-for-state DELETED
}

# Deletar o Bastion — impede a rejeição do delete da VCN e encerra a cobrança de bastion-hour
oci --profile DEFAULT bastion bastion delete `
  --bastion-id ocid1.bastion.oc1.sa-saopaulo-1.amaaaaaa6brcn3qa2gt5a2l345uxzqiiq2asvbpsm7g4fagebrz3ppmjawdq
```

**Console:** *Security → Bastion → SOC-BASTION-01 → More Actions → Delete*.

### 5.4 Passo 3 — Limpar o state local e verificar

```powershell
Remove-Item .\terraform.tfstate, .\terraform.tfstate.backup, .\soc.tfplan, .\soc-drift.tfplan -ErrorAction SilentlyContinue
```

**Verificação de que nada está cobrando:**

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

# 3) Nenhum volume do lab (via API — ver §5.2)
# 4) Bastion removido (esperar 404)
oci --profile DEFAULT bastion bastion get `
  --bastion-id ocid1.bastion.oc1.sa-saopaulo-1.amaaaaaa6brcn3qa2gt5a2l345uxzqiiq2asvbpsm7g4fagebrz3ppmjawdq
```

**Critério de aceite:** os quatro retornos **vazios** (o item 4 deve retornar 404). A verificação
definitiva é o **Faturamento** (Billing → Cost Analysis) filtrado por `Project = soc-autonomous-lab`.

### 5.5 Alternativa — pausa segura (Stop da VM)

```powershell
# Parar a VM: o compute (USD 83,00/mês) deixa de ser cobrado imediatamente
oci --profile DEFAULT compute instance action `
  --instance-id ocid1.instance.oc1.sa-saopaulo-1.antxeljr6brcn3qchqjyx64pet2rbj2qqcbi7tdbvnyiurbhnra2oyhfzsfq `
  --action stop

# Encerrar as sessões do Bastion (evita session-hours)
foreach ($sid in (oci --profile DEFAULT bastion session list `
    --bastion-id ocid1.bastion.oc1.sa-saopaulo-1.amaaaaaa6brcn3qa2gt5a2l345uxzqiiq2asvbpsm7g4fagebrz3ppmjawdq `
    --all --output json | ConvertFrom-Json).data | Where-Object { $_.'lifecycle-state' -eq 'ACTIVE' })) {
  oci --profile DEFAULT bastion session delete --session-id $sid.id --wait-for-state DELETED
}

# Encerrar os túneis SSH locais
Get-CimInstance Win32_Process -Filter "Name='ssh.exe'" | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }
```

**Resultado:** compute = USD 0 · volume 120 GB = USD 2,00 · volume 50 GB = USD 0,83 ·
bastion = USD 2,04 → **≈ USD 4,87/mês**. Wazuh, indexer, dashboard, regras de iptables e
`client.keys` **intactos**.

---

## 6. Recuperação

### 6.1 Recriar a infraestrutura

```powershell
cd infrastructure\terraform
Copy-Item "$env:USERPROFILE\Desktop\soc-lab-state-<data>.json" .\terraform.tfstate

terraform plan      # revisar ANTES
terraform apply
```

O `apply` recria VCN, sub-redes, route tables, security lists (com as regras do Bastion já
codificadas), NSGs (incluindo `wazuh_bastion_ingress` para 443/1514/1515), IGW, NAT gateway e a
instância.

### 6.2 Recriar o Bastion (fora do Terraform)

```powershell
oci --profile DEFAULT bastion bastion create \
  --compartment-id ocid1.tenancy.oc1..aaaaaaaazux2rh4z6kzy7n3dasqvxh3amxi7h4weinrhqpfrawb5e7bv4jbq \
  --vcn-id ocid1.vcn.oc1.sa-saopaulo-1.amaaaaaa6brcn3qaq4kzk5jb6r4fhecij26axttkui4g2girm5jrvs2nj6la \
  --subnet-id ocid1.subnet.oc1.sa-saopaulo-1.aaaaaaaa4nyc4rxtwd77zvadtjngqm55izk3fwdzqez6w2ne3vrd64vomq6a \
  --target-compartment-id ocid1.tenancy.oc1..aaaaaaaazux2rh4z6kzy7n3dasqvxh3amxi7h4weinrhqpfrawb5e7bv4jbq \
  --client-cidr-block-allow-lists 177.103.16.47/32
```

> O `vcn-id` e o `subnet-id` **mudam** após o recreate — use os valores novos do `terraform output`
> / `terraform state show`.

### 6.3 Reaplicar as regras de host que não estão no Terraform

As regras de iptables do manager (permitir 443/1514/1515 a partir de `10.30.1.253/32`) vivem
**apenas no volume**, em `/etc/iptables/rules.v4`. Sobrevivem a um `stop`/`start`, mas **não** a
um destroy + apply com volume novo.

```bash
sudo iptables -I INPUT 6 -p tcp -m state --state NEW -m tcp --dport 443  -s 10.30.1.253/32 -j ACCEPT
sudo iptables -I INPUT 7 -p tcp -m state --state NEW -m tcp --dport 1514 -s 10.30.1.253/32 -j ACCEPT
sudo iptables -I INPUT 8 -p tcp -m state --state NEW -m tcp --dport 1515 -s 10.30.1.253/32 -j ACCEPT
sudo netfilter-persistent save
```

> **Lacuna de IaC recomendada:** mover estas três regras para `cloud-init`/`user_data` ou para um
> módulo de configuração no Terraform, para que a recuperação não dependa de passo manual.

### 6.4 Reconstruir o Wazuh (se o volume foi destruído)

O `apply` cria a instância a partir da **imagem Ubuntu 24.04 limpa** — Wazuh, indexer, dashboard e
`client.keys` **não voltam sozinhos**.

| Alternativa | Esforço | Resultado |
|---|---|---|
| **Snapshot do volume** antes do destroy | Baixo | `apply` → restaurar o snapshot como boot volume → Wazuh intacto |
| **Reinstalar do zero** | Alto | Reexecutar a instalação do Wazuh 4.9.2 + indexer + dashboard, reemitir `client.keys`, re-enrolar o endpoint |

Com snapshot, a restauração conceitual é: `apply` → instância criada com volume novo → destruir
o volume novo → **criar a instância a partir do snapshot** → religar `subnet_id` e `nsg_ids` do
VNIC aos recursos novos (que têm OCIDs diferentes após o recreate).

### 6.5 Re-enrolar o endpoint

```powershell
$conf = 'C:\Program Files (x86)\ossec-agent\ossec.conf'
# <server><address>10.30.2.40</address><port>1514</port>
# <enrollment><manager_address>10.30.2.40</manager_address><port>1515</port>

& 'C:\Program Files (x86)\ossec-agent\agent-auth.exe' -m 10.30.2.40 -A -u <agente> -P <senha-enrollment>
```

### 6.6 Reconstruir os túneis do Bastion

Para cada porta (22, 1514, 1515, 443): criar a sessão, esperar `ACTIVE`, iniciar o túnel.
Procedimento em `docs/adr-001-persistent-agent-connectivity.md` §3 e nas seções de Phase 9/10.

### 6.7 Riscos da recuperação

| Risco | Impacto | Mitigação |
|---|---|---|
| **State local sem backend remoto** | Perda do state = perda da capacidade de gerenciar o lab | Snapshot do `terraform.tfstate` fora do repo (§4.4); adotar backend remoto (S3 + DynamoDB) |
| **Bastion fora do Terraform** | `destroy` não o remove; `apply` não o recria | Automatizar a criação (§6.2) |
| **Regras de iptables fora do IaC** | Recuperação incompleta | `cloud-init` ou módulo de config (§6.3) |
| **OCIDs mudam após o recreate** | VNIC/NSG/subnet precisam ser religados | Usar `terraform output` / `terraform state show` após o `apply` |
| **Volume preservado × recriado** | Confusão entre o volume do `destroy` e o volume novo do `apply` | Identificar **sempre por OCID** (§5.2) |
| **Perda de telemetria histórica** | Alerts do período de simulação não são regeneráveis | Exportar `alerts.json` / `alerts.log` antes (§4.4) |

### 6.8 RTO / RPO esperados

| Cenário | RTO | RPO |
|---|---|---|
| Pausa (stop da VM) | ~2 min | 0 |
| Recreate da infra (sem dados) | ~30 min | Total (telemetria perdida) |
| Recreate **com** snapshot | ~45 min | Desde o último snapshot |
| Recreate com reinstall do Wazuh | ~4–6 h | Total |

---

## 7. Achados em aberto

1. **ADR-001 em aberto** — o transporte do agente depende de sessões de 1 h do Bastion (§2.6).
2. **Regras de iptables do manager fora do IaC** (§6.3).
3. **Bastion e volume órfão de 50 GB fora do Terraform** (§3.1).
4. **Manager Wazuh 4.9.2 é EOL** — o agente foi rebaixado de 4.13.0-rc5 para 4.9.2
   (`Agent version must be lower or equal to manager version`).
5. **Detecção de perda de telemetria inexistente** — a queda do canal é silenciosa; criar regra de
   "keepalive ausente" para o agente 001.
6. **Sem monitoramento do próprio lab** — nenhum alerta se a VM, o Bastion ou o agente pararem.
7. **Fases 7 e 8 adiadas** — Elastic, Suricata e Zeek têm diretórios no repo (`elastic/`,
   `network/`) mas **nenhum recurso implantado**; sem custo associado.
8. **Segredos no diretório raiz** — `Senha Wazuh.txt` e dois `.pem` estão presentes e **ignorados
   pelo Git**, mas convém migrá-los para um cofre de segredos.

---

*Fim da revisão final — `docs/final_review.md`, 2026-11-03.*
