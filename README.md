# SOC Autonomous Lab

Plataforma SOC autocontida sobre a VCN OCI `SOC-VCN-01` (10.30.0.0/16, região `sa-saopaulo-1`):
uma VM **Wazuh all-in-one** privada, um endpoint **Windows 11** reportando por **OCI Bastion**,
telemetria de processo/rede/arquivo via **Sysmon**, e uma cadeia de detecção comprovada por
simulações de ataque controladas.

| | |
|---|---|
| **Wazuh manager** | `SOC-WAZUH-01` — 10.30.2.40 · v4.9.2 · sem IP público |
| **Endpoint** | `DESKTOP-0U2NKV7` — Windows 11 · Wazuh agent 4.9.2 · Sysmon 15.22 |
| **Acesso** | OCI Bastion `SOC-BASTION-01` (STANDARD, TTL 1 h) → port-forwarding 22/1514/1515/443 |
| **Custo estimado** | **≈ USD 89,70/mês** |
| **Terraform** | `oracle/oci ~> 7.0` · CLI ≥ 1.16 · state local (não versionado) |

---

## Architecture

```
                    Internet
                        │
            ┌───────────┴────────────┐
            │  SOC-IGW-01            │  10.30.1.0/24  (MGMT, pública)
            │  Bastion SOC-BASTION-01│  client CIDR 177.103.16.47/32
            └───────────┬────────────┘
                        │
   ══════════ VCN 10.30.0.0/16 ══════════
                        │
            ┌───────────┴────────────┐
            │  SOC-WAZUH-01 10.30.2.40│  10.30.2.0/24  (SIEM, privada)
            │  remoted:1514 authd:1515 │  dashboard:443  indexer:9200
            │  route default → SOC-NAT-01
            └─────────────────────────┘
```

**Zero Trust aplicado:** nenhuma superfície pública de serviço (o manager não tem IP público);
ingresso apenas via Bastion autenticado por chave; 3 camadas independentes de filtragem
(**NSG** → **security list** → **iptables** com política `REJECT`); separação entre o NSG de
gerência e o da workload; portas de administração (`9200`, `55000`) ausentes de toda regra.

**Telemetria do endpoint:** Sysmon 15.22 (config SwiftOnSecurity) + canais de evento do Windows
(Security, PowerShell/Operational 4104) + FIM em tempo real → `remoted` via `127.0.0.1:1514`
(túnel SSH) → gerenciador.

**Validação:** 3 simulações (força bruta, PowerShell ofuscado, modificação de arquivo)
produziram 24 alertas de ataque em 8 regras Wazuh distintas, com nível máximo 12.

---

## Repository layout

| Path | Conteúdo |
|---|---|
| `infrastructure/terraform/` | IaC da VCN, sub-redes, NSGs, security lists, NAT e a VM (`main.tf`, `variables.tf`, `outputs.tf`) |
| `infrastructure/inventory/` | Inventário de recursos descobertos |
| `wazuh/` | Configuração do manager, regras e enrolment de agentes |
| `endpoint/` | Instalação do agente Windows e configuração do Sysmon |
| `detections/` | Regras de detecção (Sigma, Elastic EQL/KQL, Splunk) |
| `elastic/` | Configuração, detection rules e integrações do Elastic |
| `network/` | Configuração de Suricata e Zeek |
| `simulations/` | Scripts de simulação de ataque (brute-force, powershell, network-scanning) |
| `investigations/` | Relatórios formais de investigação (`SOC-001-002-003-Report.md`) |
| `docs/` | `phase1_discovery.md` · `phase2_design.md` · `adr-001-persistent-agent-connectivity.md` · **`final_review.md`** |

---

## Costs and Teardown

### Running cost — ≈ USD 89.70/month

| Item | Spec | USD/month |
|---|---|---:|
| Compute | `VM.Standard.E4.Flex` · 4 OCPU · 16 GB | 83.00 |
| Block volume (active) | 120 GB · Balanced | 2.00 |
| NAT Gateway | `SOC-NAT-01` | ~1.83 |
| Bastion | `SOC-BASTION-01` | ~2.04 |
| Block volume (orphan, 50 GB) | from the first, terminated instance | ~0.83 |
| **Total** | | **≈ 89.70** |

Details, sources and caveats: [`docs/final_review.md`](docs/final_review.md) §3.

### ⚠️ `terraform destroy` does not stop the billing

Two resources are **not** tracked by Terraform and will keep charging:

| Resource | Why | Manual removal |
|---|---|---|
| **120 GB boot volume** | `preserve_boot_volume = true` → the volume is **preserved** (detached) when the instance is destroyed | §5.2 of the final review |
| **50 GB boot volume** | Belonged to the first instance; never entered the state | §5.2 of the final review |
| **Bastion `SOC-BASTION-01`** | Created out-of-band; the Terraform provider does not manage it. Destroying the VCN leaves it inoperante but still billing | §5.3 of the final review |

Residual after a bare `terraform destroy`: **≈ USD 4.87/month** (≈ 5.4 % of the total).

### Safe shutdown options

| Goal | Action | Residual | Recoverable |
|---|---|---:|---|
| **Pause between sessions** | `oci compute instance action --action stop` | ≈ USD 4.87/mo | **Fully** — volume keeps Wazuh, indexer, dashboard, iptables rules and `client.keys` |
| **Full teardown** | `terraform destroy` **+** delete both volumes **+** delete the Bastion | **USD 0.00** | Not without a snapshot |
| **Cheap mistake** | `terraform destroy` alone | ≈ USD 4.87/mo | Partially — Wazuh is lost (the next `apply` rebuilds from a clean image) |

> **Stopping the VM is the right lever to pause the lab.** Destroying the instance to "save money"
> destroys the Wazuh installation — always snapshot the boot volume first.

### Teardown order that works

```powershell
cd infrastructure\terraform

# 1. Export the evidence that cannot be regenerated, and back up the state file
Copy-Item .\terraform.tfstate "$env:USERPROFILE\Desktop\soc-lab-state-$(Get-Date -Format yyyyMMdd).json"

# 2. Delete the Bastion FIRST — the VCN delete can be rejected while the
#    Bastion still references it, and it keeps charging until removed.
oci --profile DEFAULT bastion bastion delete --bastion-id ocid1.bastion.oc1.sa-saopaulo-1.amaaaaaa6brcn3qa2gt5a2l345uxzqiiq2asvbpsm7g4fagebrz3ppmjawdq

# 3. Destroy the Terraform-managed infrastructure
terraform plan          # review first
terraform destroy

# 4. ⚠️ Delete the orphaned boot volumes MANUALLY (see final_review.md §5.2)
#    The 120 GB one survives because of preserve_boot_volume = true.
#    Identify volumes by OCID, never by display-name — both are named
#    "SOC-WAZUH-01 (Boot Volume)".

# 5. Clear the local state so a later apply does not target deleted resources
Remove-Item .\terraform.tfstate, .\terraform.tfstate.backup, .\soc.tfplan -ErrorAction SilentlyContinue
```

Exact CLI commands (both the standard `oci compute boot-volume delete` form and the
`oci raw-request` API fallback for OCI CLI builds that lack the `boot-volume` group) plus the
**Console** steps are in [`docs/final_review.md`](docs/final_review.md) §5.2.

### Recreating it later

```powershell
cd infrastructure\terraform
Copy-Item "$env:USERPROFILE\Desktop\soc-lab-state-<data>.json" .\terraform.tfstate
terraform plan && terraform apply
```

Then: recreate the Bastion (§6.2 of the final review), re-apply the manager's host iptables
rules (§6.3 — they live only on the volume, outside Terraform), re-install Wazuh or restore it
from a snapshot (§6.4), re-enrol the endpoint (§6.5) and rebuild the Bastion tunnels (§6.6).

---

## Known limitation

The agent's transport depends on OCI Bastion sessions with a **1-hour TTL**, so the endpoint goes
telemetry-dark silently when a session expires. The target state for production is a persistent
TCP proxy (`nginx stream`) or a Site-to-Site VPN — analysed in
[`docs/adr-001-persistent-agent-connectivity.md`](docs/adr-001-persistent-agent-connectivity.md).

---

## Documentation

| Document | Scope |
|---|---|
| [`docs/phase1_discovery.md`](docs/phase1_discovery.md) | Discovery of the pre-existing OCI estate |
| [`docs/phase2_design.md`](docs/phase2_design.md) | Network and security design (with Phase 9/10 corrections) |
| [`docs/adr-001-persistent-agent-connectivity.md`](docs/adr-001-persistent-agent-connectivity.md) | ADR — persistent agent transport beyond the Bastion TTL |
| [`docs/final_review.md`](docs/final_review.md) | **Architecture, FinOps, teardown and recovery** |
| [`investigations/SOC-001-002-003-Report.md`](investigations/SOC-001-002-003-Report.md) | Investigation report — brute force, obfuscated PowerShell, file tampering |

> ⚠️ `Senha Wazuh.txt` and the `*.pem` files in the repository root are **gitignored**, but should
> be migrated to a secret store or a local keystore.
