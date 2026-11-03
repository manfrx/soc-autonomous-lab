# Phase 1 — Discovery Report

**Report date:** 2026-11-02  
**Phase status:** Complete with explicitly documented unknowns.  
**Cloud changes performed by the agent:** None.

> **Post-Phase-1 amendment:** After this inventory was approved, the owner reported manually deleting `wkcyber-vm-17` through `wkcyber-vm-10` in the OCI Console. Those deletions were not performed by the agent. The reuse mapping below is retained as the historical Phase 1 record; the project subsequently changed to a greenfield design. The owner also reported installing Terraform v1.16.6.

## A. Local tool inventory

| Tool | Result at discovery | Findings |
|---|---|---|
| Node.js | Available | `v26.13.0` |
| npm | Available | `11.20.0` |
| Git | Not available | Not found on `PATH` |
| WSL2 | Installed but unusable | Virtualization/Virtual Machine Platform was not enabled; no distributions installed |
| OpenCode | Available | `v2.2.5` |
| Terraform | Not available at discovery | Not found on `PATH`; owner later reported installing v1.16.6 |
| OCI CLI | Available | `3.95.0` |
| DeepSeek Harness | Not found | No tested DSH command or alias found |
| Python | Available | Python 3.11 |

OpenCode exposes CLI, API/server, ACP, MCP and session mechanisms. Because DSH was absent, no DSH-to-OpenCode integration or delegation method was verified. No software was installed, upgraded or removed by the agent.

## B. OCI resource inventory

### Identity, tenancy and region

- Profile: `SOC_DISCOVERY`
- Identity: `soc-discovery-user`
- Group: `soc-discovery-group`
- The identity was not in `Administrators`.
- Region: `sa-saopaulo-1`
- Region key: `GRU`
- Home-region subscription: `READY`
- Availability domains returned: one, `YvZu:SA-SAOPAULO-1-AD-1`
- Child compartments returned: none; inventory was in the root compartment.

### Compute instances at the time of discovery

Twenty-one stopped instances were returned; no running instance was found.

| Shape | OCPU / RAM | Count | State |
|---|---:|---:|---|
| `VM.Standard.E4.Flex` | 2 / 16 GB | 17 | STOPPED |
| `VM.Standard.E4.Flex` | 1 / 16 GB | 1 | STOPPED |
| `VM.Standard.E4.Flex` | 2 / 12 GB | 1 | STOPPED |
| `VM.Standard.E5.Flex` | 1 / 12 GB | 1 | STOPPED |
| `VM.Standard.A1.Flex` | 2 / 12 GB | 1 | STOPPED |

The compute API returned blank display-name fields. Boot-volume inventory contained `wkcyber-vm-01` through `wkcyber-vm-17`, plus four other lab-related volumes. Exact instance-ID-to-boot-volume attachment mapping was initially incomplete and was not to be assumed from names alone.

### Storage at the time of discovery

| Resource | Findings |
|---|---|
| Boot volumes | 21 |
| Size | 47 GB each |
| Total boot-volume capacity | 987 GB |
| Performance | 10 VPUs/GB |
| State | AVAILABLE |
| Additional block volumes | None returned |
| Block-volume backups | None returned |
| Boot-volume backups | One: `splunklab-backup01`, FULL, 200 GB, AVAILABLE |

All storage resources were pre-existing and outside the agent's modification scope.

### Networking at the time of discovery

| Resource | Count / findings |
|---|---|
| VCNs | 4 |
| VCN CIDRs | All used `10.0.0.0/16` |
| Subnets | 5 |
| Public subnets | 4 |
| Private subnet | `wkcyber-subnet-private`, `10.0.2.0/24` |
| Internet gateways | 4, all enabled |
| NAT gateways | 1: `wkcyber-nat` |
| Public IPs | 6 total |
| NSGs | None returned |
| Security lists | 6 |

The four VCNs had overlapping CIDRs and could not be connected through ordinary VCN peering without renumbering or another explicit design.

Public IP breakdown:

- Four availability-domain-scoped IPs assigned to private IPs.
- One regional IP assigned to the NAT gateway.
- One reserved regional IP named `splunkcsoc`, unassigned/available.

A complete port-level review of every security list was not performed during Phase 1. No claim was made that existing public exposure was safe or unsafe.

### Budget and observed spending

One active monthly budget was found:

- Name: `SplunlLab`
- Amount: 1,200
- Actual spend reported by the budget: 191.6451
- Forecasted spend: 0
- Currency was not retrieved, so these values are not labelled BRL.

A detailed cost-by-service query was not completed. Credit-related Usage API access returned an authorization error.

## C. Quota and availability findings

| Limit | Reported value |
|---|---:|
| Standard E4 OCPUs | 100 |
| Standard E4 memory | 1,666 GB |
| Standard A1 OCPUs | 250 |
| Standard A1 memory | 1,666 GB |
| Standard E2 Micro OCPUs | 2 |
| E2.1.Micro instance count | 2 |
| Total block storage | 61,440 GB |
| Free block-storage allowance shown | 200 GB |
| Free backup count shown | 5 |
| VCNs | 50 |
| Reserved public IPs | 50 |

No compartment quotas were returned. Shape listing did not guarantee launch capacity. Real-time per-AD capacity remained unverified, and the single-AD region was accepted as a lab limitation rather than a highly available production design.

## D. Credit and expiration findings

| Item | Finding |
|---|---|
| Promotional balance | Approximately BRL 1,100 reported by owner; unverified |
| Exact expiration | Unknown |
| Services covered by credit | Unknown |
| Detailed actual cost by service | Not retrieved |
| Budget-reported spending | 191.6451, currency unverified |

The owner was asked to verify the exact balance, currency and expiration timestamp in the OCI Console.

## E. Security observations

1. The dedicated read-only discovery identity replaced the previous administrator-profile blocker.
2. Existing instances had public IP assignments; network and host-firewall review was required before SIEM installation.
3. No NSGs were found during initial discovery.
4. Public dashboards and public Elasticsearch/Wazuh API access remained prohibited.
5. Existing VCNs overlapped, motivating either clean reuse of one VCN without peering or a dedicated non-overlapping VCN.
6. Exact resource mapping was required before any Terraform import.
7. Any plan involving existing instances required review for forced replacement.
8. Destruction or recreation required separate, resource-specific approval.
9. Stopped instances still had boot volumes and networking resources that could generate charges.

## F. Historical reuse plan and cost implications

The approved Phase 1 constraint was initially to select existing VMs from the highest number downward:

| Priority | Existing VM | Planned name | Role |
|---:|---|---|---|
| 1 | `wkcyber-vm-17` | `SOC-WAZUH-01` | Wazuh all-in-one |
| 2 | `wkcyber-vm-16` | `SOC-ELASTIC-01` | Elastic Security, deferred |
| 3 | `wkcyber-vm-15` | `SOC-ATTACK-01` | Controlled simulations, on demand |
| 4 | `wkcyber-vm-14` | `SOC-NETWORK-01` | Zeek/Suricata, optional |

This mapping is superseded by the owner-reported deletions and the later greenfield decision.

At public E4 PAYG rates, resizing from 2 to 4 OCPUs was estimated to add USD 0.05/hour, approximately USD 36.50 / BRL 191.10 per 730-hour month.

The 21 existing 47 GB boot volumes represented approximately USD 41.95 / BRL 219.62 per month gross at public balanced block-volume rates, before free allowances, promotional credits or other adjustments. This was an estimate, not observed billing.

## G. Phase 1 approval boundary

Phase 2 was approved for design. No agent-performed rename, resize, start/stop, IAM/network change, Terraform apply, recreation, destruction or deletion was approved by Phase 1.

## Phase audit

- **Files changed during Phase 1:** None.
- **Cloud resources created, modified or deleted by the agent:** None.
- **Local software installed or upgraded by the agent:** None.
- **Validation:** Dedicated-profile authentication and read-only inventory succeeded after replacing PowerShell-incompatible JMESPath filters with native `ConvertFrom-Json`.
- **Known limitations:** Detailed cost-by-service, real-time AD capacity, promotional balance and exact expiration remained unknown.
