# Phase 2 — Greenfield SOC Design

**Status:** Design for review; no cloud apply approved.  
**Region:** `sa-saopaulo-1`  
**Approach:** Create new SOC infrastructure rather than importing pre-existing lab resources.

## 1. Scope and constraints

The initial Terraform configuration creates only:

- One dedicated VCN and non-overlapping subnets.
- Internet and NAT gateways with separate route tables.
- Restrictive security lists and NSGs.
- One private Wazuh all-in-one VM named `SOC-WAZUH-01`.

Elastic, attack and network-sensor VMs are deferred. Existing VCNs, public IPs, volumes and remaining VMs are not data sources to be modified and are not Terraform targets.

The owner reported deleting `wkcyber-vm-17` through `wkcyber-vm-10` manually. Terraform will not attempt to import or recreate those historical mappings.

## 2. Network architecture

The four discovered VCNs used `10.0.0.0/16`. The new VCN uses `10.30.0.0/16`, which does not overlap that range. No peering to existing VCNs is proposed.

| Component | Name | CIDR / exposure | Purpose |
|---|---|---|---|
| VCN | `SOC-VCN-01` | `10.30.0.0/16` | Isolated SOC address space |
| Management subnet | `SOC-SUBNET-MGMT-01` | `10.30.1.0/24`, public | Future explicitly approved bastion/management access |
| SIEM subnet | `SOC-SUBNET-SIEM-01` | `10.30.2.0/24`, private | Wazuh and future private SIEM workloads |
| Internet gateway | `SOC-IGW-01` | Public VCN edge | Management-subnet connectivity only |
| NAT gateway | `SOC-NAT-01` | Regional public egress | Private SIEM updates and outbound connections |
| Management route table | `SOC-RT-MGMT-01` | `0.0.0.0/0` → IGW | Public management subnet |
| SIEM route table | `SOC-RT-SIEM-01` | `0.0.0.0/0` → NAT | Private outbound-only internet access |

`SOC-WAZUH-01` receives only a private IP. `prohibit_public_ip_on_vnic` is enabled on the SIEM subnet, providing a second control against accidental public-IP assignment.

### Administrative path

The management subnet is intentionally created without a management VM. Before Phase 5, the owner must approve one administrative mechanism, preferably OCI Bastion or a tightly restricted management host. Wazuh SSH is allowed only from the management subnet.

The Wazuh dashboard will be reached through an SSH tunnel after that mechanism exists. No inbound NSG rule is created for dashboard TCP/443, Elasticsearch TCP/9200 or Wazuh API TCP/55000.

### Windows endpoint implication

A private Wazuh manager cannot directly receive connections from the owner's home Windows endpoint without private connectivity. Phase 6 must therefore propose and obtain approval for a VPN or another restricted agent path. The initial design does not expose agent ports to the internet.

> **Addendum — Phase 6/9/10 (2026-11-03).** The Phase 2 prediction above was implemented and
> confirmed. The approved administrative mechanism is **OCI Bastion** (`SOC-BASTION-01`,
> `SOC-SUBNET-MGMT-01`), and the agent path runs as SSH port-forwarding tunnels to
> `10.30.2.40:1514` (events) and `1515` (enrollment). The private IP is assigned by OCI and
> changes on every recreate — derive it from `terraform output wazuh_private_ip`.
>
> Two findings from implementation require the design changes recorded in
> **`adr-001-persistent-agent-connectivity.md`**:
>
> 1. Bastion sessions are **session-scoped with a 1-hour TTL** and cannot be made persistent.
>    The endpoint therefore goes telemetry-dark every hour unless sessions and tunnels are
>    renewed manually. The target state is a persistent TCP proxy or a Site-to-Site VPN.
> 2. The dashboard **does** require a TCP/443 path from the management subnet, which this
>    design originally listed as "explicitly absent". See §3 and the Bastion ingress rows in
>    `SOC-NSG-WAZUH-01` below.

## 3. NSG and security-list design

> **Correction — 2026-11-03 (Phase 9/10).** The statement below that "security lists attached to
> both subnets contain no rules; traffic permissions are centralized in NSGs" is **not valid in
> OCI and has been corrected in the Terraform**. OCI enforces subnet security lists **and** NSGs
> conjunctively — traffic must be permitted by *both*, and a security list with no rules denies
> everything for that subnet. The empty-list design therefore silently blocked the Bastion path
> (agent events and dashboard) at the VCN layer before the instance firewall was ever reached.
> Both security lists now carry the rules that carry the Bastion → manager path, and the
> NSGs remain in place as the narrower, host-scoped layer.

Security lists attached to both subnets now carry only the rules that permit the OCI Bastion
forwarding path; the VCN default security list is explicitly emptied so its usual default SSH
rule cannot silently expose a future public management host.

### `SOC-NSG-MGMT-01`

Intended for a future management host, not attached to Wazuh.

| Direction | Protocol / port | Source / destination | Reason |
|---|---|---|---|
| Ingress | TCP/22 | Owner-approved single `/32` admin CIDR | SSH to future management host |
| Egress | TCP/22 | `10.30.2.0/24` | SSH from management to SIEM |
| Egress | TCP/80, TCP/443 | `0.0.0.0/0` | Package updates and administration downloads |
| Egress | TCP/53, UDP/53 | `10.30.0.0/16` | VCN DNS |
| Egress | UDP/123 | `0.0.0.0/0` | Time synchronization |

The Terraform variable defaults to the documentation-only address `203.0.113.1/32`. It must be replaced with the owner's actual single-IP CIDR before any apply. `0.0.0.0/0` is rejected for SSH input.

### `SOC-NSG-WAZUH-01`

Attached directly to the Wazuh VNIC.

| Direction | Protocol / port | Source / destination | Reason |
|---|---|---|---|
| Ingress | TCP/22 | `10.30.1.0/24` | Administration from management subnet only |
| Ingress | TCP/1514 | `10.30.2.0/24` | Future private lab Wazuh agents |
| Ingress | TCP/1515 | `10.30.2.0/24` | Future private lab agent enrollment |
| Ingress | TCP/443 | `10.30.1.0/24` | Bastion → Wazuh dashboard *(added Phase 9/10)* |
| Ingress | TCP/1514 | `10.30.1.0/24` | Bastion → agent events *(added Phase 9/10)* |
| Ingress | TCP/1515 | `10.30.1.0/24` | Bastion → agent enrollment *(added Phase 9/10)* |
| Egress | TCP/80, TCP/443 | `0.0.0.0/0` | OS/Wazuh updates and threat-intelligence feeds |
| Egress | TCP/53, UDP/53 | `10.30.0.0/16` | VCN DNS |
| Egress | UDP/123 | `0.0.0.0/0` | Time synchronization |

All NSG rules are stateful. Return traffic for established connections therefore does not require broad inbound rules. Host-level Ubuntu firewall rules and verified Wazuh-version port requirements will be reviewed during Phase 5; cloud NSGs are not a substitute for host hardening.

> **Addendum — Phase 9/10.** The three `10.30.1.0/24` ingress rows are required because the OCI
> Bastion forwards port-forwarding sessions from its private endpoint `10.30.1.253`, which lives
> in the management subnet. Without them the manager never receives the agent's packets: the NSG
> drops them before they reach the instance, so the host firewall never gets a chance to answer
> and the agent's TLS handshake to `remoted` hangs until timeout. The same three ports are
> required in the management-subnet security list (egress) and the SIEM-subnet security list
> (ingress) — see the correction note above.

Explicitly absent from inbound rules:

- Elasticsearch TCP/9200
- Wazuh API TCP/55000
- SSH from `0.0.0.0/0`
- Wazuh agent ports from the public internet

> **Correction — Phase 9/10.** "Wazuh dashboard TCP/443" was originally listed as absent. It is
> now present, but scoped to `10.30.1.0/24` (management subnet / Bastion) only — never from
> `0.0.0.0/0`. The dashboard remains unreachable from the internet.

## 4. Compute design

| Attribute | Initial value |
|---|---|
| Name | `SOC-WAZUH-01` |
| Image | Latest OCI Canonical Ubuntu 24.04 image compatible with the selected shape, discovered at plan time |
| Shape | `VM.Standard.E4.Flex` |
| OCPUs | 4 |
| RAM | 16 GB |
| Boot volume | 120 GB, balanced 10 VPUs/GB |
| Subnet | Private SIEM subnet |
| Public IP | None |
| NSG | `SOC-NSG-WAZUH-01` |

For reproducibility, the plan output identifies the selected image OCID. Before apply, that OCID can be pinned with `ubuntu_image_ocid`; otherwise a later plan may select a newer Ubuntu image.

Wazuh installation, credentials, dashboard configuration and agent enrollment are excluded from Terraform cloud-init in this phase. They belong to Phase 5 and must not place secrets in Terraform state.

## 5. Terraform mapping and safety controls

The greenfield resource map is:

- `oci_core_vcn.soc`
- `oci_core_internet_gateway.soc`
- `oci_core_nat_gateway.soc`
- `oci_core_route_table.mgmt` and `oci_core_route_table.siem`
- `oci_core_default_security_list.soc` plus two custom security lists (now carrying the Bastion
  path rules — see the correction note in §3)
- `oci_core_network_security_group.mgmt` and `oci_core_network_security_group.wazuh`
- `oci_core_subnet.mgmt` and `oci_core_subnet.siem`
- `oci_core_instance.wazuh`

There are no `terraform import` operations and no references to the deleted `wkcyber-vm-*` instances. Terraform state is local initially and excluded from Git; a locking remote backend requires a later security/cost review.

Plan review must confirm:

1. Only greenfield SOC resources are scheduled for creation.
2. No existing resource is scheduled for update or deletion.
3. Wazuh has no public IP and uses the private SIEM subnet.
4. No public inbound dashboard, API or Elasticsearch rule exists.
5. The admin CIDR is a single approved address, not the documentation placeholder or an unrestricted range.
6. The selected image is x86_64-compatible Canonical Ubuntu 24.04.

## 6. Preliminary cost estimate

Using the previously retrieved Oracle public PAYG list rates and 730 hours/month:

| Item | Estimate |
|---|---:|
| E4 compute: 4 OCPUs, 16 GB | USD 90.52 / BRL 473.94 per month |
| 120 GB balanced boot volume | USD 2.13 / BRL 11.13 per month |
| Known subtotal | **USD 92.65 / BRL 485.07 per month** |

Not included: NAT/public-IP charges, taxes, backups, snapshots, logging and any future management host or VPN. Free-tier and promotional-credit eligibility remain unverified. This estimate is not approval to create billable resources.

Stopping Wazuh later does not remove storage or other attached-resource charges.

## 7. Approval boundary and next steps

Allowed in the current request: local project files, Terraform formatting, initialization, validation and a read-only plan.

Still required before apply:

- Approval of this design and the reviewed Terraform plan.
- Replacement of the placeholder admin CIDR.
- A final itemized estimate including networking and the selected management mechanism.
- A dedicated least-privilege deployment identity/profile. `SOC_DISCOVERY` is read-only; the owner's administrator profile is not required by Terraform and is not the approved automation identity.
- Explicit approval for every billable resource included in the apply.
