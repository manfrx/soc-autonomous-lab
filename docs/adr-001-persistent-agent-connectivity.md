# ADR-001 — Persistência do canal do agente Wazuh além do TTL do OCI Bastion

| Campo | Valor |
|---|---|
| **ID** | ADR-001 |
| **Status** | **Aceito** (estado-alvo de produção); **Provisório em execução** — túneis OCI Bastion (TTL 1 h) |
| **Data** | 2026-11-03 |
| **Escopo** | Conectividade de gerenciamento do endpoint Windows 11 (`DESKTOP-0U2NKV7`) ao gerenciador Wazuh privado (`SOC-WAZUH-01` / 10.30.2.49) |
| **Relacionados** | `docs/phase2_design.md` §2 *Administrative path*, §2 *Windows endpoint implication*, `investigations/SOC-001-002-003-Report.md` §6.3 |

---

## 1. Contexto e vetores de decisão

O endpoint é uma estação Windows 11 em **rede doméstica** (`192.168.15.9`, NAT, sem IP público).
O gerenciador Wazuh é uma VM **privada** em `10.30.2.49`, dentro da VCN `SOC-VCN-01`
(`10.30.0.0/16`), sem IP público (`prohibit_public_ip_on_vnic = true`).

Não existe rota de rede entre os dois. O único caminho disponível é o **OCI Bastion**, por meio de
sessões de *port forwarding* — e o Bastion é um serviço **session-scoped**, não um servidor SSH
convencional:

- Cada conexão SSH ao Bastion é autenticada contra o OCID de uma **sessão específica**.
- A sessão possui TTL fixo e, ao expirar, **a conexão SSH é encerrada pelo serviço**.
- `SOC-BASTION-01` opera com `max-session-ttl-in-seconds = 3600` (1 hora) e
  `max-sessions-allowed = 20`.

Consequência: **não existe túnel SSH persistente através do Bastion.** O agente não pode manter
uma conexão de longa duração para `remoted` usando esse mecanismo.

## 2. Evidência empírica (Fases 6, 9 e 10)

O problema não é teórico — foi reproduzido **três vezes** durante a implementação:

| Ocorrência | Momento (UTC) | Sintoma observado |
|---|---|---|
| 1ª | ~00:21 | Sessão de 443 expirou → `ERR_CONNECTION_REFUSED` em `https://127.0.0.1:8443`; 3 túneis encerrados de uma vez |
| 2ª | ~01:22 | Todas as sessões (criadas 00:21–00:22) expiraram → agente desconectado, dashboard inacessível |
| 3ª | ~02:38 | Renovação preventiva executada a tempo (sem impacto) |

**Modo de falha característico (silencioso):** quando a sessão expira, o `WazuhSvc` continua
reportando `Running`, o processo `wazuh-agent` continua ativo, mas a conexão TCP com
`127.0.0.1:1514` cai e o agente registra apenas `Closing connection to server` a cada 60 s
(`time-reconnect`). No painel do gerenciador o agente transita para `Never connected` /
`Disconnected` **sem qualquer alerta** — não há regra que detecte a perda do próprio canal de
telemetria.

Custo operacional medido: **3 renovações manuais de sessão + 3 recriações de túnel** em ~4 h de
trabalho, cada uma exigindo `oci bastion session create` + validação de propagação na
frente SSH do Bastion (o frontend do Bastion replicou as sessões com atraso inconsistente de
~1 s a ~10 min, exigindo retries).

### 2.1 Acoplamento do agente ao túnel

O agente foi configurado para `127.0.0.1:1514` (loopback local) porque essa era a única rota
disponível. Isso cria um **acoplamento direto entre a topologia de transporte e a configuração do
agente**:

```xml
<client>
  <server>
    <address>127.0.0.1</address>   <!-- funciona SOMENTE com o túnel ativo -->
    <port>1514</port>
```

Qualquer migração para transporte persistente **não é uma mudança no agente** — é a remoção de
um `127.0.0.1` e a escrita de um IP/hostname estável. O `client.keys` do agente não precisa ser
reemitido: a chave é a identidade, e o gerenciador já registra o agente com `IP: any`
(`001 windows-endpoint any 92d84918…`), ou seja, **não há pin de IP**.

## 3. Decisão

Para produção, substituir o Bastion como **transportador de dados do agente** por um transporte
persistente, escolhendo entre:

- **Opção A — Proxy TCP persistente (Nginx `stream`)** com um *forwarder* alcançável a partir do endpoint.
- **Opção B — VPN Site-to-Site (IPsec)** entre a rede doméstica e a VCN.

Em ambos os casos o agente passa a apontar para um endereço **estável** do gerenciador, e a
perda da sessão deixa de ser um evento de disponibilidade.

### 3.1 Precondição crítica — por que o Nginx Stream *no gerenciador* não basta

Um proxy `stream` Nginx **rodando no próprio `SOC-WAZUH-01`** é inócuo para o endpoint: ele
continua inalcançável, porque o endpoint não tem rota para `10.30.2.0/24`. O proxy resolve
problemas de *terminação* e *observabilidade* de conexão, **não o problema de alcançabilidade**.

Portanto, a Opção A exige um **forwarder com IP público** (ou atrás de um balanceador público),
encaminhando TCP para `10.30.2.49`. Isso acrescenta uma superfície pública à topologia e deve ser
tratado como tal.

### 3.2 Opção A — Forwarder Nginx `stream` (recomendada para este ambiente)

**Topologia-alvo**

```
Endpoint Windows 11 (192.168.15.9, NAT)
        │  TCP 1514/443
        ▼
┌───────────────────────────────────────────┐
│ VCN SOC-VCN-01 (10.30.0.0/16)            │
│  ┌─────────────────────────────────────┐  │
│  │ SOC-FORWARDER-01  (IP público)     │  │
│  │  nginx stream :1514 / :443         │  │
│  └──────────────┬──────────────────────┘  │
│                 │ 10.30.0.0/16           │
│                 ▼                         │
│  ┌─────────────────────────────────────┐  │
│  │ SOC-WAZUH-01  10.30.2.49           │  │
│  │  remoted :1514  authd :1515         │  │
│  │  dashboard :443                    │  │
│  └─────────────────────────────────────┘  │
└───────────────────────────────────────────┘
```

**Configuração Nginx (mínima, sem Terminate TLS — proxy L4 transparente)**

```nginx
# /etc/nginx/nginx.conf
stream {
    upstream wazuh_remoted { server 10.30.2.49:1514; max_fails=3 fail_timeout=30s; }
    upstream wazuh_dash    { server 10.30.2.49:443;  max_fails=3 fail_timeout=30s; }

    server {
        listen 1514;
        # allowlist: apenas o IP público do endpoint
        allow  <ENDPOINT_PUBLIC_CIDR>;
        deny   all;
        proxy_pass            wazuh_remoted;
        proxy_connect_timeout 5s;
        proxy_timeout         1h;      # > notify_time(20s); não corta sessão longa do agente
    }

    server {
        listen 443;
        allow  <ENDPOINT_PUBLIC_CIDR>;
        deny   all;
        proxy_pass            wazuh_dash;
        proxy_connect_timeout 5s;
        proxy_timeout         1h;
    }
}
```

**Pontos de atenção verificados nesta execução**

- **Transparência TLS:** como o proxy é L4, o handshake TLS do agente (`remoted`) e a validação de
  certificado contra `wpk_root.pem` permanecem inalterados. `verify-host` do agente não é
  habilitado por padrão, portanto a apresentação do certificado do `remoted` via o forwarder
  não quebra a conexão.
- **`proxy_timeout`:** o agente envia keepalive a cada `notify_time` (20 s neste host) e
  reconecta em `time-reconnect` (60 s). O padrão do Nginx para `stream` é 10 min; valores
  curtos demais derrubariam sessões o agent considera ativas.
- **Isolamento de origem:** `allow/deny` no `stream` é o controle de acesso real, já que o
  forwarder é público.
- **Não expor `1515`:** `authd` (enrollment) só é necessário no registro inicial. Após o
  registro, apenas `1514` é exigido pelo agente em execução.

**Terraform (proposto, não aplicado)**

```hcl
resource "oci_core_instance" "forwarder" {
  compartment_id      = var.compartment_id
  availability_domain = local.availability_domain
  display_name        = "SOC-FORWARDER-01"
  shape               = var.forwarder_shape          # VM.Standard.E2.Flex
  source_details { source_type = "image" source_id = local.ubuntu_image_id }
  create_vnic_details {
    subnet_id        = oci_core_subnet.mgmt.id
    assign_public_ip = true
    nsg_ids          = [oci_core_network_security_group.forwarder.id]
  }
}
```

Exige sub-rede de management com `prohibit_public_ip_on_vnic = false` (já é o caso) e um NSG
próprio com ingress 1514/443 restrito ao `/32` do endpoint.

### 3.3 Opção B — VPN Site-to-Site (IPsec)

**Topologia-alvo**

```
Rede doméstica 192.168.15.0/24
   CPE / roteador com IPsec  ──IPsec──▶  OCI IPSec Tunnel
                                             │
                                        DRG + rotas
                                             │
                                             ▼
                                    10.30.2.49 (remoted :1514)
```

**Requisitos**

- CPE (roteador doméstico / appliance) com suporte a IPsec e **IP público estável**.
- OCI: `oci_core_ip_security_connection` + `oci_core_drouting_attachment` + `oci_core_drg_route_distribution`
  (roteamento dinâmico/BGP ou estático).
- Roteamento `192.168.15.0/24 ⇄ 10.30.2.0/24` e NSG da VCN permitindo 1514 a partir do
  prefixo doméstico.

**Vantagens**

- **Zero superfície pública nova** — o gerenciador permanece inteiramente privado.
- Endpoint e todos os hosts domésticos ganham acesso direto à VCN, o que resolve de uma vez
  dashboard, API (55000), indexer e enrollment.
- Independência de fornecedor (não é um SaaS adicional).

**Custo / risco**

- Exige ** CPE** que suporte IPsec — a maioria dos roteadores domésticos não tem.
- IP público **estável** no CPE (o endpoint não tem).
- Managed by the CPE: falhas de IKEKey rotation e de keepalive exigem manutenção.

**Variante recomendada quando o CPE não é viável:** um **subnet router WireGuard/Tailscale**
(uma micro-VM no `SOC-SUBNET-MGMT-01`) anuncia o prefixo `10.30.2.0/24` para a malha do endpoint.
É a variante de menor atrito para o caso de uso "estação de trabalho em casa".

### 3.4 Opção C — OCI Secure Access (ZTNA), nativa da OCI

Não citada no levantamento original, mas é a alternativa **nativa da OCI** para ZTNA sobre IP
privado: um *Windows Connector* no endpoint e uma política de serviço permitindo TCP a
`10.30.2.49:1514`. Não expõe nada publicamente e não exige VPN site-to-site no CPE.

Contra-indicação: o Secure Access é um **add-on pago** fora do free tier, e exige agentes
específicos por SO (o Connector para Windows). Deve ser avaliado contra o custo de um
subnet router WireGuard.

### 3.5 Mitigação imediata (estado corrente)

Independentemente da opção escolhida, o estado provisório pode ser endurecido:

1. **Elevar o TTL das sessões.** `max-session-ttl-in-seconds` é configurável no Bastion
   (`oci bastion bastion update`). O valor atual é 3600; **verificar se a OCI aceita 86400
   (24 h)** reduziria as renovações de 24×/dia para 1×/dia. *Não aplicado — requer validação
   do limite aceito pela OCI e aprovação de mudança.*
2. **Tarefa agendada de renovação** que recrie as sessões e reinicie os túneis proativamente
   (por exemplo, a cada 45 min), com **início na origem** do túnel para evitar a janela de
   indisponibilidade.
3. **Alerta de perda de telemetria.** Criar regra no gerenciador que detecte a ausência de
   keepalive do agente 001 e emita alerta — hoje a queda do canal é **silenciosa**.

## 4. Comparativo

| Critério | A — Nginx stream (forwarder) | B — IPsec Site-to-Site | C — Secure Access (ZTNA) | Atual — Bastion |
|---|---|---|---|---|
| Persistência | Total | Total | Total | **1 h (sessão)** |
| Superfície pública nova | Sim (1 IP + 2 portas) | Não | Não | Sim (IP público do Bastion) |
| Requisito no endpoint | Nada | Nada ( CPE no roteador) | Windows Connector | `ssh.exe` + sessão |
| Custo | Compute da VM | IPsec do provider | Add-on pago | Incluído |
| Alcança dashboard/API/indexer | Com portas adicionais | Sim, toda a VCN | Por política | Uma porta por sessão |
| Complexidade operacional | Baixa (nginx + systemd) | Média (IKE, BGP, CPE) | Média (agente + política) | **Alta (manual)** |
| Adequado ao endpoint em casa | Sim | Depende do CPE | Sim | Apenas como ponte |

**Recomendação para este laboratório:** avançar com a **Opção B (ou sua variante WireGuard)** se
houver um CPE com IPsec; caso contrário, **Opção A** com allowlist de `/32` no endpoint e a
**Opção C** se o custo do Secure Access for aceitável. A Opção A isolada — sem forwarder
publicamente alcançável — não resolve o problema, conforme §3.1.

## 5. Mudanças de configuração exigidas por opção

| Componente | Estado atual | Estado-alvo (A, B ou C) |
|---|---|---|
| `ossec.conf` (agente) | `<address>127.0.0.1</address>` | `<address>10.30.2.49</address>` (ou IP do forwarder) |
| `ossec.conf` (agente) | sem `<enrollment>` | idem, com `<manager_address>` apontando para o mesmo endereço |
| `client.keys` | `001 windows-endpoint any 92d84918…` | **inalterado** — a chave é a identidade; `any` significa sem pin de IP |
| NSG `SOC-NSG-WAZUH-01` | ingress 1514/1515 de `10.30.1.0/24` | sem alteração (o agente não é mais originado do Bastion); revisar remoção das regras do Bastion |
| NSG novo `SOC-NSG-FORWARDER` | — | ingress 1514/443 do `/32` do endpoint |
| iptables (host do gerenciador) | ACCEPT 443/1514/1515 de `10.30.1.253/32` | reavaliar: origem passa a ser o forwarder ou a rede doméstica |
| `systemd` | — | `nginx.service` com `After=network-online.target` e `Restart=always` |

## 6. Plano de migração

1. **Preparar a rota alternativa sem cortar o canal existente** (o agente continua no Bastion).
2. Implantar o transporte persistente (forwarder **ou** VPN) e validar conectividade por
   `nc`/`curl` a partir do endpoint.
3. Alterar `<address>` no `ossec.conf` e reiniciar `WazuhSvc`.
4. **Verificar no gerenciador** que `agent_control -lc` reporta `ID: 001 … Active` **e** que
   houve **zero** eventos de `Closing connection` no `ossec.log` do agente.
5. Manter o Bastion por um período de observação (uma janela de TTL completa = 1 h) para
   garantir que nenhuma dependência residual permaneça.
6. Remover então as regras de ingress do Bastion (NSG + security lists) e as tarefas de
   renovação, reduzindo a superfície.

**Rollback:** restaurar `ossec.conf` para `127.0.0.1` e reabrir a sessão do Bastion — o caminho
de retorno é o estado já validado em produção parcial.

## 7. Riscos e mitigações

| Risco | Mitigação |
|---|---|
| Forwarder públicoizado atrai varredura | `allow/deny` por `/32`; revisão de logs; preferir B/C se o CPE permitir |
| Perda do canal continua silenciosa | Regra de detecção de ausência de keepalive (§3.5.3) |
| Alinhamento de versão Wazuh | Restringir a versão do agente à do gerenciador em CI (`wazuh-control -i` vs. versão do manager) |
| Alteração de rota derruba a telemetria | Janela de observação de 1 TTL completo antes de remover o Bastion |

## 8. Consequências

**Positivas**

- A telemetria do endpoint deixa de depender de intervenção humana recorrente.
- O `ossec.conf` volta a descrever a topologia real (`10.30.2.49`), e não um detalhe de
  transporte local.
- O dashboard deixa de exigir uma sessão por sessão.

**Negativas**

- A Opção A introduz um IP público no perímetro da VCN e exige revisão de segurança.
- A Opção B transfere parte da operação para o CPE doméstico.
- Requer trabalho adicional de Terraform e hardening do forwarder.

## 9. Referências

- `docs/phase2_design.md` §2 — *Administrative path*, §2 — *Windows endpoint implication*
  (a previsão original de "VPN ou outro caminho restrito" foi **confirmada** pela implementação)
- `investigations/SOC-001-002-003-Report.md` §6.3 — recomendação 9 (remover o Bastion do caminho de dados)
- `infrastructure/terraform/main.tf` — `oci_core_network_security_group_security_rule.wazuh_bastion_ingress`
  (as regras que hoje sustentam o caminho via Bastion e que serão removidas na etapa 6)
