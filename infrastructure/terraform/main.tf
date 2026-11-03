data "oci_identity_availability_domains" "ads" {
  compartment_id = var.tenancy_ocid
}

data "oci_core_images" "ubuntu_2404" {
  compartment_id           = var.compartment_id
  operating_system         = "Canonical Ubuntu"
  operating_system_version = "24.04"
  shape                    = var.wazuh_shape
  sort_by                  = "TIMECREATED"
  sort_order               = "DESC"
}

locals {
  availability_domain = coalesce(
    var.availability_domain,
    data.oci_identity_availability_domains.ads.availability_domains[0].name
  )
  ubuntu_image_id = coalesce(var.ubuntu_image_ocid, data.oci_core_images.ubuntu_2404.images[0].id)

  common_tags = {
    Project     = "soc-autonomous-lab"
    Environment = "lab"
    ManagedBy   = "terraform"
  }
}

resource "oci_core_vcn" "soc" {
  compartment_id = var.compartment_id
  display_name   = "SOC-VCN-01"
  cidr_blocks    = [var.vcn_cidr]
  dns_label      = "soclab"
  freeform_tags  = local.common_tags
}

resource "oci_core_internet_gateway" "soc" {
  compartment_id = var.compartment_id
  vcn_id         = oci_core_vcn.soc.id
  display_name   = "SOC-IGW-01"
  enabled        = true
  freeform_tags  = local.common_tags
}

resource "oci_core_nat_gateway" "soc" {
  compartment_id = var.compartment_id
  vcn_id         = oci_core_vcn.soc.id
  display_name   = "SOC-NAT-01"
  freeform_tags  = local.common_tags
}

resource "oci_core_route_table" "mgmt" {
  compartment_id = var.compartment_id
  vcn_id         = oci_core_vcn.soc.id
  display_name   = "SOC-RT-MGMT-01"
  freeform_tags  = local.common_tags

  route_rules {
    destination       = "0.0.0.0/0"
    destination_type  = "CIDR_BLOCK"
    network_entity_id = oci_core_internet_gateway.soc.id
  }
}

resource "oci_core_route_table" "siem" {
  compartment_id = var.compartment_id
  vcn_id         = oci_core_vcn.soc.id
  display_name   = "SOC-RT-SIEM-01"
  freeform_tags  = local.common_tags

  route_rules {
    destination       = "0.0.0.0/0"
    destination_type  = "CIDR_BLOCK"
    network_entity_id = oci_core_nat_gateway.soc.id
  }
}

# Remove the default rules, including default SSH access from the internet.
resource "oci_core_default_security_list" "soc" {
  manage_default_resource_id = oci_core_vcn.soc.default_security_list_id
  display_name               = "SOC-DEFAULT-SL-DENY-ALL"
}

# OCI enforces subnet security lists AND network security groups conjunctively:
# traffic must be permitted by both. An empty security list therefore denies
# everything for that subnet, so the rules that carry the Bastion -> Wazuh
# manager path are declared here as well as in the NSGs.
#
# The OCI Bastion service forwards port-forwarding sessions from its private
# endpoint (10.30.1.253) which resides in var.management_subnet_cidr.

resource "oci_core_security_list" "mgmt" {
  compartment_id = var.compartment_id
  vcn_id         = oci_core_vcn.soc.id
  display_name   = "SOC-SL-MGMT-EMPTY"
  freeform_tags  = local.common_tags

  # Bastion -> Wazuh manager (SIEM subnet)
  egress_security_rules {
    protocol         = "6"
    destination      = var.siem_subnet_cidr
    destination_type = "CIDR_BLOCK"
    stateless        = false

    tcp_options {
      min = 22
      max = 22
    }
  }

  egress_security_rules {
    description      = "Allow Bastion to Wazuh HTTPS"
    protocol         = "6"
    destination      = var.siem_subnet_cidr
    destination_type = "CIDR_BLOCK"
    stateless        = false

    tcp_options {
      min = 443
      max = 443
    }
  }

  egress_security_rules {
    description      = "Allow Bastion to Wazuh agent events 1514"
    protocol         = "6"
    destination      = var.siem_subnet_cidr
    destination_type = "CIDR_BLOCK"
    stateless        = false

    tcp_options {
      min = 1514
      max = 1514
    }
  }

  egress_security_rules {
    description      = "Allow Bastion to Wazuh agent enrollment 1515"
    protocol         = "6"
    destination      = var.siem_subnet_cidr
    destination_type = "CIDR_BLOCK"
    stateless        = false

    tcp_options {
      min = 1515
      max = 1515
    }
  }
}

resource "oci_core_security_list" "siem" {
  compartment_id = var.compartment_id
  vcn_id         = oci_core_vcn.soc.id
  display_name   = "SOC-SL-SIEM-EMPTY"
  freeform_tags  = local.common_tags

  # Bastion (management subnet) -> Wazuh manager
  ingress_security_rules {
    protocol    = "6"
    source      = var.management_subnet_cidr
    source_type = "CIDR_BLOCK"
    stateless   = false

    tcp_options {
      min = 22
      max = 22
    }
  }

  ingress_security_rules {
    description = "Allow Bastion HTTPS"
    protocol    = "6"
    source      = var.management_subnet_cidr
    source_type = "CIDR_BLOCK"
    stateless   = false

    tcp_options {
      min = 443
      max = 443
    }
  }

  ingress_security_rules {
    description = "Allow Bastion to Wazuh agent events 1514"
    protocol    = "6"
    source      = var.management_subnet_cidr
    source_type = "CIDR_BLOCK"
    stateless   = false

    tcp_options {
      min = 1514
      max = 1514
    }
  }

  ingress_security_rules {
    description = "Allow Bastion to Wazuh agent enrollment 1515"
    protocol    = "6"
    source      = var.management_subnet_cidr
    source_type = "CIDR_BLOCK"
    stateless   = false

    tcp_options {
      min = 1515
      max = 1515
    }
  }

  # Wazuh manager -> Bastion (reply traffic)
  egress_security_rules {
    description      = "Allow Wazuh to reply Bastion"
    protocol         = "6"
    destination      = var.management_subnet_cidr
    destination_type = "CIDR_BLOCK"
    stateless        = false

    tcp_options {
      min = 443
      max = 443
    }
  }

  egress_security_rules {
    description      = "Allow Wazuh to reply Bastion 1514"
    protocol         = "6"
    destination      = var.management_subnet_cidr
    destination_type = "CIDR_BLOCK"
    stateless        = false

    tcp_options {
      min = 1514
      max = 1514
    }
  }

  egress_security_rules {
    description      = "Allow Wazuh to reply Bastion 1515"
    protocol         = "6"
    destination      = var.management_subnet_cidr
    destination_type = "CIDR_BLOCK"
    stateless        = false

    tcp_options {
      min = 1515
      max = 1515
    }
  }
}

resource "oci_core_network_security_group" "mgmt" {
  compartment_id = var.compartment_id
  vcn_id         = oci_core_vcn.soc.id
  display_name   = "SOC-NSG-MGMT-01"
  freeform_tags  = local.common_tags
}

resource "oci_core_network_security_group" "wazuh" {
  compartment_id = var.compartment_id
  vcn_id         = oci_core_vcn.soc.id
  display_name   = "SOC-NSG-WAZUH-01"
  freeform_tags  = local.common_tags
}

resource "oci_core_network_security_group_security_rule" "mgmt_ssh_ingress" {
  network_security_group_id = oci_core_network_security_group.mgmt.id
  direction                 = "INGRESS"
  protocol                  = "6"
  source                    = var.admin_cidr
  source_type               = "CIDR_BLOCK"
  stateless                 = false

  tcp_options {
    destination_port_range {
      min = 22
      max = 22
    }
  }
}

resource "oci_core_network_security_group_security_rule" "mgmt_siem_ssh_egress" {
  network_security_group_id = oci_core_network_security_group.mgmt.id
  direction                 = "EGRESS"
  protocol                  = "6"
  destination               = var.siem_subnet_cidr
  destination_type          = "CIDR_BLOCK"
  stateless                 = false

  tcp_options {
    destination_port_range {
      min = 22
      max = 22
    }
  }
}

resource "oci_core_network_security_group_security_rule" "wazuh_ssh_ingress" {
  network_security_group_id = oci_core_network_security_group.wazuh.id
  direction                 = "INGRESS"
  protocol                  = "6"
  source                    = var.management_subnet_cidr
  source_type               = "CIDR_BLOCK"
  stateless                 = false

  tcp_options {
    destination_port_range {
      min = 22
      max = 22
    }
  }
}

resource "oci_core_network_security_group_security_rule" "wazuh_agent_ingress" {
  for_each = {
    agent-events     = 1514
    agent-enrollment = 1515
  }

  network_security_group_id = oci_core_network_security_group.wazuh.id
  direction                 = "INGRESS"
  protocol                  = "6"
  source                    = var.siem_subnet_cidr
  source_type               = "CIDR_BLOCK"
  stateless                 = false

  tcp_options {
    destination_port_range {
      min = each.value
      max = each.value
    }
  }
}

# Bastion -> Wazuh manager.
#
# The OCI Bastion service forwards port-forwarding sessions from its private
# endpoint (10.30.1.253), which lives in var.management_subnet_cidr. Without
# these rules the manager never sees the agent traffic: the OCI NSG drops the
# packets before they reach the instance, so the host firewall never gets a
# chance to answer and the agent's TLS handshake to remoted hangs forever.
#
#   443  - Wazuh dashboard (HTTPS)
#   1514 - agent event channel (remoted)
#   1515 - agent enrollment / registration (authd)
resource "oci_core_network_security_group_security_rule" "wazuh_bastion_ingress" {
  for_each = {
    dashboard-https  = 443
    agent-events     = 1514
    agent-enrollment = 1515
  }

  network_security_group_id = oci_core_network_security_group.wazuh.id
  direction                 = "INGRESS"
  protocol                  = "6"
  source                    = var.management_subnet_cidr
  source_type               = "CIDR_BLOCK"
  stateless                 = false

  tcp_options {
    destination_port_range {
      min = each.value
      max = each.value
    }
  }
}

locals {
  internet_tcp_egress_ports = {
    http  = 80
    https = 443
  }
}

resource "oci_core_network_security_group_security_rule" "mgmt_internet_tcp_egress" {
  for_each = local.internet_tcp_egress_ports

  network_security_group_id = oci_core_network_security_group.mgmt.id
  direction                 = "EGRESS"
  protocol                  = "6"
  destination               = "0.0.0.0/0"
  destination_type          = "CIDR_BLOCK"
  stateless                 = false

  tcp_options {
    destination_port_range {
      min = each.value
      max = each.value
    }
  }
}

resource "oci_core_network_security_group_security_rule" "wazuh_internet_tcp_egress" {
  for_each = local.internet_tcp_egress_ports

  network_security_group_id = oci_core_network_security_group.wazuh.id
  direction                 = "EGRESS"
  protocol                  = "6"
  destination               = "0.0.0.0/0"
  destination_type          = "CIDR_BLOCK"
  stateless                 = false

  tcp_options {
    destination_port_range {
      min = each.value
      max = each.value
    }
  }
}

resource "oci_core_network_security_group_security_rule" "mgmt_dns_egress" {
  for_each = {
    tcp = "6"
    udp = "17"
  }

  network_security_group_id = oci_core_network_security_group.mgmt.id
  direction                 = "EGRESS"
  protocol                  = each.value
  destination               = var.vcn_cidr
  destination_type          = "CIDR_BLOCK"
  stateless                 = false

  dynamic "tcp_options" {
    for_each = each.key == "tcp" ? [1] : []
    content {
      destination_port_range {
        min = 53
        max = 53
      }
    }
  }

  dynamic "udp_options" {
    for_each = each.key == "udp" ? [1] : []
    content {
      destination_port_range {
        min = 53
        max = 53
      }
    }
  }
}

resource "oci_core_network_security_group_security_rule" "wazuh_dns_egress" {
  for_each = {
    tcp = "6"
    udp = "17"
  }

  network_security_group_id = oci_core_network_security_group.wazuh.id
  direction                 = "EGRESS"
  protocol                  = each.value
  destination               = var.vcn_cidr
  destination_type          = "CIDR_BLOCK"
  stateless                 = false

  dynamic "tcp_options" {
    for_each = each.key == "tcp" ? [1] : []
    content {
      destination_port_range {
        min = 53
        max = 53
      }
    }
  }

  dynamic "udp_options" {
    for_each = each.key == "udp" ? [1] : []
    content {
      destination_port_range {
        min = 53
        max = 53
      }
    }
  }
}

resource "oci_core_network_security_group_security_rule" "mgmt_ntp_egress" {
  network_security_group_id = oci_core_network_security_group.mgmt.id
  direction                 = "EGRESS"
  protocol                  = "17"
  destination               = "0.0.0.0/0"
  destination_type          = "CIDR_BLOCK"
  stateless                 = false

  udp_options {
    destination_port_range {
      min = 123
      max = 123
    }
  }
}

resource "oci_core_network_security_group_security_rule" "wazuh_ntp_egress" {
  network_security_group_id = oci_core_network_security_group.wazuh.id
  direction                 = "EGRESS"
  protocol                  = "17"
  destination               = "0.0.0.0/0"
  destination_type          = "CIDR_BLOCK"
  stateless                 = false

  udp_options {
    destination_port_range {
      min = 123
      max = 123
    }
  }
}

resource "oci_core_subnet" "mgmt" {
  compartment_id             = var.compartment_id
  vcn_id                     = oci_core_vcn.soc.id
  display_name               = "SOC-SUBNET-MGMT-01"
  cidr_block                 = var.management_subnet_cidr
  dns_label                  = "mgmt"
  prohibit_public_ip_on_vnic = false
  route_table_id             = oci_core_route_table.mgmt.id
  security_list_ids          = [oci_core_security_list.mgmt.id]
  freeform_tags              = local.common_tags
}

resource "oci_core_subnet" "siem" {
  compartment_id             = var.compartment_id
  vcn_id                     = oci_core_vcn.soc.id
  display_name               = "SOC-SUBNET-SIEM-01"
  cidr_block                 = var.siem_subnet_cidr
  dns_label                  = "siem"
  prohibit_public_ip_on_vnic = true
  route_table_id             = oci_core_route_table.siem.id
  security_list_ids          = [oci_core_security_list.siem.id]
  freeform_tags              = local.common_tags
}

resource "oci_core_instance" "wazuh" {
  compartment_id      = var.compartment_id
  availability_domain = local.availability_domain
  display_name        = "SOC-WAZUH-01"
  shape               = var.wazuh_shape
  freeform_tags       = local.common_tags

  shape_config {
    ocpus         = var.wazuh_ocpus
    memory_in_gbs = var.wazuh_memory_gb
  }

  source_details {
    source_type             = "image"
    source_id               = local.ubuntu_image_id
    boot_volume_size_in_gbs = var.wazuh_boot_volume_gb
    boot_volume_vpus_per_gb = 10
  }

  create_vnic_details {
    display_name     = "SOC-WAZUH-01-VNIC"
    hostname_label   = "soc-wazuh-01"
    subnet_id        = oci_core_subnet.siem.id
    assign_public_ip = false
    nsg_ids          = [oci_core_network_security_group.wazuh.id]
  }

  metadata = {
    # CorreÃ§Ã£o: Lendo o conteÃºdo do arquivo em vez do caminho
    ssh_authorized_keys = file(var.ssh_public_key)
  }

  preserve_boot_volume = true

  # Trava de seguranÃ§a comentada temporariamente para permitir a recriaÃ§Ã£o da mÃ¡quina
  # lifecycle {
  #   prevent_destroy = true
  # }
}