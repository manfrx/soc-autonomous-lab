variable "tenancy_ocid" {
  description = "OCID of the tenancy used for availability-domain discovery."
  type        = string
}

variable "compartment_id" {
  description = "OCID of the compartment in which SOC resources will be created."
  type        = string
}

variable "region" {
  description = "OCI region identifier."
  type        = string
  default     = "sa-saopaulo-1"
}

variable "oci_profile" {
  description = "OCI CLI config profile. SOC_DISCOVERY is sufficient for plan; apply requires a separate least-privilege profile."
  type        = string
  default     = "SOC_DISCOVERY"
}

variable "availability_domain" {
  description = "Optional availability-domain name. Defaults to the first AD returned by OCI."
  type        = string
  default     = null
  nullable    = true
}

variable "vcn_cidr" {
  description = "Dedicated SOC VCN CIDR; must not overlap existing 10.0.0.0/16 VCNs."
  type        = string
  default     = "10.30.0.0/16"
}

variable "management_subnet_cidr" {
  description = "Public management subnet CIDR."
  type        = string
  default     = "10.30.1.0/24"
}

variable "siem_subnet_cidr" {
  description = "Private SIEM subnet CIDR."
  type        = string
  default     = "10.30.2.0/24"
}

variable "admin_cidr" {
  description = "Single approved public IP in /32 CIDR form for future management-host SSH. Replace the documentation placeholder before apply."
  type        = string
  default     = "203.0.113.1/32"

  validation {
    condition     = can(cidrhost(var.admin_cidr, 0)) && endswith(var.admin_cidr, "/32") && var.admin_cidr != "0.0.0.0/32"
    error_message = "admin_cidr must be a valid, non-zero single IPv4 /32 CIDR."
  }
}

variable "wazuh_shape" {
  description = "OCI flexible shape for SOC-WAZUH-01."
  type        = string
  default     = "VM.Standard.E4.Flex"
}

variable "wazuh_ocpus" {
  description = "Number of OCPUs assigned to SOC-WAZUH-01."
  type        = number
  default     = 4

  validation {
    condition     = var.wazuh_ocpus >= 4
    error_message = "The Wazuh baseline requires at least 4 OCPUs."
  }
}

variable "wazuh_memory_gb" {
  description = "Memory assigned to SOC-WAZUH-01 in GiB."
  type        = number
  default     = 16

  validation {
    condition     = var.wazuh_memory_gb >= 8
    error_message = "The Wazuh baseline requires at least 8 GiB of memory."
  }
}

variable "wazuh_boot_volume_gb" {
  description = "Wazuh boot-volume size in GiB. The deployed SOC-WAZUH-01 was resized in place to 120 GiB (indexer + dashboard data); the default is reconciled to that value so `terraform apply` does not attempt to shrink the live boot volume."
  type        = number
  default     = 120

  validation {
    condition     = var.wazuh_boot_volume_gb >= 50
    error_message = "The Wazuh boot volume must be at least 50 GiB."
  }
}

variable "ubuntu_image_ocid" {
  description = "Optional pinned Ubuntu 24.04 image OCID. Null selects the newest compatible image returned by OCI."
  type        = string
  default     = null
  nullable    = true
}

variable "ssh_public_key" {
  description = "SSH public key for the ubuntu user. Read from a local file at plan time; never commit a private key."
  type        = string
}
