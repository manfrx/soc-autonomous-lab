output "vcn_id" {
  description = "OCID of the planned dedicated SOC VCN."
  value       = oci_core_vcn.soc.id
}

output "wazuh_instance_id" {
  description = "OCID of the planned Wazuh instance."
  value       = oci_core_instance.wazuh.id
}

output "wazuh_private_ip" {
  description = "Private IP assigned to SOC-WAZUH-01."
  value       = oci_core_instance.wazuh.private_ip
}

output "selected_ubuntu_image_id" {
  description = "Ubuntu image selected for SOC-WAZUH-01; pin this before apply if reproducibility is required."
  value       = local.ubuntu_image_id
}
