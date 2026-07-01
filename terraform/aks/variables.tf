variable "location" {
  description = "Azure region for the resource group and AKS cluster."
  type        = string
  default     = "eastus"
}

variable "resource_group_name" {
  description = "Resource group name (created by this module)."
  type        = string
  default     = "kube-rbac-polp-aks-test-rg"
}

variable "cluster_name" {
  description = "AKS cluster name (also used as dns_prefix when dns_prefix is empty)."
  type        = string
  default     = "kube-rbac-polp-aks-test"
}

variable "dns_prefix" {
  description = "DNS prefix for the API server FQDN (must be DNS-1123; empty uses cluster_name)."
  type        = string
  default     = ""
}

variable "kubernetes_version" {
  description = "Kubernetes version for the control plane (null = latest supported in region)."
  type        = string
  default     = null
}

variable "node_count" {
  description = "Node count for the default system pool (lab default: 1)."
  type        = number
  default     = 1
}

variable "vm_size" {
  description = "VM SKU for default node pool."
  type        = string
  default     = "Standard_B2s"
}

variable "os_disk_size_gb" {
  description = "OS disk size (GB) for nodes in the default pool."
  type        = number
  default     = 30
}

variable "deploy_capability_test_workloads" {
  description = "Create namespace and Deployments for ../../AKS-ContainerCapabilities.sh."
  type        = bool
  default     = true
}

variable "deploy_rbac_test_fixtures" {
  description = "Create namespace + Role/RoleBinding for ../../AKS-rbac.sh (pods/exec on a dedicated ServiceAccount)."
  type        = bool
  default     = true
}

variable "capability_test_namespace" {
  description = "Namespace for capability test pods (PSA enforce=privileged)."
  type        = string
  default     = "kube-rbac-polp-cap-test"
}

variable "rbac_test_namespace" {
  description = "Namespace for RBAC test RoleBinding (must not collide with capability_test_namespace)."
  type        = string
  default     = "kube-rbac-polp-rbac-test"
}

variable "capability_test_pause_image" {
  description = "Minimal image for main containers in test Deployments."
  type        = string
  default     = "registry.k8s.io/pause:3.9"
}

variable "capability_test_init_container_image" {
  description = "Image for init containers that must exit 0."
  type        = string
  default     = "docker.io/library/busybox:1.36"
}

variable "tags" {
  description = "Tags applied to the resource group and AKS cluster."
  type        = map(string)
  default     = {}
}
