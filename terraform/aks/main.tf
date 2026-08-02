# Lab AKS cluster for ../../AKS-rbac.sh and ../../AKS-ContainerCapabilities.sh fixtures.
#
# Requires: Azure credentials (e.g. az login), subscription access, and quotas for AKS in the region.
# Kubernetes provider uses cluster-admin kube_config from the created cluster (no kubelogin needed for apply).
# For kubectl after apply: az aks get-credentials --resource-group <rg> --name <cluster>

provider "azurerm" {
  features {}

  # "all" registers every RP on first plan (very slow). "core" is enough for this AKS lab.
  resource_provider_registrations = "core"
}

resource "azurerm_resource_group" "this" {
  name     = var.resource_group_name
  location = var.location
  tags     = var.tags
}

resource "azurerm_kubernetes_cluster" "this" {
  name                = var.cluster_name
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  dns_prefix          = var.dns_prefix != "" ? var.dns_prefix : var.cluster_name
  kubernetes_version  = var.kubernetes_version

  default_node_pool {
    name            = "default"
    node_count      = var.node_count
    vm_size         = var.vm_size
    os_disk_size_gb = var.os_disk_size_gb
  }

  identity {
    type = "SystemAssigned"
  }

  sku_tier = "Free"

  tags = var.tags
}
