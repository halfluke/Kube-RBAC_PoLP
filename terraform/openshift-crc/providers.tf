provider "kubernetes" {
  config_path = pathexpand(var.kubeconfig_path)

  # Omit when empty so the kubeconfig's current-context is used.
  config_context = var.kube_context != "" ? var.kube_context : null
}
