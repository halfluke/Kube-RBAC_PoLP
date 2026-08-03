output "kube_context_used" {
  description = "Context passed to the provider; empty means kubeconfig current-context."
  value       = var.kube_context
}

output "capability_test_namespace" {
  description = "Namespace for OpenShift-ContainerCapabilities.sh fixtures."
  value       = var.deploy_capability_test_workloads ? var.capability_test_namespace : ""
}

output "rbac_test_namespace" {
  description = "Namespace for OpenShift-RBAC.sh fixtures."
  value       = var.deploy_rbac_test_fixtures ? var.rbac_test_namespace : ""
}

output "run_scripts_from_repo_root" {
  description = "Run with oc pointed at the same CRC cluster/context Terraform used (kubeadmin recommended for audits)."
  value       = <<-EOT
    cd ../..
    ./OpenShift-RBAC.sh --quiet
    ./OpenShift-ContainerCapabilities.sh --only-user-ns --output text
  EOT
}
