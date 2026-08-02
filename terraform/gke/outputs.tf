output "project_id" {
  description = "GCP project ID."
  value       = var.project_id
}

output "cluster_name" {
  description = "GKE cluster name (for GKE_CLUSTER_NAME and kubectl)."
  value       = google_container_cluster.this.name
}

output "zone" {
  description = "Cluster zone (use as GKE_LOCATION for zonal clusters)."
  value       = var.zone
}

output "region" {
  description = "GCP region."
  value       = var.region
}

output "get_credentials" {
  description = "Shell command to configure kubectl."
  value       = "gcloud container clusters get-credentials ${google_container_cluster.this.name} --zone ${var.zone} --project ${var.project_id}"
}

output "run_rbac_audit" {
  description = "Example env + command for GKE-rbac.sh (check 2 IAM + full audit)."
  value       = <<-EOT
    export GKE_PROJECT="${var.project_id}"
    export GKE_CLUSTER_NAME="${google_container_cluster.this.name}"
    export GKE_LOCATION="${var.zone}"
    gcloud container clusters get-credentials ${google_container_cluster.this.name} --zone ${var.zone} --project ${var.project_id}
    ../../GKE-rbac.sh --quiet
  EOT
}

output "capability_test_namespace" {
  description = "Namespace created for GKE-ContainerCapabilities.sh fixtures (empty if deploy_capability_test_workloads is false)."
  value       = var.deploy_capability_test_workloads ? var.capability_test_namespace : ""
}

output "rbac_test_namespace" {
  description = "Namespace for RBAC fixtures (empty if deploy_rbac_test_fixtures is false)."
  value       = var.deploy_rbac_test_fixtures ? var.rbac_test_namespace : ""
}

output "run_container_capabilities_audit" {
  description = "Example command for GKE-ContainerCapabilities.sh after kubectl is configured."
  value       = <<-EOT
    gcloud container clusters get-credentials ${google_container_cluster.this.name} --zone ${var.zone} --project ${var.project_id}
    ../../GKE-ContainerCapabilities.sh
  EOT
}

output "endpoint" {
  description = "Kubernetes API endpoint (sensitive)."
  value       = google_container_cluster.this.endpoint
  sensitive   = true
}
