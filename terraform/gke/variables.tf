variable "project_id" {
  description = "GCP project ID where the test cluster will run."
  type        = string
}

variable "region" {
  description = "GCP region (used for provider default and outputs)."
  type        = string
  default     = "us-central1"
}

variable "zone" {
  description = "GCP zone for the zonal cluster (cheaper for short-lived tests)."
  type        = string
  default     = "us-central1-a"
}

variable "cluster_name" {
  description = "GKE cluster name."
  type        = string
  default     = "kube-rbac-polp-gke-test"
}

variable "machine_type" {
  description = "Machine type for the single-node pool."
  type        = string
  default     = "e2-small"
}

variable "disk_size_gb" {
  description = "Boot disk size per node (GB)."
  type        = number
  default     = 30
}

variable "deploy_capability_test_workloads" {
  description = "Create a namespace and Deployments that exercise GKE-ContainerCapabilities.sh (caps add/drop, init vs app, automount, runAsNonRoot)."
  type        = bool
  default     = true
}

variable "capability_test_namespace" {
  description = "Namespace for capability test pods (PSA enforce=privileged so examples schedule on default GKE admission)."
  type        = string
  default     = "kube-rbac-polp-cap-test"
}

variable "deploy_rbac_test_fixtures" {
  description = "Create namespace + Role/RoleBinding for ../../GKE-rbac.sh (pods/exec on a dedicated ServiceAccount)."
  type        = bool
  default     = true
}

variable "rbac_test_namespace" {
  description = "Namespace for RBAC test RoleBinding (must not collide with capability_test_namespace)."
  type        = string
  default     = "kube-rbac-polp-rbac-test"
}

variable "capability_test_pause_image" {
  description = "Minimal image for main containers in test Deployments (must exist on nodes / pullable)."
  type        = string
  default     = "registry.k8s.io/pause:3.9"
}

variable "capability_test_init_container_image" {
  description = "Image for init containers that must exit 0 (not pause, which runs forever)."
  type        = string
  default     = "docker.io/library/busybox:1.36"
}
