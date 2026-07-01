variable "kubeconfig_path" {
  description = "Path to kubeconfig (your existing local cluster, e.g. kind/minikube/k3d)."
  type        = string
  default     = "~/.kube/config"
}

variable "kube_context" {
  description = "kubectl context name; leave empty to use the current default context from kubeconfig."
  type        = string
  default     = ""
}

variable "deploy_capability_test_workloads" {
  description = "Namespace + Deployments for Vanilla-ContainerCapabilities.sh (caps, init vs main, automount, runAsNonRoot)."
  type        = bool
  default     = true
}

variable "capability_test_namespace" {
  description = "Namespace for capability fixtures (PSA enforce=privileged for broad compatibility on local clusters)."
  type        = string
  default     = "kube-rbac-polp-local-cap-test"
}

variable "capability_test_pause_image" {
  description = "Image for main containers (must be pullable by your local nodes)."
  type        = string
  default     = "registry.k8s.io/pause:3.9"
}

variable "capability_test_init_container_image" {
  description = "Image for init containers that must exit 0 (not pause, which runs forever)."
  type        = string
  default     = "docker.io/library/busybox:1.36"
}

variable "deploy_rbac_test_fixtures" {
  description = "Namespace + Role/RoleBinding (pods/exec) so Vanilla-RBAC.sh reports at least one intentional non-system finding."
  type        = bool
  default     = true
}

variable "rbac_test_namespace" {
  description = "Namespace for RBAC fixtures."
  type        = string
  default     = "kube-rbac-polp-local-rbac-test"
}
