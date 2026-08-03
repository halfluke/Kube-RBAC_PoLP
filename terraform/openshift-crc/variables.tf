variable "kubeconfig_path" {
  description = "Path to kubeconfig after oc login to CRC as kubeadmin (cluster-admin required for SCC bindings)."
  type        = string
  default     = "~/.kube/config"
}

variable "kube_context" {
  description = "oc/kubectl context name; leave empty to use the current default context from kubeconfig."
  type        = string
  default     = ""
}

variable "deploy_capability_test_workloads" {
  description = "Namespace + Deployments for OpenShift-ContainerCapabilities.sh (caps, init vs main, automount, escape chains)."
  type        = bool
  default     = true
}

variable "capability_test_namespace" {
  description = "Namespace for capability fixtures (SCC privileged SA used for elevated workloads)."
  type        = string
  default     = "kube-rbac-polp-crc-cap-test"
}

variable "capability_test_pause_image" {
  description = "Image for main containers (must be pullable by CRC nodes)."
  type        = string
  default     = "registry.k8s.io/pause:3.9"
}

variable "capability_test_init_container_image" {
  description = "Image for init containers that must exit 0 (not pause, which runs forever)."
  type        = string
  default     = "docker.io/library/busybox:1.36"
}

variable "deploy_rbac_test_fixtures" {
  description = "Namespace + Role/RoleBinding (pods/exec) so OpenShift-RBAC.sh reports at least one intentional non-system finding."
  type        = bool
  default     = true
}

variable "rbac_test_namespace" {
  description = "Namespace for RBAC fixtures."
  type        = string
  default     = "kube-rbac-polp-crc-rbac-test"
}
