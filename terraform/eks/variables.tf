variable "aws_region" {
  description = "AWS region for EKS and supporting resources."
  type        = string
  default     = "us-east-1"
}

variable "cluster_name" {
  description = "EKS cluster name."
  type        = string
  default     = "kube-rbac-polp-eks-test"
}

variable "cluster_version" {
  description = "Kubernetes version for the EKS control plane."
  type        = string
  default     = "1.31"
}

variable "cluster_endpoint_public_access" {
  description = "If true, the Kubernetes API is reachable from the internet (lab convenience; tighten for production)."
  type        = bool
  default     = true
}

variable "vpc_cidr" {
  description = "IPv4 CIDR for the lab VPC."
  type        = string
  default     = "10.0.0.0/16"
}

variable "node_instance_type" {
  description = "Instance type for the single managed node group."
  type        = string
  default     = "t3.small"
}

variable "node_disk_size" {
  description = "Root volume size (GiB) for managed nodes."
  type        = number
  default     = 30
}

variable "deploy_capability_test_workloads" {
  description = "Create namespace and Deployments for ../../EKS-ContainerCapabilities.sh (caps, init vs main, automount, runAsNonRoot)."
  type        = bool
  default     = true
}

variable "deploy_rbac_test_fixtures" {
  description = "Create namespace + Role/RoleBinding for ../../EKS-rbac.sh (pods/exec on a dedicated ServiceAccount)."
  type        = bool
  default     = true
}

variable "deploy_irsa_demo" {
  description = "Create an IAM role + annotated ServiceAccount + pause Deployment in the capability namespace (requires deploy_capability_test_workloads)."
  type        = bool
  default     = true

  validation {
    condition     = !var.deploy_irsa_demo || var.deploy_capability_test_workloads
    error_message = "deploy_irsa_demo requires deploy_capability_test_workloads (IRSA demo uses the capability test namespace)."
  }
}

variable "capability_test_namespace" {
  description = "Namespace for capability test pods (PSA enforce=privileged so fixtures schedule cleanly)."
  type        = string
  default     = "kube-rbac-polp-cap-test"
}

variable "rbac_test_namespace" {
  description = "Namespace for RBAC test RoleBinding (must not collide with capability_test_namespace)."
  type        = string
  default     = "kube-rbac-polp-rbac-test"
}

variable "irsa_demo_service_account_name" {
  description = "Kubernetes ServiceAccount name for the IRSA demo workload."
  type        = string
  default     = "kube-rbac-polp-irsa-demo-sa"
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
  description = "Extra tags applied to supported AWS resources."
  type        = map(string)
  default     = {}
}

variable "az_count" {
  description = "Number of availability zones (2 is enough for EKS + NAT)."
  type        = number
  default     = 2

  validation {
    condition     = var.az_count >= 2 && var.az_count <= 4
    error_message = "az_count must be between 2 and 4."
  }
}

variable "single_nat_gateway" {
  description = "Use one NAT gateway for the VPC (cheaper lab default)."
  type        = bool
  default     = true
}
