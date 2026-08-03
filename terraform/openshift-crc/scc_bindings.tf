# Grant privileged SCC to the dedicated capability SA so hostNetwork / hostPath / elevated
# capabilities can schedule on OpenShift CRC (restricted SCC would block them).

resource "kubernetes_service_account" "cap_privileged" {
  count = var.deploy_capability_test_workloads ? 1 : 0

  metadata {
    name      = "openshift-cap-privileged-sa"
    namespace = var.capability_test_namespace
  }

  # OpenShift adds dockercfg pull secrets/annotations after create.
  lifecycle {
    ignore_changes = [
      metadata[0].annotations,
      image_pull_secret,
      secret,
    ]
  }

  depends_on = [kubernetes_namespace.cap_test]
}

resource "kubernetes_cluster_role_binding" "cap_privileged_scc" {
  count = var.deploy_capability_test_workloads ? 1 : 0

  metadata {
    name = "kube-rbac-polp-crc-cap-privileged-scc"
  }

  role_ref {
    api_group = "rbac.authorization.k8s.io"
    kind      = "ClusterRole"
    name      = "system:openshift:scc:privileged"
  }

  subject {
    kind      = "ServiceAccount"
    name      = kubernetes_service_account.cap_privileged[0].metadata[0].name
    namespace = var.capability_test_namespace
  }

  depends_on = [kubernetes_service_account.cap_privileged]
}
