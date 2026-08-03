# Intentional Role + RoleBinding for ../../OpenShift-RBAC.sh (pods/exec create on a non-system SA).
# Targets an existing CRC cluster; Terraform does not create the cluster.

resource "kubernetes_namespace" "rbac_test" {
  count = var.deploy_rbac_test_fixtures ? 1 : 0

  metadata {
    name = var.rbac_test_namespace
  }

  # OpenShift injects SCC/UID annotations after create; do not fight them.
  lifecycle {
    ignore_changes = [metadata[0].annotations]
  }
}

resource "kubernetes_service_account" "rbac_audit" {
  count = var.deploy_rbac_test_fixtures ? 1 : 0

  metadata {
    name      = "openshift-rbac-audit-sa"
    namespace = var.rbac_test_namespace
  }

  # OpenShift adds dockercfg pull secrets/annotations after create.
  lifecycle {
    ignore_changes = [
      metadata[0].annotations,
      image_pull_secret,
      secret,
    ]
  }

  depends_on = [kubernetes_namespace.rbac_test]
}

resource "kubernetes_role" "pods_exec" {
  count = var.deploy_rbac_test_fixtures ? 1 : 0

  metadata {
    name      = "openshift-rbac-test-pods-exec"
    namespace = var.rbac_test_namespace
  }

  rule {
    api_groups = [""]
    resources  = ["pods/exec"]
    verbs      = ["create"]
  }

  depends_on = [kubernetes_namespace.rbac_test]
}

resource "kubernetes_role_binding" "pods_exec" {
  count = var.deploy_rbac_test_fixtures ? 1 : 0

  metadata {
    name      = "openshift-rbac-test-pods-exec"
    namespace = var.rbac_test_namespace
  }

  role_ref {
    api_group = "rbac.authorization.k8s.io"
    kind      = "Role"
    name      = kubernetes_role.pods_exec[0].metadata[0].name
  }

  subject {
    kind      = "ServiceAccount"
    name      = kubernetes_service_account.rbac_audit[0].metadata[0].name
    namespace = var.rbac_test_namespace
  }

  depends_on = [
    kubernetes_role.pods_exec,
    kubernetes_service_account.rbac_audit,
  ]
}
