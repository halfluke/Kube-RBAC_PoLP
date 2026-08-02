# Intentional Role + RoleBinding for ../../GKE-rbac.sh (pods/exec create on a non-system SA).

resource "kubernetes_namespace" "rbac_test" {
  count = var.deploy_rbac_test_fixtures ? 1 : 0

  metadata {
    name = var.rbac_test_namespace
  }

  depends_on = [google_container_node_pool.primary]
}

resource "kubernetes_service_account" "rbac_audit" {
  count = var.deploy_rbac_test_fixtures ? 1 : 0

  metadata {
    name      = "vanilla-rbac-audit-sa"
    namespace = var.rbac_test_namespace
  }

  depends_on = [kubernetes_namespace.rbac_test]
}

resource "kubernetes_role" "pods_exec" {
  count = var.deploy_rbac_test_fixtures ? 1 : 0

  metadata {
    name      = "vanilla-rbac-test-pods-exec"
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
    name      = "vanilla-rbac-test-pods-exec"
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
