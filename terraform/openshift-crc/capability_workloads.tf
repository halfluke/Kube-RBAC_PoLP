# Fixtures for ../../OpenShift-ContainerCapabilities.sh: caps add/drop, init vs app,
# automountServiceAccountToken, runAsNonRoot / allowPrivilegeEscalation, and
# declared-spec escape-chain pairs (NET_* + hostNetwork; MKNOD + writable /dev hostPath).
# Elevated workloads use openshift-cap-privileged-sa (privileged SCC); automount-nonroot
# stays on the namespace default SA without that SCC.
# Targets an existing CRC cluster; Terraform does not create the cluster.

resource "kubernetes_namespace" "cap_test" {
  count = var.deploy_capability_test_workloads ? 1 : 0

  metadata {
    name = var.capability_test_namespace
    labels = {
      "pod-security.kubernetes.io/enforce" = "privileged"
      "pod-security.kubernetes.io/audit"   = "restricted"
      "pod-security.kubernetes.io/warn"    = "restricted"
    }
  }

  # OpenShift injects SCC/UID annotations after create; do not fight them.
  lifecycle {
    ignore_changes = [metadata[0].annotations]
  }
}

resource "kubernetes_deployment" "cap_net_admin" {
  count = var.deploy_capability_test_workloads ? 1 : 0

  metadata {
    name      = "cap-test-net-admin"
    namespace = var.capability_test_namespace
    labels    = { "app.kubernetes.io/name" = "cap-test-net-admin" }
  }

  spec {
    replicas = 1
    selector {
      match_labels = { "app.kubernetes.io/name" = "cap-test-net-admin" }
    }
    template {
      metadata {
        labels = { "app.kubernetes.io/name" = "cap-test-net-admin" }
      }
      spec {
        service_account_name = kubernetes_service_account.cap_privileged[0].metadata[0].name
        container {
          name  = "main"
          image = var.capability_test_pause_image
          security_context {
            capabilities {
              add = ["NET_ADMIN"]
            }
          }
        }
      }
    }
  }

  depends_on = [
    kubernetes_namespace.cap_test,
    kubernetes_cluster_role_binding.cap_privileged_scc,
  ]
}

resource "kubernetes_deployment" "cap_baseline_privileged" {
  count = var.deploy_capability_test_workloads ? 1 : 0

  metadata {
    name      = "cap-test-chown-dac"
    namespace = var.capability_test_namespace
    labels    = { "app.kubernetes.io/name" = "cap-test-chown-dac" }
  }

  spec {
    replicas = 1
    selector {
      match_labels = { "app.kubernetes.io/name" = "cap-test-chown-dac" }
    }
    template {
      metadata {
        labels = { "app.kubernetes.io/name" = "cap-test-chown-dac" }
      }
      spec {
        service_account_name = kubernetes_service_account.cap_privileged[0].metadata[0].name
        container {
          name  = "main"
          image = var.capability_test_pause_image
          security_context {
            capabilities {
              add = ["CHOWN", "DAC_OVERRIDE"]
            }
          }
        }
      }
    }
  }

  depends_on = [
    kubernetes_namespace.cap_test,
    kubernetes_cluster_role_binding.cap_privileged_scc,
  ]
}

resource "kubernetes_deployment" "cap_drop_all_net_bind" {
  count = var.deploy_capability_test_workloads ? 1 : 0

  metadata {
    name      = "cap-test-drop-all-net-bind"
    namespace = var.capability_test_namespace
    labels    = { "app.kubernetes.io/name" = "cap-test-drop-all-net-bind" }
  }

  spec {
    replicas = 1
    selector {
      match_labels = { "app.kubernetes.io/name" = "cap-test-drop-all-net-bind" }
    }
    template {
      metadata {
        labels = { "app.kubernetes.io/name" = "cap-test-drop-all-net-bind" }
      }
      spec {
        service_account_name = kubernetes_service_account.cap_privileged[0].metadata[0].name
        container {
          name  = "main"
          image = var.capability_test_pause_image
          security_context {
            capabilities {
              drop = ["ALL"]
              add  = ["NET_BIND_SERVICE"]
            }
          }
        }
      }
    }
  }

  depends_on = [
    kubernetes_namespace.cap_test,
    kubernetes_cluster_role_binding.cap_privileged_scc,
  ]
}

resource "kubernetes_deployment" "cap_init_vs_main" {
  count = var.deploy_capability_test_workloads ? 1 : 0

  metadata {
    name      = "cap-test-init-mknod"
    namespace = var.capability_test_namespace
    labels    = { "app.kubernetes.io/name" = "cap-test-init-mknod" }
  }

  spec {
    replicas = 1
    selector {
      match_labels = { "app.kubernetes.io/name" = "cap-test-init-mknod" }
    }
    template {
      metadata {
        labels = { "app.kubernetes.io/name" = "cap-test-init-mknod" }
      }
      spec {
        service_account_name = kubernetes_service_account.cap_privileged[0].metadata[0].name
        init_container {
          name    = "init-caps"
          image   = var.capability_test_init_container_image
          command = ["/bin/sh", "-c", "exit 0"]
          security_context {
            capabilities {
              add = ["MKNOD"]
            }
          }
        }
        container {
          name  = "main"
          image = var.capability_test_pause_image
        }
      }
    }
  }

  depends_on = [
    kubernetes_namespace.cap_test,
    kubernetes_cluster_role_binding.cap_privileged_scc,
  ]
}

resource "kubernetes_deployment" "cap_automount_nonroot" {
  count = var.deploy_capability_test_workloads ? 1 : 0

  metadata {
    name      = "cap-test-automount-nonroot"
    namespace = var.capability_test_namespace
    labels    = { "app.kubernetes.io/name" = "cap-test-automount-nonroot" }
  }

  spec {
    replicas = 1
    selector {
      match_labels = { "app.kubernetes.io/name" = "cap-test-automount-nonroot" }
    }
    template {
      metadata {
        labels = { "app.kubernetes.io/name" = "cap-test-automount-nonroot" }
      }
      spec {
        # Default SA — no privileged SCC. Omit fixed UIDs: OpenShift restricted
        # assigns a UID from the namespace range (hardcoded 65534 is rejected).
        automount_service_account_token = false
        security_context {
          run_as_non_root = true
        }
        container {
          name  = "main"
          image = var.capability_test_pause_image
          security_context {
            allow_privilege_escalation = false
            run_as_non_root            = true
          }
        }
      }
    }
  }

  depends_on = [kubernetes_namespace.cap_test]
}

# Escape-chain fixture: NET_ADMIN + hostNetwork (OpenShift-ContainerCapabilities check_escape_chains).
resource "kubernetes_deployment" "cap_escape_net_hostnetwork" {
  count = var.deploy_capability_test_workloads ? 1 : 0

  metadata {
    name      = "cap-test-escape-net-hostnetwork"
    namespace = var.capability_test_namespace
    labels    = { "app.kubernetes.io/name" = "cap-test-escape-net-hostnetwork" }
  }

  spec {
    replicas = 1
    selector {
      match_labels = { "app.kubernetes.io/name" = "cap-test-escape-net-hostnetwork" }
    }
    template {
      metadata {
        labels = { "app.kubernetes.io/name" = "cap-test-escape-net-hostnetwork" }
      }
      spec {
        service_account_name = kubernetes_service_account.cap_privileged[0].metadata[0].name
        host_network         = true
        container {
          name  = "main"
          image = var.capability_test_pause_image
          security_context {
            capabilities {
              add = ["NET_ADMIN"]
            }
          }
        }
      }
    }
  }

  depends_on = [
    kubernetes_namespace.cap_test,
    kubernetes_cluster_role_binding.cap_privileged_scc,
  ]
}

# Escape-chain fixture: MKNOD + writable /dev hostPath mount.
resource "kubernetes_deployment" "cap_escape_mknod_dev_hostpath" {
  count = var.deploy_capability_test_workloads ? 1 : 0

  metadata {
    name      = "cap-test-escape-mknod-dev"
    namespace = var.capability_test_namespace
    labels    = { "app.kubernetes.io/name" = "cap-test-escape-mknod-dev" }
  }

  spec {
    replicas = 1
    selector {
      match_labels = { "app.kubernetes.io/name" = "cap-test-escape-mknod-dev" }
    }
    template {
      metadata {
        labels = { "app.kubernetes.io/name" = "cap-test-escape-mknod-dev" }
      }
      spec {
        service_account_name = kubernetes_service_account.cap_privileged[0].metadata[0].name
        volume {
          name = "dev-host"
          host_path {
            path = "/dev"
            type = "Directory"
          }
        }
        container {
          name  = "main"
          image = var.capability_test_pause_image
          volume_mount {
            name       = "dev-host"
            mount_path = "/dev"
            read_only  = false
          }
          security_context {
            capabilities {
              add = ["MKNOD"]
            }
          }
        }
      }
    }
  }

  depends_on = [
    kubernetes_namespace.cap_test,
    kubernetes_cluster_role_binding.cap_privileged_scc,
  ]
}
