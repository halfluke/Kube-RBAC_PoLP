# Kube-RBAC_PoLP

**Testing disclaimer:** These scripts have been exercised **only in local Kubernetes environments** and, **partially**, on **OpenShift** (an **earlier** version of the repo). They have **not** yet been fully validated on **AKS, EKS, or GKE**; **planned** testing on those platforms is expected **within a reasonable timeframe**. Treat cloud-specific paths and Terraform stacks accordingly.

Shell-based **Kubernetes security audits** focused on **RBAC** and **workload security posture** (PSA labels, pod security context, Linux capabilities, and cloud-specific identity hints). Optional **Terraform** stacks provision short-lived clusters and apply test fixtures.

These tools are intended for **analysis, education, and lab environments**. They do not replace cloud IAM reviews, admission controllers, or organizational policy.

---

## Quickstart

```bash
cd /path/to/Kube-RBAC_PoLP
chmod +x *.sh   # once, if needed
```

1) Configure cluster access so `kubectl get ns` succeeds (see Requirements section for EKS/GKE/AKS examples).  
2) Pick the script matching your target.  
3) Start with:

```bash
./Vanilla-RBAC.sh --quiet
./Vanilla-ContainerCapabilities.sh --output text
```

For cloud targets, use the cloud-specific script variants (`EKS-*`, `GKE-*`, `AKS-*`).

---

## Script guide

### RBAC audit scripts

| Script | Target | Scope |
|--------|--------|--------|
| `Vanilla-RBAC.sh` | Local / lab Kubernetes (kubectl) | Checks **1–19**: core RBAC plus token minting, enhanced wildcards, sensitive subresources, CRD heuristics, default-SA bindings, workload cross-reference; **no** provider IAM |
| `EKS-rbac.sh` | EKS-oriented cluster | Full check catalogue including EKS **`aws-auth`** scan (Check 2) and IRSA demo support in Terraform |
| `GKE-rbac.sh` | GKE-oriented cluster | Full catalogue + optional **GCP cluster IAM** (Check 2) + GKE Workload Identity (Check 22) |
| `AKS-rbac.sh` | AKS-oriented cluster | Full catalogue + optional **Azure RBAC on the cluster resource** (Check 2) + Azure WI (Check 22) |
| `OpenShift-RBAC.sh` | OpenShift | Same CLI style as Vanilla-RBAC; uses **`oc`**; OpenShift-focused namespace defaults |

RBAC scripts answer: **who can perform high-risk API actions** (cluster-admin, secrets, exec, token minting, wildcards, CRD exposure heuristics, etc.). Each script documents semantics in its file header (bindings, `via =/≠`, excluded namespaces).

### Container capabilities / PSA scripts

| Script | Target | Notes |
|--------|--------|--------|
| `Vanilla-ContainerCapabilities.sh` | Generic Kubernetes | PSA labels + pod spec; **no** cloud identity column |
| `EKS-ContainerCapabilities.sh` | EKS | + **IRSA** role ARN hint (pod or ServiceAccount) |
| `GKE-ContainerCapabilities.sh` | GKE | + **GKE Workload Identity** annotation; optional Autopilot `[INFO]` |
| `AKS-ContainerCapabilities.sh` | AKS | + **Azure Workload Identity** client-id; optional AKS node `[INFO]` |
| `OpenShift-ContainerCapabilities.sh` | OpenShift | **SCC**-aware flow; uses **`oc`** and a bundled **`./jq-linux-amd64`**; different flags (`--scc-matching`) |

These scripts inspect **declared** pod/namespace state. They are **not** full admission-controller or runtime-enforcement audits; each run prints an `[INFO]` line stating that (and that cloud identity columns are in-cluster hints, not cloud IAM).

---

## Other scripts (quick reference)

`ControlPlane_WorkerNodes_fromAllPods.sh` probes node ports from all running pods and reports whether access is blocked, auth-gated, or exposed.

- Uses `oc` when available, else `kubectl`.
- Requires `jq`, `curl`, `timeout`; supports `--namespaces`, `--output`, timeout flags, and `--max-pods`.
- Modes: `full` (control-plane + worker checks) and `worker_only` (worker checks only).
- Outputs human table or JSONL; high-risk `EXPOSED` findings are clearly highlighted.
- For full status taxonomy and probe logic, see the script header comments.

---

### Subject access verifier

`check_subject_access.sh` evaluates effective RBAC exposure for a specific subject (`User`, `Group`, or `ServiceAccount`) and flags high-risk privilege patterns.

- Uses `oc` when available, else `kubectl`.
- Core inputs: `--kind`, `--name`; optional namespace/groups/output controls.
- Resolves effective bindings and rules, then emits high-risk findings (`cluster-admin`, wildcards, `bind`, `escalate`, impersonation, secret access, etc.).
- Exits `1` when high-risk findings are present, `0` otherwise.

---

### Endpoint connectivity sweep

`network_segreg_via_endpoints.sh` performs namespace-to-endpoint connectivity checks by selecting one running curl-capable source pod per namespace, then probing discovered service endpoints.

- Uses `oc` when available, else `kubectl`.
- Selects one curl-capable source pod per namespace and probes discovered endpoints.
- Reports `EXPOSED`, `BLOCKED_OR_UNREACHABLE`, `DENIED_WITHOUT_CREDS`, and `TEST_ERROR` with per-pod and cluster-wide summaries.
- Includes additive NetworkPolicy/plugin metadata for triage (not a full enforcement proof).

---

## Requirements

### On your workstation

- **Bash** (scripts use `#!/usr/bin/env bash` or `#!/bin/bash`).
- **`kubectl`** on `PATH` for all scripts **except** OpenShift variants (those use **`oc`**).
- **`jq`** on `PATH` for JSON parsing (RBAC + most capabilities scripts).

### Optional (by script / check)

| Need | Used for |
|------|-----------|
| **AWS CLI** | `aws eks update-kubeconfig` (EKS); EKS Terraform kubernetes provider exec |
| **Google Cloud SDK (`gcloud`)** | Cluster credentials; **GKE-rbac.sh Check 2** (`GKE_*` env vars) |
| **Azure CLI (`az`)** | Cluster credentials; **AKS-rbac.sh Check 2** (`AKS_*` env vars) |
| **`terraform`** | Provisioning lab clusters and fixtures under `terraform/` |

### Cluster access

- A **kubeconfig** with a context that can **list namespaces** and **read** RBAC and workload objects (exact verbs depend on your role). The capabilities scripts fail early if `kubectl get ns` fails.

### Configure `kubectl` for cloud clusters (EKS / GKE / AKS)

If you’re targeting a managed cloud cluster, first ensure your kubeconfig has a working context for that cluster.

**EKS (AWS)**

```bash
aws eks update-kubeconfig --name <cluster-name> --region <region>
kubectl config current-context
kubectl get ns
```

**GKE (GCP)**

```bash
gcloud container clusters get-credentials <cluster-name> --location <zone-or-region> --project <project-id>
kubectl config current-context
kubectl get ns
```

**AKS (Azure)**

```bash
az aks get-credentials --resource-group <rg> --name <cluster-name>
kubectl config current-context
kubectl get ns
```

Notes:

- If you manage multiple kubeconfigs, use `KUBECONFIG=/path/to/kubeconfig` (or merge contexts) before running scripts.
- If `kubectl get ns` fails, fix auth first (cloud login, exec plugin, expired tokens, wrong subscription/project, etc.)—the scripts assume basic API access is already working.

### OpenShift-only

- **`oc`** authenticated to the cluster (`OC` env var overrides the binary path; default `oc`).
- **`OpenShift-ContainerCapabilities.sh`:** expects **`./jq-linux-amd64`** in the repo directory (as noted in the script).

---

## How to run (from repository root)

### RBAC scripts

```bash
./Vanilla-RBAC.sh --help
./Vanilla-RBAC.sh --quiet
./Vanilla-RBAC.sh --list-checks
./Vanilla-RBAC.sh --checks=1,3-5
```

The same flag style applies to **`EKS-rbac.sh`**, **`GKE-rbac.sh`**, **`AKS-rbac.sh`**, and **`OpenShift-RBAC.sh`**: `--checks`, `--list` / `--list-checks`, `--quiet`, `--critical`, `--debug-check20`, `--debug-check21`, `-h` / `--help`. **`Vanilla-RBAC.sh`** uses **`--debug-check18`** / **`--debug-check19`** for its workload-binding diagnostics (see `--help`).

To confirm context quickly before any run:

```bash
kubectl config current-context
kubectl get ns
```

**Override kubectl binary (RBAC scripts that use `K=`):**

```bash
K=/path/to/kubectl ./EKS-rbac.sh --quiet
```

**OpenShift RBAC** uses **`oc`**:

```bash
OC=/path/to/oc ./OpenShift-RBAC.sh --quiet
```

**Optional Check 2 environment variables**

- **GKE:** `GKE_PROJECT`, `GKE_CLUSTER_NAME`, `GKE_LOCATION` (region or zone matching your cluster type).
- **AKS:** `AKS_RESOURCE_GROUP`, `AKS_CLUSTER_NAME`, optional `AKS_SUBSCRIPTION_ID` (else active `az account`).

### Container capabilities scripts

```bash
./Vanilla-ContainerCapabilities.sh
./Vanilla-ContainerCapabilities.sh --only-user-ns --output text
./EKS-ContainerCapabilities.sh --output json
```

Flags: `--only-user-ns`, `--output text|csv|json`, `--debug` (where supported). **`OpenShift-ContainerCapabilities.sh`** also supports `--scc-matching v1|v2` (see script header).

---

## Terraform lab stacks

Under **`terraform/`**, each directory is a **standalone** root module (run commands from that directory).

| Directory | Creates cluster? | Purpose |
|-----------|------------------|---------|
| `terraform/eks/` | Yes (EKS + VPC) | Fixtures for `EKS-rbac.sh`, `EKS-ContainerCapabilities.sh`; optional IRSA demo |
| `terraform/gke/` | Yes (GKE) | Fixtures for `GKE-rbac.sh`, `Vanilla-ContainerCapabilities.sh` |
| `terraform/aks/` | Yes (AKS) | Fixtures for `AKS-rbac.sh`, `AKS-ContainerCapabilities.sh` |
| `terraform/local-vanilla/` | No | Applies fixtures to **existing** cluster via kubeconfig |

Typical workflow:

```bash
cd terraform/<stack>
cp terraform.tfvars.example terraform.tfvars   # if present; edit values
terraform init
terraform apply
terraform output -raw configure_kubectl        # or get_credentials / equivalent
cd ../..
./<Matching-rbac-script>.sh --quiet
```

- **`terraform.tfvars`** is gitignored; use `*.example` files as templates.
- See each stack’s **`outputs.tf`** for copy-paste **`run_rbac_audit`** / **`run_container_capabilities_audit`** examples (including exports for GKE/AKS Check 2).
- If Terraform prints a kubeconfig command, run it first, then confirm:

```bash
kubectl config current-context
kubectl get ns
```

---

## Details appendix

**RBAC performance note (`Vanilla-RBAC.sh`)**

- Checks **3–19** reuse one prefetch of RBAC objects.
- `--checks=1` and/or `2` skips that prefetch path.

**Cloud “Check 2” scope**

- **EKS:** reads **`kube-system/aws-auth`** mappings to **`system:masters`** (not a full AWS/EKS IAM inventory).
- **GKE:** queries cluster IAM policy (`roles/container.clusterAdmin`, `roles/container.admin`) on the cluster resource; parent-level bindings may not appear.
- **AKS:** queries role assignments at managed-cluster ARM scope; not a complete map of Azure authorization paths.
- Scripts print a short scope line for Check 2 (unless `--quiet`).

---

## Limitations (summary)

- RBAC audits reflect **Kubernetes RBAC** (plus the **documented** cloud slices for Check 2 on GKE/AKS, and **aws-auth** on EKS). They are not complete cloud IAM inventories.
- Capabilities scripts use **pod spec + namespace labels**, not live admission results.
- Terraform configs are for **labs** (e.g. single-node pools, permissive test namespaces). Harden before production use.

For full behavior, semantics, and check IDs, use **`--help`** and **`--list-checks`** on each RBAC script and read the **header comments** at the top of each file.
