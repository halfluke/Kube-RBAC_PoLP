# Kube-RBAC_PoLP

Shell scripts that audit **Kubernetes RBAC** and **workload security** (PSA labels, pod security context, capabilities). Optional **Terraform** under `terraform/` can create a small lab cluster and drop in test workloads.

**Use for labs and learning only** — not a replacement for cloud IAM reviews, admission controllers, or org policy.

**Testing status:** Heavily used on **local Kubernetes** and **OpenShift** (older tree). **AKS**, **GKE**, and **EKS** scripts and their Terraform lab stacks have been validated end-to-end (apply → audits → destroy).

---

## Start here: pick your situation

| You have… | Do this |
|-----------|---------|
| **kubectl already works** (`kubectl get ns` OK) | [Run the audits](#run-the-audits) with **Vanilla-*** scripts (or cloud-named scripts if the cluster is on that cloud). |
| **No cluster — want Azure / AWS / GCP lab** | [Deploy with Terraform](#deploy-a-cloud-lab-with-terraform), then [run the audits](#run-the-audits). |
| **Kind / minikube / home cluster, need test pods only** | `terraform/local-vanilla/` applies fixtures to your kubeconfig (no new cluster). |

---

## What you need on your laptop

| Tool | When |
|------|------|
| **bash**, **kubectl**, **jq** | Almost every script |
| **terraform** | Only if you use `terraform/*` |
| **aws** | EKS kubeconfig + EKS Terraform |
| **gcloud** | GKE kubeconfig + GKE RBAC Check 2 |
| **az** | AKS kubeconfig + AKS RBAC Check 2 |
| **oc** | OpenShift scripts only |

**Cluster access:** Your kubeconfig must be able to list namespaces and read RBAC + pods. Scripts stop early if `kubectl get ns` fails.

**OpenShift:** use `oc` instead of `kubectl`; `OpenShift-ContainerCapabilities.sh` needs `./jq-linux-amd64` in the repo root.

---

## Deploy a cloud lab with Terraform

Each folder under `terraform/` is **independent**. Always run Terraform **from that folder**, not the repo root.

### Steps (same for EKS, GKE, AKS)

1. **Log in to the cloud** (see [cloud login](#cloud-login-one-liners) below).
2. **Copy settings:** `cp terraform.tfvars.example terraform.tfvars` and edit (region, names, `project_id` on GKE).
3. **Install infra:** `terraform init` → `terraform plan` → `terraform apply` (often **10–20+ minutes** for a new cluster).
4. **Connect kubectl:** run the command from `terraform output` (see [after apply](#after-terraform-apply)).
5. **Run scripts** from the [repo root](#run-the-audits).
6. **Tear down when done:** `terraform destroy` (stops cloud charges).

`terraform.tfvars` is gitignored. By default, **RBAC + capability test fixtures** are deployed (including intentional “bad” examples like `pods/exec` and escape-chain pods).

> **`terraform output run_rbac_audit`** only **prints** a copy/paste recipe; it does not run commands for you.

### Cloud login (one-liners)

| Cloud | Before `terraform apply` |
|-------|---------------------------|
| **Azure (AKS)** | `az login` → `az account show` (switch with `az account set --subscription <id>` if needed) |
| **AWS (EKS)** | `aws configure` or `AWS_PROFILE=...` |
| **GCP (GKE)** | `gcloud auth login` and `gcloud auth application-default login`; enable billing + Container API on your project |

### Choosing a region (AKS, EKS, GKE)

Examples in this repo’s `terraform.tfvars.example` files often default to **US** regions. **Pick a region close to you** (latency, data residency, quota). Your physical location does not auto-configure anything — you set it in `terraform.tfvars`.

| Cloud | Terraform variable | What to set | UK examples (common lab choice) |
|-------|-------------------|-------------|----------------------------------|
| **Azure AKS** | `location` | Azure **region** code | `uksouth` (London), `ukwest` |
| **AWS EKS** | `aws_region` | AWS **region** code | `eu-west-2` (London), `eu-west-1` (Ireland) |
| **GCP GKE** | `zone` (+ `region`) | **Zonal** cluster: zone must belong to `region` | `region = "europe-west2"`, `zone = "europe-west2-a"` (London) |

**Do not** use display-only geography labels (e.g. Azure’s `uk` row from `az account list-locations`) as `location` — use deployable codes like `uksouth`.

**Check the region supports Kubernetes before apply:**

```bash
# AKS
az account list-locations -o table | grep -i uk
az aks get-versions --location uksouth -o table

# EKS (replace region)
aws ec2 describe-regions --region-names eu-west-2 --query 'Regions[0].RegionName' --output text
aws eks describe-cluster-versions --region eu-west-2 --query 'clusterVersions[0:5]' --output table 2>/dev/null || true

# GKE
gcloud compute regions list --filter="name:europe-west2"
gcloud container get-server-config --zone europe-west2-a --format='yaml(validMasterVersions)' 2>/dev/null | head
```

After apply, **kubeconfig and Check 2 env must match the same region/location** you chose (e.g. `aws eks update-kubeconfig --region eu-west-2`, `GKE_LOCATION` = your cluster zone).

Repo default if you change nothing: **AKS** `eastus`, **EKS** `us-east-1`, **GKE** `us-central1` / `us-central1-a` — fine for a lab, but not required.

### Minimal `terraform.tfvars` examples

**AKS** (`terraform/aks/`):

```hcl
location            = "uksouth"   # UK South; or ukwest, eastus, westeurope, …
resource_group_name = "kube-rbac-polp-aks-test-rg"
cluster_name        = "kube-rbac-polp-aks-test"
vm_size             = "Standard_B2s"
```

**EKS** (`terraform/eks/`):

```hcl
aws_region   = "eu-west-2"   # UK (London); or eu-west-1, us-east-1, …
cluster_name = "kube-rbac-polp-eks-test"
```

**GKE** (`terraform/gke/`) — `project_id` is **required**; keep `region` and `zone` aligned:

```hcl
project_id   = "my-gcp-project-id"
region       = "europe-west2"
zone         = "europe-west2-a"   # UK-adjacent; or us-central1 + us-central1-a, …
cluster_name = "kube-rbac-polp-gke-test"
```

More knobs (node size, K8s version, fixture flags) live in each stack’s `variables.tf`.

### After Terraform apply

From the stack directory (e.g. `terraform/aks/`):

```bash
# 1) kubeconfig — use the output name for your stack:
eval "$(terraform output -raw configure_kubectl)"   # AKS, EKS
# GKE uses:
# eval "$(terraform output -raw get_credentials)"

kubectl get ns

# 2) Optional env vars for cloud RBAC “Check 2” (see below)
# AKS:
export AKS_RESOURCE_GROUP="$(terraform output -raw resource_group_name)"
export AKS_CLUSTER_NAME="$(terraform output -raw cluster_name)"
# GKE:
# export GKE_PROJECT="$(terraform output -raw project_id)"
# export GKE_CLUSTER_NAME="$(terraform output -raw cluster_name)"
# export GKE_LOCATION="$(terraform output -raw zone)"
# EKS: Check 2 uses kubectl aws-auth + aws Access Entries (cluster/region from kubeconfig ARN,
# or export EKS_CLUSTER_NAME / AWS_REGION)

# 3) Audits (from repo root)
cd ../..
./AKS-rbac.sh --quiet
./AKS-ContainerCapabilities.sh --output text
```

Swap `AKS-*` for `EKS-*` or `GKE-*` on other clouds.

**Fixtures-only (existing cluster):**

```bash
cd terraform/local-vanilla
terraform init && terraform apply
cd ../..
./Vanilla-RBAC.sh --quiet
./Vanilla-ContainerCapabilities.sh --output text
```

### Terraform stacks at a glance

| Directory | Creates cluster? | Scripts to run after |
|-----------|------------------|----------------------|
| `terraform/aks/` | Yes (AKS) | `AKS-rbac.sh`, `AKS-ContainerCapabilities.sh` |
| `terraform/eks/` | Yes (EKS + VPC) | `EKS-rbac.sh`, `EKS-ContainerCapabilities.sh` |
| `terraform/gke/` | Yes (GKE) | `GKE-rbac.sh`, `GKE-ContainerCapabilities.sh` |
| `terraform/local-vanilla/` | No | `Vanilla-RBAC.sh`, `Vanilla-ContainerCapabilities.sh` |

Useful outputs (all clouds): `configure_kubectl` or `get_credentials`, `capability_test_namespace`, `rbac_test_namespace`, `run_rbac_audit`, `run_container_capabilities_audit`.

---

## Run the audits

Run from the **repository root**. Confirm context first:

```bash
kubectl config current-context
kubectl get ns
```

### Which script pair?

| Your cluster | RBAC | Capabilities / PSA |
|--------------|------|---------------------|
| Generic / local / kind | `Vanilla-RBAC.sh` | `Vanilla-ContainerCapabilities.sh` |
| Amazon EKS | `EKS-rbac.sh` | `EKS-ContainerCapabilities.sh` |
| Google GKE | `GKE-rbac.sh` | `GKE-ContainerCapabilities.sh` |
| Azure AKS | `AKS-rbac.sh` | `AKS-ContainerCapabilities.sh` |
| Red Hat OpenShift | `OpenShift-RBAC.sh` (`oc`) | `OpenShift-ContainerCapabilities.sh` |

**RBAC scripts** answer: *who can do dangerous things?* (cluster-admin, secrets, exec, wildcards, token minting, etc.). High-risk checks may show an **Attack path:** line under `Checking:`.

**Capabilities scripts** answer: *how risky are pods on paper?* (privileged, caps, host namespaces, PSA labels). They read **declared spec**, not live enforcement. **Escape chains** (e.g. caps + `hostNetwork`) print as separate `Escape chain:` lines — they do **not** change the main `Status` severity.

On **EKS / GKE / AKS**, known managed-plane pods (`aws-node` / `kube-proxy`, GKE `netd`, AKS CNI, etc.) still report `CRITICAL`/`HIGH` when the spec warrants it, but Status and escape-chain lines are tagged `[known … platform component — expected on managed nodes]` (annotate, do not hide). Other findings in system namespaces get a milder `[platform namespace workload …]` tag. Use `--only-user-ns` to focus on app/lab namespaces.

### Commands beginners use most

```bash
chmod +x *.sh   # once

./Vanilla-RBAC.sh --help
./Vanilla-RBAC.sh --quiet          # less noise; good first run
./Vanilla-RBAC.sh --list-checks

./Vanilla-ContainerCapabilities.sh --output text
./Vanilla-ContainerCapabilities.sh --only-user-ns --output json
```

Same flags work on `EKS-rbac.sh`, `GKE-rbac.sh`, `AKS-rbac.sh`, `OpenShift-RBAC.sh` (`--checks`, `--quiet`, `--list-checks`, `--help`, …).

**Cloud RBAC Check 2** (extra cloud IAM slice — optional but needs env on GKE/AKS):

| Cloud | Extra env before RBAC script |
|-------|------------------------------|
| EKS | *(usually none)* — `aws-auth` via kubectl; Access Entries via `aws` (cluster/region from kubeconfig ARN or `EKS_CLUSTER_NAME` + `AWS_REGION`) |
| GKE | `GKE_PROJECT` (project IAM; cluster name/location not required for Check 2) |
| AKS | `AKS_RESOURCE_GROUP`, `AKS_CLUSTER_NAME` |

Without those exports, most RBAC checks still run; Check 2 is skipped or thin on GKE/AKS.

**Manual kubeconfig (no Terraform):**

```bash
aws eks update-kubeconfig --name <cluster> --region <aws_region>   # EKS — region must match cluster
gcloud container clusters get-credentials <cluster> --location <zone-or-region> --project <proj>  # GKE
az aks get-credentials --resource-group <rg> --name <cluster>       # AKS
```

---

## Other scripts (optional)

| Script | Purpose |
|--------|---------|
| `check_subject_access.sh` | RBAC risk for one User / Group / ServiceAccount |
| `ControlPlane_WorkerNodes_fromAllPods.sh` | Probe node ports from pods; optional `--check-imds-creds` |
| `network_segreg_via_endpoints.sh` | Namespace → service endpoint reachability sweep |

See each script’s header for flags.

---

## Troubleshooting

### `kubectl get ns` fails (Unauthorized, timeout, connection refused)

- Run **`kubectl config current-context`** — is it the lab cluster, not an old kind/minikube context?
- Re-fetch credentials after apply:
  - AKS/EKS: `eval "$(terraform output -raw configure_kubectl)"` from the correct `terraform/<stack>/` directory
  - GKE: `eval "$(terraform output -raw get_credentials)"`
- **Cloud login expired:** `az login`, `aws sts get-caller-identity`, or `gcloud auth list`.
- **EKS:** `aws eks update-kubeconfig --name … --region …` must use the **same `aws_region`** as Terraform.
- **AKS:** wrong subscription → `az account set --subscription <id>` then get-credentials again.

### Terraform `plan` hangs or ends with Resource Provider registration

**Symptom:** `plan` runs many minutes with little output, or after Ctrl+C you see  
`Encountered an error whilst ensuring Resource Providers are registered` / `Microsoft.EventHub` / `context canceled`.

**Cause:** Azure provider 4.x may try to **register many resource providers** in your subscription on first run. That is slow and can fail if you lack permission or cancel mid-way.

**Fix (this repo):** `terraform/aks/main.tf` sets `resource_provider_registrations = "core"` (not `"all"`) so first `plan` is much faster.

Then:

```bash
cd terraform/aks
rm -f .terraform.tfstate.lock.info
terraform plan
```

**If registration still fails**, disable auto-registration and register AKS providers yourself:

```hcl
# in provider "azurerm" { … }
resource_provider_registrations = "none"
```

```bash
az provider register --namespace Microsoft.ContainerService --wait
az provider register --namespace Microsoft.Compute --wait
az provider register --namespace Microsoft.Network --wait
terraform plan
```

### Terraform `apply` fails (quota, SKU, region)

| Symptom | Things to try |
|---------|----------------|
| **Insufficient quota** (vCPUs, AKS/EKS limits) | Cloud portal → Quotas; try another region; reduce `node_count` / smaller VM (`Standard_B2s`, `t3.small`). |
| **SKU not available** in region | Change `vm_size` / `node_instance_type` / `machine_type`; try paired region (e.g. `ukwest` if `uksouth` fails). |
| **AKS version** error | Leave `kubernetes_version` unset (`null` = latest in region) or pick from `az aks get-versions --location <location>`. |
| **GKE** “project not found” / API disabled | Set correct `project_id`; enable Kubernetes Engine API; billing enabled. |
| **Wrong directory** | Run Terraform only inside `terraform/aks`, `terraform/eks`, or `terraform/gke` — not repo root. |

### Azure CLI on Kali (install script error)

Microsoft’s `InstallAzureCLIDeb` script does not recognize `kali-rolling`. Options:

- **Recommended on Kali:** `sudo apt update && sudo apt install -y azure-cli`
- Or: `curl -sL https://aka.ms/InstallAzureCLIDeb | sudo DIST_CODE=bookworm bash`
- **`SyntaxWarning`** spam from `python3-azext-devops` during install is harmless; `az version` should still work.

### RBAC Check 2 missing or “skipped” (GKE / AKS)

Check 2 needs **cloud env vars** in the same shell as the script:

```bash
# AKS (from terraform/aks after apply)
export AKS_RESOURCE_GROUP="$(terraform output -raw resource_group_name)"
export AKS_CLUSTER_NAME="$(terraform output -raw cluster_name)"

# GKE Check 2 only needs the project (from terraform/gke)
export GKE_PROJECT="$(terraform output -raw project_id)"
# Optional helpers for get-credentials / docs:
# export GKE_CLUSTER_NAME="$(terraform output -raw cluster_name)"
# export GKE_LOCATION="$(terraform output -raw zone)"
```

Also install **`gke-gcloud-auth-plugin`** (`sudo apt install google-cloud-cli-gke-gcloud-auth-plugin` when gcloud is from apt) so Terraform’s Kubernetes provider and kubectl can authenticate to GKE.

**EKS** Check 2: `aws-auth` needs only kubectl. Access Entries need the AWS CLI (same creds as the cluster); cluster/region are taken from the kubeconfig context ARN when possible, else:

```bash
export EKS_CLUSTER_NAME="$(terraform output -raw cluster_name)"
export AWS_REGION="$(terraform output -raw aws_region)"
```

### Audit runs but cap/RBAC test namespaces look empty

- Confirm fixtures were applied: `terraform apply` with `deploy_capability_test_workloads = true` and `deploy_rbac_test_fixtures = true` (defaults).
- Check outputs: `terraform output capability_test_namespace` and `rbac_test_namespace`.
- Wait for pods: `kubectl get pods -A | grep -E 'cap-test|rbac'`.

### `--quiet` shows check headers with no lines underneath

That usually means only platform roles matched and were filtered out — not necessarily “all clear.” Re-run **without** `--quiet` once to see skipped system roles, or use `--checks=N` for one check.

### Still stuck?

Note the **exact command**, **cloud + region from `terraform.tfvars`**, and the **last 20 lines of error**. Use `./<Script>.sh --help` and the script header for check IDs.

---

## Reference (when you need detail)

### Check 2 scope (cloud RBAC scripts)

Not a full cloud IAM audit — only a **small, documented slice**:

- **EKS:** `aws-auth` → `system:masters`, plus Access Entries with `AmazonEKSClusterAdminPolicy` / `AmazonEKSAdminPolicy`  
- **GKE:** project IAM (`Owner` / `Editor` / `container.clusterAdmin` / `container.admin` on the GCP project; GKE has no cluster-resource `get-iam-policy`)
- **AKS:** Azure role assignments on the AKS cluster resource

### Known platform break-glass (annotated in output)

Cloud RBAC scripts **do not hide** vendor break-glass paths. They **tag** them so triage can separate platform noise from your lab/app findings:

| Cloud | Tagged in output |
|-------|------------------|
| **AKS** | `ClusterRole/aks-service`, Users `aks-support` / `clusterAdmin` / `clusterUser`; Check 2 Azure RBAC hits; `cluster-admin` |
| **EKS** | Check 2 `aws-auth` → `system:masters` and/or Access Entry `AmazonEKSClusterAdminPolicy`; Check 1 `system:masters`; `cluster-admin` (no AKS-style `aks-service` role) |
| **GKE** | Check 2 GCP project `Owner` / `Editor` / `container.clusterAdmin` / `container.admin`; Check 1 `system:masters`; `cluster-admin` |

Look for the suffix `[known … platform break-glass]` (or `[known Kubernetes break-glass ClusterRole]`). These remain listed on purpose.

### Identity baseline

Optional [`identity_baseline.conf`](identity_baseline.conf) hides noisy **subject names** (e.g. platform SAs) in many listings. Override with `IDENTITY_BASELINE_FILE`. Not applied to cluster-admin subject listings (by design).

### Capability escape chains

Heuristic only: **estimated effective caps** from pod spec + conditions (hostPath, `hostNetwork`, …). Output: text `Escape chain:` lines, JSON `escape_chains`, CSV column `escape_chains`.

### Limitations

- RBAC ≠ complete Azure/AWS/GCP IAM.  
- Capabilities ≠ admission controller or runtime truth.  
- Terraform labs use small node pools and permissive test namespaces — **destroy when finished**.  
- For every check ID and nuance: `./<script> --help`, `--list-checks`, and the script header comments.
