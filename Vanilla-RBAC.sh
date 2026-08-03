#!/bin/bash
# ------------------------------------------------------------
# Portable Kubernetes RBAC audit (kubectl API only, checks 1–19).
#
# Scope: local / lab clusters—full in-cluster Role/ClusterRole/Binding analysis including token
# minting, enhanced wildcards, sensitive subresources, CRD heuristics, default-SA bindings, and
# workload cross-reference. No cloud IAM or provider CLIs.
# When checks 3–19 are selected (or full run), roles + bindings are prefetched once and reused.
#
# CLI: --checks --list/--list-checks --quiet --critical --help
#      --debug-check18 --debug-check19 (verbose stderr for checks 18–19)
# Env: K=/path/to/kubectl  DEBUG_CHECK18=1 DEBUG_CHECK19=1
# ------------------------------------------------------------
CHECKS_SPEC=""
LIST_CHECKS=0
QUIET=0
CRITICAL_ONLY=0
SHOW_HELP=0
[[ "${DEBUG_CHECK18:-}" == "1" ]] && DEBUG_CHECK18=1 || DEBUG_CHECK18=0
[[ "${DEBUG_CHECK19:-}" == "1" ]] && DEBUG_CHECK19=1 || DEBUG_CHECK19=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --checks=*)
      CHECKS_SPEC="${1#*=}"
      shift
      ;;
    --checks)
      CHECKS_SPEC="$2"
      shift 2
      ;;
    --list-checks|--list)
      LIST_CHECKS=1
      shift
      ;;
    --quiet)
      QUIET=1
      shift
      ;;
    --critical)
      CRITICAL_ONLY=1
      shift
      ;;
    --debug-check18)
      DEBUG_CHECK18=1
      shift
      ;;
    --debug-check19)
      DEBUG_CHECK19=1
      shift
      ;;
    -h|--help)
      SHOW_HELP=1
      shift
      ;;
    *)
      shift
      ;;
  esac
done

if [[ $SHOW_HELP -eq 1 ]]; then
  cat <<'EOF'
Kubernetes RBAC Security Audit (vanilla / kubectl)

Usage:
  Vanilla-RBAC.sh [--checks LIST] [--critical] [--quiet] [--debug-check18] [--debug-check19]
                  [--list-checks | --list] [--help | -h]

Flags:
  --checks=LIST      Run only checks 1–19; comma-separated, ranges allowed (e.g. 1,3-5,18).
  --critical         Run only high-severity checks (1,2,4,6,7,9,10,13,15,17,18).
  --quiet            Suppress OK lines, empty results, <no subjects>, and
                     "skipped system/operator-managed" noise.
  --debug-check18    Verbose diagnostics on stderr for check 18 (privileged default-SA bindings).
  --debug-check19    Verbose diagnostics on stderr for check 19 (workload ↔ risky SA cross-ref).
  --list, --list-checks   Print check catalogue and exit.
  -h, --help         Show this help and exit.

Env:
  K=/path/to/kubectl   Override kubectl binary.
  DEBUG_CHECK18=1 / DEBUG_CHECK19=1   Same as the matching --debug-check flags.

Examples:
  Vanilla-RBAC.sh --quiet
  Vanilla-RBAC.sh --checks=1,2,14
  Vanilla-RBAC.sh --critical

Description:
  Runs an in-cluster RBAC review for local/lab Kubernetes: checks 1–19 via kubectl only (no provider
  IAM). Check 19 (workload cross-reference) is omitted from --critical by default as in the extended
  audit family; run it explicitly with --checks=19 when needed.
EOF
  exit 0
fi

declare -A RUN
RUN_ALL=0

add_check_id() {
  local id="$1"
  if [[ "$id" =~ ^[0-9]+$ ]]; then
    RUN["$id"]=1
  fi
}

if [[ -n "$CHECKS_SPEC" ]]; then
  IFS=',' read -r -a check_spec_parts <<< "$CHECKS_SPEC"
  for p in "${check_spec_parts[@]}"; do
    p="$(echo "$p" | tr -d '[:space:]')"
    [[ -z "$p" ]] && continue
    if [[ "$p" =~ ^([0-9]+)-([0-9]+)$ ]]; then
      start="${BASH_REMATCH[1]}"
      end="${BASH_REMATCH[2]}"
      if (( start <= end )); then
        for ((n=start; n<=end; n++)); do add_check_id "$n"; done
      else
        for ((n=start; n>=end; n--)); do add_check_id "$n"; done
      fi
    else
      add_check_id "$p"
    fi
  done
else
  RUN_ALL=1
fi

# Critical set (14 configmap audit omitted — noisy; 19 workload xref omitted — same as extended audits)
CRITICAL_CHECKS=(1 2 4 6 7 9 10 13 15 17 18)

if [[ $CRITICAL_ONLY -eq 1 ]]; then
  RUN_ALL=0
  unset RUN
  declare -A RUN
  for c in "${CRITICAL_CHECKS[@]}"; do
    RUN["$c"]=1
  done
fi

should_run() {
  local id="$1"
  if [[ $RUN_ALL -eq 1 ]]; then return 0; fi
  [[ -n "${RUN[$id]:-}" ]] && return 0 || return 1
}

if [[ $LIST_CHECKS -eq 1 ]]; then
  cat <<'EOF'
Available checks (use --checks to select, comma-separated, ranges allowed):
  (Vanilla: IDs 1–19; kubectl API only, for local/lab clusters.)
  1  : System groups must not have cluster-admin
  2  : No custom (non-system) subjects with cluster-admin
  3  : No custom subjects creating workloads (pods, deployments, statefulsets)
  4  : No permission to exec into pods (pods/exec)
  5  : Only control plane should create persistentvolumes
  6  : No escalate on clusterroles; no bind on rolebindings; no impersonate
  7  : No custom subjects read secrets (get/list/watch)
  8  : No subject should patch namespaces
  9  : No subject should CRUD validating/mutating webhook configurations
  10 : Wildcard usage in verbs, resources, apiGroups, or nonResourceURLs (aggregated per role)
  11 : No subject should create tokenreviews
  12 : No subject should create subjectaccessreviews
  13 : Restricted access to nodes (get/list/watch/patch)
  14 : Read access to configmaps in system namespaces (CONFIGMAP_CHECK_NAMESPACES)
  15 : ServiceAccount token minting (serviceaccounts/token, tokenrequests)
  16 : Sensitive pod subresources + endpoints/endpointslices read access
  17 : CRD secret/credential heuristics + RBAC readers
  18 : Default SA and system:serviceaccounts* bound to privileged roles
  19 : Workloads using ServiceAccounts exposed to risky RBAC (cross-reference)
EOF
  exit 0
fi

set -e
set -o pipefail

K="${K:-kubectl}"

# Print audit banner, current user context, and output legend
echo "===== Kubernetes RBAC Security Audit (Vanilla, checks 1–19) ====="
echo "Running as: $($K config current-context)"
if [[ $RUN_ALL -eq 0 ]]; then
  echo "Selected checks: $(printf '%s\n' "${!RUN[@]}" | sort -n | paste -sd, -)"
  if [[ $CRITICAL_ONLY -eq 1 ]]; then echo "(--critical active: running only critical checks)"; fi
else
  echo "(No --checks specified: running ALL checks)"
fi
if [[ $QUIET -eq 1 ]]; then echo "(--quiet active: suppressing OK/Info and 'skipped system/operator-managed' lines)"; fi
echo
echo "Legend:"
echo "  ⚠ Check reported potential issues"
if [[ $QUIET -eq 0 ]]; then echo "  ✔ OK / no issues"; fi
echo "  = Role name = binding name"
echo "  ≠ Role name ≠ binding name"
echo
if [[ $QUIET -eq 0 ]]; then
  echo "[INFO] Local/lab audit: kubectl API only (checks 1–19). No provider IAM or cloud CLIs."
  echo
fi

##############################################
# Excluded namespaces
##############################################
# Static list of namespaces excluded from all checks
EXCLUDED_NS=("kube-system" "kube-public" "kube-node-lease")

# Add operator-managed namespaces dynamically (using common operator labels)
OP_NS=$($K get ns -o json | jq -r '.items[] | select(.metadata.labels."operators.coreos.com") | .metadata.name')
if [[ -n "$OP_NS" ]]; then
    EXCLUDED_NS+=("$OP_NS")
fi

echo "Excluding system/operator namespaces from checks: ${EXCLUDED_NS[*]}"
echo

# True when selected checks need the shared RBAC JSON cache (skip extra API work for --checks=1,2 only).
vanilla_needs_rbac_cache() {
  if [[ $RUN_ALL -eq 1 ]]; then return 0; fi
  local c
  for c in 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19; do
    [[ -n "${RUN[$c]:-}" ]] && return 0
  done
  return 1
}

# Namespace exclusion function
is_excluded_ns() {
    local ns="$1"
    for ex in "${EXCLUDED_NS[@]}"; do
        [[ "$ns" == "$ex" ]] && return 0
    done
    return 1
}

##############################################
# Attack-path phrases for high-value checks
##############################################
# Keys match check_permission args: "verbs_in:resource"
declare -A ATTACK_PATH=(
  ["create:pods/exec"]="exec into pod -> run arbitrary commands -> lateral movement / data exfiltration"
  ["escalate:clusterroles"]="escalate ClusterRole -> grant privileges subject does not hold -> cluster takeover"
  ["bind:clusterrolebindings"]="bind ClusterRoleBinding -> attach any ClusterRole to any subject -> privilege escalation"
  ["bind:rolebindings"]="bind RoleBinding -> attach any Role/ClusterRole in scope -> privilege escalation"
  ["impersonate:users"]="impersonate user -> act as another identity -> bypass RBAC"
  ["impersonate:groups"]="impersonate group -> inherit group privileges -> bypass RBAC"
  ["impersonate:serviceaccounts"]="impersonate ServiceAccount -> assume pod identity -> lateral movement"
  ["impersonate:userextras"]="impersonate user extras -> forge authn attributes -> bypass RBAC"
  ["get,list,watch:secrets"]="read Secrets -> harvest credentials/tokens/TLS keys -> account takeover"
  ["get,list,watch,*:secrets"]="read Secrets -> harvest credentials/tokens/TLS keys -> account takeover"
  ["create:validatingwebhookconfigurations"]="create ValidatingWebhook -> intercept/deny API requests cluster-wide -> persistence or DoS"
  ["delete:validatingwebhookconfigurations"]="delete ValidatingWebhook -> remove admission controls -> weaken cluster policy"
  ["update:validatingwebhookconfigurations"]="update ValidatingWebhook -> rewrite admission logic -> silent request mutation/denial"
  ["patch:validatingwebhookconfigurations"]="patch ValidatingWebhook -> rewrite admission logic -> silent request mutation/denial"
  ["create:mutatingwebhookconfigurations"]="create MutatingWebhook -> rewrite objects on admission -> persistence / backdoor"
  ["delete:mutatingwebhookconfigurations"]="delete MutatingWebhook -> remove mutation controls -> weaken cluster policy"
  ["update:mutatingwebhookconfigurations"]="update MutatingWebhook -> rewrite objects on admission -> persistence / backdoor"
  ["patch:mutatingwebhookconfigurations"]="patch MutatingWebhook -> rewrite objects on admission -> persistence / backdoor"
  ["create:tokenreviews"]="create TokenReview -> validate arbitrary bearer tokens -> credential probing"
  ["create:subjectaccessreviews"]="create SubjectAccessReview -> enumerate other identities' permissions -> privilege mapping"
  ["create:serviceaccounts/token"]="mint ServiceAccount token -> obtain long-lived credentials for another SA -> identity theft"
)

##############################################
# Optional identity baseline (subject-name allowlist)
##############################################
# Loaded from identity_baseline.conf next to this script (or IDENTITY_BASELINE_FILE).
# Missing file => empty allowlist (unchanged behavior).
IDENTITY_BASELINE_GLOBS=()
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IDENTITY_BASELINE_FILE="${IDENTITY_BASELINE_FILE:-$SCRIPT_DIR/identity_baseline.conf}"

load_identity_baseline() {
  IDENTITY_BASELINE_GLOBS=()
  local f="$IDENTITY_BASELINE_FILE"
  [[ -f "$f" ]] || return 0
  local line glob
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
    # Require exactly "glob | reason" (two fields)
    if [[ "$line" != *"|"* ]]; then
      continue
    fi
    glob="${line%%|*}"
    glob="$(echo "$glob" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
    [[ -z "$glob" ]] && continue
    IDENTITY_BASELINE_GLOBS+=("$glob")
  done < "$f"
  if [[ ${#IDENTITY_BASELINE_GLOBS[@]} -gt 0 && $QUIET -eq 0 ]]; then
    echo "[INFO] Loaded ${#IDENTITY_BASELINE_GLOBS[@]} identity baseline pattern(s) from $f"
    echo
  fi
}

is_baseline_identity() {
  local name="$1"
  local pat
  [[ -z "$name" ]] && return 1
  for pat in "${IDENTITY_BASELINE_GLOBS[@]}"; do
    # shellcheck disable=SC2254
    case "$name" in
      $pat) return 0 ;;
    esac
  done
  return 1
}

load_identity_baseline

##############################################
# RBAC API cache (one fetch per run when needed)
##############################################
ALL_CRB=""
ALL_RB=""
ALL_ROLES_AND_CR=""
RBAC_CACHE_LOADED=""

ensure_rbac_cache() {
  [[ -n "${RBAC_CACHE_LOADED:-}" ]] && return
  ALL_CRB="$($K get clusterrolebinding -o json 2>/dev/null || echo '{"items": []}')"
  ALL_RB="$($K get rolebinding -A -o json 2>/dev/null || echo '{"items": []}')"
  ALL_ROLES_AND_CR="$($K get clusterrole,role -A -o json 2>/dev/null || echo '{"items": []}')"
  RBAC_CACHE_LOADED=1
}

if vanilla_needs_rbac_cache; then
  ensure_rbac_cache
  if [[ $QUIET -eq 0 ]]; then
    echo "[INFO] Prefetched ClusterRoles/Roles + bindings once for this run."
    echo
  fi
fi

# Benign controller / system role name globs (comma-separated) for checks 16–19 quiet noise
ALLOWLIST_ROLES="\
system:node,system:node-proxier,system:kube-controller-manager,system:kube-scheduler,system:kube-proxy,system:coredns,system:aggregated-metrics-reader,system:public-info-viewer,\
kube-proxy,cluster-autoscaler,\
cilium,cilium-*,cilium-operator,hubble-ui,hubble-relay,\
istiod,istiod-*,istio-reader-*,istio-gateway-*,\
argo-cd-application-controller,argo-cd-applicationset-controller,argo-cd-server,argocd-ecr-updater,argocd-dex-server,\
kyverno-*,kyverno-background-controller,kyverno-cleanup-controller,\
keda-operator,keda-operator-certs,keda-*,\
external-dns,external-dns-viewer,\
external-secrets,external-secrets-controller,external-secrets-cert-controller,\
datadog,datadog-*,datadog-cluster-agent,datadog-ksm-core,\
trivy-operator,trivy-adapter,reloader-*,\
k8sensor,instana-*,policy-reporter-*,nginx-gateway-internal"

is_allowlisted_role() {
  local name="$1"
  IFS=',' read -r -a _arr <<< "$ALLOWLIST_ROLES"
  for pat in "${_arr[@]}"; do
    # shellcheck disable=SC2254
    case "$name" in
      $pat) return 0 ;;
    esac
  done
  return 1
}

##############################################
# Helper: Get subjects for a role or binding
##############################################
# Resolves all subjects bound to a given role by name.
# For ClusterRoles, queries both ClusterRoleBindings and all-namespace RoleBindings
# (a RoleBinding may reference a ClusterRole, granting it scoped to one namespace).
# For namespaced Roles, queries only RoleBindings in the given namespace.
# Returns formatted subject lines, or the sentinel "<no subjects>" if none found.
get_subjects_for_role() {
    local kind="$1"
    local name="$2"
    local ns="$3"

    ensure_rbac_cache

    local subjects
    if [[ "$ns" == "cluster" ]]; then
        # ClusterRoles can be bound via ClusterRoleBindings OR via RoleBindings in any namespace
        # Both paths must be queried, otherwise subjects granted through RoleBinding→ClusterRole are missed.
        local crb_subjects rb_subjects
        crb_subjects=$(echo "$ALL_CRB" \
          | jq -r --arg ROLE "$name" '
              .items[]
              | select(.roleRef.name == $ROLE)
              | . as $binding
              | .subjects[]?
              | {kind:.kind,name:.name,namespace:(.namespace//"-"),binding:($binding.metadata.name)}
          ' | jq -s 'unique_by(.kind + .name + .namespace + .binding)' || echo '[]')
        rb_subjects=$(echo "$ALL_RB" \
          | jq -r --arg ROLE "$name" '
              .items[]
              | select(.roleRef.kind == "ClusterRole" and .roleRef.name == $ROLE)
              | . as $binding
              | .subjects[]?
              | {kind:.kind,name:.name,namespace:(.namespace//($binding.metadata.namespace//"-")),binding:($binding.metadata.name)}
          ' | jq -s 'unique_by(.kind + .name + .namespace + .binding)' || echo '[]')
        subjects=$(printf '%s\n%s\n' "$crb_subjects" "$rb_subjects" \
          | jq -s 'add | unique_by(.kind + .name + .namespace + .binding)')
    else
        subjects=$(echo "$ALL_RB" \
          | jq -r --arg ROLE "$name" --arg NS "$ns" '
              .items[]
              | select(.metadata.namespace == $NS and .roleRef.name == $ROLE)
              | . as $binding
              | .subjects[]?
              | {kind:.kind,name:.name,namespace:(.namespace//"-"),binding:($binding.metadata.name)}
          ' | jq -s 'unique_by(.kind + .name + .namespace + .binding)')
    fi

    if [[ -z "$subjects" || "$subjects" == "[]" ]]; then
        echo "<no subjects>"
    else
        # Append binding name after = / ≠
        echo "$subjects" | jq -r --arg ROLE "$name" '.[] | if .binding == $ROLE then "\(.kind) \(.name) (ns: \(.namespace)) via = \(.binding)" else "\(.kind) \(.name) (ns: \(.namespace)) via ≠ \(.binding)" end'
    fi
}
##############################################
# CHECK 1: System groups should not have cluster-admin
##############################################
# Check 1: Verify that broad system groups (authenticated, unauthenticated, anonymous,
# all serviceaccounts) are NOT bound to cluster-admin. Any such binding would grant
# unrestricted cluster access to every user or pod in the cluster.
check_system_group() {
    local group="$1"
    echo " Checking: $group"

    if [[ -n "${RBAC_CACHE_LOADED:-}" ]]; then
    hits=$(echo "$ALL_CRB" | jq -r --arg GRP "$group" '
          .items[]
          | select(.subjects[]? | .kind=="Group" and .name==$GRP)
          | select(.roleRef.name=="cluster-admin")
          | select(.metadata.labels."olm.owner"? | not)   # skip operator bindings
          | .metadata.name')
    else
    hits=$($K get clusterrolebinding -o json \
      | jq -r --arg GRP "$group" '
          .items[]
          | select(.subjects[]? | .kind=="Group" and .name==$GRP)
          | select(.roleRef.name=="cluster-admin")
          | select(.metadata.labels."olm.owner"? | not)   # skip operator bindings
          | .metadata.name')
    fi

    if [[ -z "$hits" ]]; then
        [[ $QUIET -eq 0 ]] && echo "  ✔ OK"
    else
        echo "  ⚠ VIOLATION: $group has cluster-admin:"
        echo "    - ${hits//$'\n'/$'\n'    - }"
    fi
    echo
}

if should_run 1; then
echo "1: System groups must not have cluster-admin"
for grp in system:authenticated system:unauthenticated system:anonymous system:serviceaccounts; do
    check_system_group "$grp"
done
echo
fi

##############################################
# CHECK 2: No custom subjects with cluster-admin
# Excludes system and operator namespaces
##############################################
# Check 2: Find non-system (custom) subjects directly bound to cluster-admin via
# ClusterRoleBindings. Excludes subjects in system/operator-managed namespaces and
# OLM-owned bindings. Uses a found flag so the ✔ OK message reliably prints when
# all subjects are filtered out.
if should_run 2; then
echo "2: No custom (non-system) subjects with cluster-admin"

found=0
while IFS= read -r line; do
    ns=$(echo "$line" | sed -n 's/.*(ns: \(.*\)).*/\1/p')
    binding_olm=$(echo "$line" | awk '{print $NF}')
    is_excluded_ns "$ns" && continue
    [[ "$binding_olm" != "-" ]] && continue
    echo "      * $line"
    found=1
done < <(
    if [[ -n "${RBAC_CACHE_LOADED:-}" ]]; then
    echo "$ALL_CRB" | jq -r '
      .items[]
      | select(.roleRef.name=="cluster-admin")
      | . as $binding
      | .subjects[]?
      | select(.name | startswith("system:") | not)
      | "\(.kind) \(.name) (ns: \(.namespace // "-")) via ClusterRoleBinding: \($binding.metadata.name) \($binding.metadata.labels."olm.owner" // "-")"
    ' | sort -u
    else
    $K get clusterrolebinding -o json \
    | jq -r '
      .items[]
      | select(.roleRef.name=="cluster-admin")
      | . as $binding
      | .subjects[]?
      | select(.name | startswith("system:") | not)
      | "\(.kind) \(.name) (ns: \(.namespace // "-")) via ClusterRoleBinding: \($binding.metadata.name) \($binding.metadata.labels."olm.owner" // "-")"
    ' | sort -u
    fi
)
if [[ $found -eq 0 ]]; then
    [[ $QUIET -eq 0 ]] && echo "  ✔ OK: No custom subjects have cluster-admin."
fi
echo
fi

##############################################
# Generic permission check helper
##############################################
# Generic helper used by Checks 3–13.
# Accepts one or more comma-separated verbs (e.g. "get,list,watch") and a resource name,
# then finds every ClusterRole/Role that grants any of those verbs on that resource.
# System, OLM-managed, and excluded-namespace roles are skipped or labelled accordingly.
# Subjects are resolved via get_subjects_for_role and filtered by is_excluded_ns.
check_permission() {
    local verbs_in="$1"
    local resource="$2"
    local msg="$3"
    local empty_msg="${4:-✔ No matching roles found.}"
    local ap_key="${verbs_in}:${resource}"

    echo "Checking: $msg ($verbs_in $resource)"
    if [[ -n "${ATTACK_PATH[$ap_key]:-}" ]]; then
      echo "  Attack path: ${ATTACK_PATH[$ap_key]}"
    fi

    ensure_rbac_cache

    # Scan cached ClusterRoles + Roles (single list per call, not per-verb refetch)
    matches=$(echo "$ALL_ROLES_AND_CR" \
      | jq -r --arg verbs "$verbs_in" --arg res "$resource" '
          ($verbs | split(",")) as $wv |
          .items[]
          | . as $role
          | (.rules[]? // empty)
          | select(
                (
                  (.verbs // []) |
                  . as $rv |
                  (($rv | index("*")) != null) or
                  ($wv | map(. as $w | $rv | index($w) != null) | any)
                )
                and
                (
                  (.resources // []) |
                  (index("*") != null) or (index($res) != null)
                )
            )
          | [
              $role.kind,
              $role.metadata.name,
              ($role.metadata.namespace // "cluster"),
              (.verbs // [] | join(",")),
              (.resources // [] | join(",")),
              (.apiGroups // [] | join(",")),
              ($role.metadata.labels."olm.owner" // "-")
            ]
          | @tsv
      ')

    if [[ -z "$matches" ]]; then
        [[ $QUIET -eq 0 ]] && echo "  $empty_msg"
        echo
        return
    fi

    # Known system clusterroles to skip
    SYSTEM_ROLES=("admin" "edit" "view" "cluster-admin" "basic-user" "self-provisioner" \
                  "cluster-reader" "system:discovery" "system:heapster" \
                  "system:node" "system:controller" "system:aggregate-to-admin" \
                  "system:aggregate-to-edit" "system:aggregate-to-view")

    local roles_header_printed=0
    echo "$matches" | sort -u | while IFS=$'\t' read -r kind name ns verbs resources apigroups olm; do

        # Skip system/operator-managed roles
        if [[ "$kind" == "ClusterRole" ]]; then
            if [[ "$olm" != "-" ]] || [[ "$name" == system:* ]] || [[ " ${SYSTEM_ROLES[*]} " =~ $name ]] || is_excluded_ns "$ns"; then
                [[ $QUIET -eq 0 ]] && echo "    - $kind/$name (ns: $ns) -> <skipped system/operator-managed clusterrole>"
                continue
            fi
        else
            # For namespaced Roles, skip roles in excluded namespaces
            [[ -n "$ns" ]] && is_excluded_ns "$ns" && continue
        fi

        # Get subjects for this role
        subjects=$(get_subjects_for_role "$kind" "$name" "$ns")

        # Filter out system/operator subjects
        filtered_subjects=$(echo "$subjects" | while read -r subj; do
            subj_ns=$(echo "$subj" | sed -n 's/.*(ns: \(.*\)).*/\1/p')
            subj_name=$(echo "$subj" | awk '{print $2}')
            is_excluded_ns "$subj_ns" && continue
            [[ "$subj_name" == system:* ]] && continue
            is_baseline_identity "$subj_name" && continue
            echo "$subj"
        done)

        if [[ $QUIET -eq 1 ]]; then
            if [[ "$subjects" == "<no subjects>" || -z "$filtered_subjects" ]]; then
                continue
            fi
        fi

        if [[ $roles_header_printed -eq 0 ]]; then
            echo "  ⚠ Roles with this permission:"
            roles_header_printed=1
        fi

        echo "    - $kind/$name (ns: $ns)"

        if [[ "$subjects" == "<no subjects>" ]]; then
            [[ $QUIET -eq 0 ]] && echo "      <no subjects>"
            continue
        fi

        if [[ -z "$filtered_subjects" ]]; then
            [[ $QUIET -eq 0 ]] && echo "      ✔ All subjects are system/operator accounts"
        else
            echo "$filtered_subjects" | while read -r subj; do
                echo "      * $subj"
            done
        fi
    done
    echo
}

##############################################
# CHECKS 3–13: Permission checks
##############################################

# CHECK 3: No custom subjects creating workloads
# Check 3: Identify roles that allow creating pods, deployments, or statefulsets.
# Workload creation can be used to introduce privileged or hostile containers into the cluster.
if should_run 3; then
echo "3: No custom subjects creating workloads (pods, deployments, statefulsets)"
WORKLOAD_RESOURCES=(pods deployments statefulsets)
for res in "${WORKLOAD_RESOURCES[@]}"; do
    check_permission create "$res" "No custom subjects should create workload resources ($res)"
    echo
done
fi

# CHECK 4: No exec into pods
# Check 4: Detect roles that allow pods/exec. This grants arbitrary command execution
# inside running containers and is a critical lateral-movement and data-exfiltration vector.
if should_run 4; then
echo "4: No permission to exec into pods (pods/exec)"
check_permission create pods/exec "No subjects should have permission to exec into pods"
echo
fi

# CHECK 5: No persistent volume creation
# CHECK 5: No persistent volume creation
# Check 5: Verify only control-plane components can create PersistentVolumes.
# Unrestricted PV creation can expose host filesystem paths or cloud storage buckets.
if should_run 5; then
echo "5: Only control plane should create persistentvolumes"
check_permission create persistentvolumes "Only control plane components should create persistentvolumes"
echo
fi

# CHECK 6: Escalate, Bind, Impersonate
# Check 6: Detect privilege-escalation verbs.
# 'escalate' on clusterroles allows granting permissions the subject doesn't hold themselves.
# 'bind' on role bindings allows attaching any role to any subject.
# 'impersonate' allows acting as another user, group, or serviceaccount, bypassing RBAC entirely.
if should_run 6; then
echo "6: No escalate on clusterroles; no bind on rolebindings; no impersonate"
check_permission escalate clusterroles "No subject should have 'escalate' verb on clusterroles"
echo
check_permission bind clusterrolebindings "No subject should have 'bind' verb on clusterrolebindings" "✔ No subjects found with bind permissions"
echo
check_permission bind rolebindings "No subject should have 'bind' verb on rolebindings" "✔ No subjects found with bind permissions"
echo
for res in users groups serviceaccounts userextras; do
    check_permission impersonate "$res" "No subject should 'impersonate' verb on $res"
    echo
done
fi

# Check 7: Find roles that can read Secrets (get/list/watch or wildcard).
# A single combined call avoids duplicate output for roles that match multiple verbs.
if should_run 7; then
echo "7: No custom subjects read secrets (get/list/watch)"
check_permission "get,list,watch" secrets "No custom subjects should read secrets (get/list/watch)"
echo
fi

# Check 8: Detect roles that can patch namespaces. Namespace labels control admission
# policies (e.g. PodSecurity, Kyverno), so patching them can disable security controls.
if should_run 8; then
echo "8: No subject should patch namespaces"
check_permission patch namespaces "No subject should patch namespaces"
echo
fi

# Check 9: Detect roles that can create/update/patch/delete ValidatingWebhookConfigurations
# or MutatingWebhookConfigurations. Modifying these can intercept or silently mutate
# every API request cluster-wide, making them a high-value escalation target.
if should_run 9; then
echo "9: No subject should CRUD validating/mutating webhook configurations"
for res in validatingwebhookconfigurations mutatingwebhookconfigurations; do
    for verb in create delete update patch; do
        check_permission "$verb" "$res" "No subject should $verb $res"
        echo
    done
done
echo
fi

# Check 10: Wildcards in verbs, resources, apiGroups, or nonResourceURLs (aggregated per role).
if should_run 10; then
echo "10: Wildcard usage in verbs, resources, apiGroups, or nonResourceURLs (aggregated per role)"
ensure_rbac_cache
wild_rules=$(
  echo "$ALL_ROLES_AND_CR" \
  | jq -r '
      def wild_rule($r):
        ((($r.verbs // [])          | index("*")) or
         (($r.resources // [])       | index("*")) or
         (($r.apiGroups // [])       | index("*")) or
         (($r.nonResourceURLs // []) | index("*")));
      .items[] as $role
      | ($role.rules // []) as $rules
      | any($rules[]?; wild_rule(.))
      | select(. == true)
      | [
          $role.kind,
          $role.metadata.name,
          ($role.metadata.namespace // "cluster"),
          ($rules | map(.verbs // [])           | add // [] | unique | join(",")),
          ($rules | map(.resources // [])       | add // [] | unique | join(",")),
          ($rules | map(.apiGroups // [])       | add // [] | unique | join(",")),
          ($rules | map(.nonResourceURLs // []) | add // [] | unique | join(",")),
          ($role.metadata.labels."olm.owner" // "-")
        ]
      | @tsv
    '
)
if [[ -z "$wild_rules" ]]; then
    [[ $QUIET -eq 0 ]] && echo "  ✔ No critical wildcard usage detected."
    echo
else
    # Known system clusterroles to skip (same set as check_permission)
    SYSTEM_ROLES=("admin" "edit" "view" "cluster-admin" "basic-user" "self-provisioner" \
                  "cluster-reader" "system:discovery" "system:heapster" \
                  "system:node" "system:controller" "system:aggregate-to-admin" \
                  "system:aggregate-to-edit" "system:aggregate-to-view")

    # Process substitution (not a pipe) so set -e/pipefail cannot abort the script when
    # the last loop body ends with a failing quiet-mode [[ ... ]] && echo.
    while IFS=$'\t' read -r kind name ns verbs resources apigroups nresurls olm; do

        if [[ "$kind" == "ClusterRole" ]]; then
            if [[ "$olm" != "-" ]] || [[ "$name" == system:* ]] || [[ " ${SYSTEM_ROLES[*]} " =~ $name ]]; then
                [[ $QUIET -eq 0 ]] && echo "    - $kind/$name (ns: $ns) -> <skipped system/operator-managed>"
                continue
            fi
        else
            [[ -n "$ns" ]] && is_excluded_ns "$ns" && continue
        fi

        # Determine correct scope for fetching bindings
        if [[ "$ns" == "cluster" ]]; then
            subjects=$(get_subjects_for_role "$kind" "$name" "cluster")
        else
            subjects=$(get_subjects_for_role "$kind" "$name" "$ns")
        fi

        if [[ "$subjects" == "<no subjects>" ]]; then
            if [[ $QUIET -eq 0 ]]; then
                echo "    - $kind/$name (ns: $ns) (rule: verbs=$verbs, resources=$resources, apiGroups=$apigroups, nonResourceURLs=$nresurls)"
                echo "      <no subjects>"
            fi
            continue
        fi

        filtered_subjects=$(echo "$subjects" | while read -r subj; do
            subj_ns=$(echo "$subj" | sed -n 's/.*(ns: \(.*\)).*/\1/p')
            subj_name=$(echo "$subj" | awk '{print $2}')
            is_excluded_ns "$subj_ns" && continue
            [[ "$subj_name" == system:* ]] && continue
            is_baseline_identity "$subj_name" && continue
            echo "$subj"
        done)

        if [[ -z "$filtered_subjects" ]]; then
            if [[ $QUIET -eq 0 ]]; then
                echo "    - $kind/$name (ns: $ns) (rule: verbs=$verbs, resources=$resources, apiGroups=$apigroups, nonResourceURLs=$nresurls)"
                echo "      ✔ All subjects are system/operator accounts"
            fi
            continue
        fi

        echo "    - $kind/$name (ns: $ns) (rule: verbs=$verbs, resources=$resources, apiGroups=$apigroups, nonResourceURLs=$nresurls)"
        echo "$filtered_subjects" | while read -r subj; do
            echo "      * $subj"
        done
    done < <(echo "$wild_rules" | awk -F'\t' '!seen[$2,$3,$4,$5,$6,$7]++')
    echo
fi
fi

# Check 11: Find roles that can create TokenReviews. This allows a subject to validate
# arbitrary bearer tokens and probe for valid credentials across the cluster.
if should_run 11; then
echo "11: No subject should create tokenreviews"
check_permission create tokenreviews "No subject should create tokenreviews"
echo
fi

# Check 12: Find roles that can create SubjectAccessReviews. This allows a subject to
# enumerate what permissions any other identity holds — useful for privilege mapping attacks.
if should_run 12; then
echo "12: No subject should create subjectaccessreviews"
check_permission create subjectaccessreviews "No subject should create subjectaccessreviews"
echo
fi

# Check 13: Detect over-permissive node access. Read access (get/list/watch) exposes
# the full inventory of pods and tokens on each node; patch access can alter node
# taints, labels, and conditions to influence scheduling or disable health checks.
if should_run 13; then
echo "13: Restricted access to nodes (get/list/watch/patch)"
for verb in get list watch patch; do
    check_permission "$verb" nodes "No subject should $verb nodes"
    echo
done
fi

##############################################
# CHECK 14: Read access to configmaps in system namespaces (Option A)
##############################################

# Check 14: Find subjects that can read ConfigMaps in sensitive system namespaces.
# These namespaces may contain kubeconfig data, bootstrap tokens, etcd encryption keys,
# or other cluster-critical configuration. Checked via both RoleBindings (namespace-scoped)
# and ClusterRoleBindings (cluster-scoped but still able to read any namespace's ConfigMaps).
# The target namespace list can be overridden via CONFIGMAP_CHECK_NAMESPACES env var.

# Default namespaces to inspect on vanilla Kubernetes
SYSTEM_CONFIGMAP_NAMESPACES=(
  kube-system
  kube-public
  default
)

# Optional override:
#   export CONFIGMAP_CHECK_NAMESPACES="ns1 ns2 ..."
if [[ -n "${CONFIGMAP_CHECK_NAMESPACES:-}" ]]; then
  read -r -a SYSTEM_CONFIGMAP_NAMESPACES <<< "${CONFIGMAP_CHECK_NAMESPACES}"
fi

if should_run 14; then
ensure_rbac_cache
echo "14: Read access to configmaps in system namespaces (CONFIGMAP_CHECK_NAMESPACES)"
echo "Checking: subjects who can get/list/watch configmaps in system namespaces:"
echo "  Targets: ${SYSTEM_CONFIGMAP_NAMESPACES[*]}"
echo

for TARGET_NS in "${SYSTEM_CONFIGMAP_NAMESPACES[@]}"; do
  # Skip if namespace does not exist
  if ! $K get ns "$TARGET_NS" >/dev/null 2>&1; then
    [[ $QUIET -eq 0 ]] && echo "  (skip: namespace $TARGET_NS not present)"
    continue
  fi

  echo "  Checking RoleBindings in $TARGET_NS…"
  echo "$ALL_RB" | jq -rc --arg ns "$TARGET_NS" '
      .items[] | select(.metadata.namespace == $ns) | . as $rb
      | .roleRef as $ref
      | {binding:$rb.metadata.name, refKind:$ref.kind, refName:$ref.name, subjects:($rb.subjects // [])}
    ' \
  | while IFS= read -r json; do
      refKind=$(echo "$json" | jq -r '.refKind')
      refName=$(echo "$json" | jq -r '.refName')

      # Resolve rules from prefetch (no per-binding get role/clusterrole)
      if [[ "$refKind" == "Role" ]]; then
        rules=$(echo "$ALL_ROLES_AND_CR" | jq -c --arg n "$refName" --arg ns "$TARGET_NS" '.items[] | select(.kind=="Role" and .metadata.name==$n and .metadata.namespace==$ns)' | head -n1)
      else
        rules=$(echo "$ALL_ROLES_AND_CR" | jq -c --arg n "$refName" '.items[] | select(.kind=="ClusterRole" and .metadata.name==$n)' | head -n1)
      fi
      [[ -z "$rules" ]] && continue

      # Does this role grant get/list/watch/* on configmaps?
      has_configmaps=$(echo "$rules" | jq -e '
        [.rules[]? |
           ((.resources // [] | index("configmaps")) != null or (.resources // [] | index("*")) != null)
           and
           ((.verbs // [] | index("get")) != null or (.verbs // [] | index("list")) != null
            or (.verbs // [] | index("watch")) != null or (.verbs // [] | index("*")) != null)
        ] | any
      ' >/dev/null && echo yes || echo no)
      [[ "$has_configmaps" == "no" ]] && continue

      # Emit subjects; apply same filtering policy as the rest of the script
      echo "$json" \
      | jq -r '
          .binding as $b |
          .subjects[]? |
          "\(.kind) \(.name) (ns: \(.namespace // "-")) via RoleBinding=\($b)"
      ' | while read -r subj; do
          subj_ns=$(echo "$subj" | sed -n 's/.*(ns: \(.*\)).*/\1/p')
          subj_name=$(echo "$subj" | awk '{print $2}')
          is_excluded_ns "$subj_ns" && continue
          [[ "$subj_name" == system:* ]] && continue
          is_baseline_identity "$subj_name" && continue
          echo "    * $subj"
        done
    done
  echo

  echo "  Checking ClusterRoleBindings affecting $TARGET_NS…"
  echo "$ALL_CRB" | jq -rc '
      .items[] | . as $crb
      | {binding:$crb.metadata.name, refName:$crb.roleRef.name, subjects:($crb.subjects // [])}
    ' \
  | while IFS= read -r json; do
      ref=$(echo "$json" | jq -r '.refName')
      rules=$(echo "$ALL_ROLES_AND_CR" | jq -c --arg n "$ref" '.items[] | select(.kind=="ClusterRole" and .metadata.name==$n)' | head -n1)
      [[ -z "$rules" ]] && continue

      has_configmaps=$(echo "$rules" | jq -e '
        [.rules[]? |
            ((.resources // [] | index("configmaps")) != null or (.resources // [] | index("*")) != null)
            and
            ((.verbs // [] | index("get")) != null or (.verbs // [] | index("list")) != null
             or (.verbs // [] | index("watch")) != null or (.verbs // [] | index("*")) != null)
        ] | any
      ' >/dev/null && echo yes || echo no)
      [[ "$has_configmaps" == "no" ]] && continue

      echo "$json" \
      | jq -r '
          .binding as $b |
          .subjects[]? |
          "\(.kind) \(.name) (ns: \(.namespace // "-")) via ClusterRoleBinding=\($b)"
      ' | while read -r subj; do
          subj_ns=$(echo "$subj" | sed -n 's/.*(ns: \(.*\)).*/\1/p')
          subj_name=$(echo "$subj" | awk '{print $2}')
          is_excluded_ns "$subj_ns" && continue
          [[ "$subj_name" == system:* ]] && continue
          is_baseline_identity "$subj_name" && continue
          echo "    * $subj"
        done
    done
  echo
done
fi

# Check 15: ServiceAccount token minting
if should_run 15; then
  echo "15: ServiceAccount token minting (TokenVolumeProjection)"
  check_permission create "serviceaccounts/token" "No subjects should be allowed to mint service account tokens"
  echo
  check_permission create "tokenrequests" "No subjects should be allowed to create tokenrequests" "✔ No roles found with tokenrequests create"
  echo
fi

if should_run 16; then
  ensure_rbac_cache
  echo "16: Sensitive subresources (ephemeralcontainers, attach, portforward, proxy) + endpoints"

  matches=$(
    echo "$ALL_ROLES_AND_CR" |
    jq -r '
      .items[] as $role
      | ($role.rules // []) as $rules
      | (
          [
            $rules[]?
            | (
                 # --- pods subresources that can compromise running workloads ---
                 (
                   (.resources // []) | any(
                     . == "pods/ephemeralcontainers" or
                     . == "pods/attach" or
                     . == "pods/portforward" or
                     . == "pods/proxy" or
                     . == "pods/*" or
                     . == "*"
                   )
                 )
                 and
                 (
                   (.verbs // []) | any(
                     . == "create" or
                     . == "update" or
                     . == "patch" or
                     . == "*"
                   )
                 )
               )
            or
               (
                 # --- endpoints / endpointslices (read) ---
                 (
                   (.resources // []) | any(
                     . == "endpoints" or
                     . == "endpointslices" or
                     . == "*"
                   )
                 )
                 and
                 (
                   (.verbs // []) | any(
                     . == "get" or
                     . == "list" or
                     . == "watch" or
                     . == "*"
                   )
                 )
               )
          ] | any
        ) as $has
      | select($has == true)
      | [
          $role.kind,
          $role.metadata.name,
          ($role.metadata.namespace // "cluster"),
          ($role.metadata.labels."olm.owner" // "-")
        ]
      | @tsv
    '
  )

  if [[ -z "$matches" ]]; then
    [[ $QUIET -eq 0 ]] && echo " ✔ No roles grant sensitive pod subresource or endpoint access"
    echo
  else
    check16_section_header_printed=0

    # Build per-(kind|name|ns)
    declare -A ROLE_KIND ROLE_NAME ROLE_NS ROLE_OLM ROLE_SUBJECTS
    while IFS=$'\t' read -r kind name ns olm; do
      rkey="$kind|$name|$ns"
      ROLE_KIND[$rkey]="$kind"
      ROLE_NAME[$rkey]="$name"
      ROLE_NS[$rkey]="$ns"
      ROLE_OLM[$rkey]="$olm"
      [[ -z "${ROLE_SUBJECTS[$rkey]:-}" ]] && ROLE_SUBJECTS[$rkey]=$(get_subjects_for_role "$kind" "$name" "$ns")
    done <<<"$(echo "$matches" | sort -u)"

    # Group by (kind|name) to condense namespaces
    declare -A GROUP_NS GROUP_OLM GROUP_ALLOW
    for k in "${!ROLE_KIND[@]}"; do
      kind="${ROLE_KIND[$k]}"; name="${ROLE_NAME[$k]}"; ns="${ROLE_NS[$k]}"; olm="${ROLE_OLM[$k]}"
      g="$kind|$name"
      if [[ -z "${GROUP_NS[$g]}" ]]; then GROUP_NS[$g]="$ns"
      else case ",${GROUP_NS[$g]}," in *,"$ns",*) : ;; *) GROUP_NS[$g]="${GROUP_NS[$g]},$ns" ;; esac
      fi
      [[ "$olm" != "-" ]] && GROUP_OLM[$g]=1
      is_allowlisted_role "$name" && GROUP_ALLOW[$g]=1
    done

    # Sort groups by importance
    groups=("${!GROUP_NS[@]}")
    sorted_groups=$(for g in "${groups[@]}"; do
        kind="${g%%|*}"; name="${g#*|}"; score=0
        [[ "$kind" == "ClusterRole" ]] && score=$((score+10))
        [[ "$name" == "cluster-admin" ]] && score=$((score+1000))
        is_allowlisted_role "$name" && score=$((score-5))
        printf '%04d\t%s\n' "$score" "$g"
      done | sort -rn | cut -f2)

    # Print each group once (hide empty roles)
    while IFS= read -r g; do
      kind="${g%%|*}"; name="${g#*|}"; ns_csv="${GROUP_NS[$g]}"

      # Skip system/operator-managed clusterroles in quiet mode logic
      if [[ "$kind" == "ClusterRole" && ( -n "${GROUP_OLM[$g]:-}" || "$name" == system:* ) ]]; then
        [[ $QUIET -eq 0 ]] && echo "     - $kind/$name (ns: cluster) -> <skipped system/operator-managed>"
        continue
      fi

      # Prepare namespace label
      if [[ "$kind" == "ClusterRole" ]]; then ns_pretty="cluster"
      else ns_pretty=$(echo "$ns_csv" | tr ',' '\n' | sort -u | paste -sd',' -)
      fi

      # Build consolidated subject list first; if empty -> skip role
      all_subjs=$(
        IFS=',' read -r -a arr <<<"$ns_csv"
        for _ns in "${arr[@]}"; do
          rkey="$kind|$name|$_ns"
          block="${ROLE_SUBJECTS[$rkey]}"
          [[ -z "$block" || "$block" == "<no subjects>" ]] && continue
          while IFS= read -r subj; do
            subj_ns=$(echo "$subj" | sed -n 's/.*(ns: \(.*\)).*/\1/p')
            subj_name=$(echo "$subj" | awk '{print $2}')
            is_excluded_ns "$subj_ns" && continue
            [[ "$subj_name" == system:* ]] && continue
            is_baseline_identity "$subj_name" && continue
            origin="$_ns"; [[ "$kind" == "ClusterRole" ]] && origin="cluster"
            printf '%s|||%s\n' "$origin" "$subj"
          done <<<"$block"
        done
      )

      # Hide roles with no surviving subjects
      [[ -z "$all_subjs" ]] && continue

      # Allowlist behavior
      if [[ -n "${GROUP_ALLOW[$g]:-}" ]]; then
        [[ $QUIET -eq 1 ]] && continue
        AL="[allowlisted]"
      else
        AL=""
      fi

      if [[ $check16_section_header_printed -eq 0 ]]; then
        echo "  ⚠ Roles granting sensitive subresources or endpoints access:"
        check16_section_header_printed=1
      fi

      echo "     - $kind/$name (ns: $ns_pretty) $AL"

      # Deduplicate subjects; prefer canonical 'via = <roleName>'
      echo "$all_subjs" | awk '
        BEGIN { FS="\\|\\|\\|"; OFS="" }
        function parse(line,   kd,nm,ns){
          split(line,t," ")
          kd=t[1]; gsub(/^\(/,"",kd); gsub(/\)$/,"",kd)
          nm=t[2]
          ns="-"; if (match(line, /\(ns: ([^)]+)\)/, m)) ns=m[1]
          return kd SUBSEP nm SUBSEP ns
        }
        {
          o=$1; line=$2
          key=parse(line)
          iseq=index(line," via = ")>0
          if(!(key in best) || (iseq==1 && best_eq[key]==0)){ best[key]=line; best_eq[key]=iseq }
          if(!(key in orig)){ orig[key]=o }
          else{
            split(orig[key],a,", ")
            found=0; for(i in a) if(a[i]==o) found=1
            if(!found) orig[key]=orig[key] ", " o
          }
        }
        END{
          n=0; for(k in best){ lines[++n]=best[k]; keys[n]=k }
          for(i=1;i<n;i++) for(j=i+1;j<=n;j++) if(lines[i]>lines[j]){
            tmp=lines[i]; lines[i]=lines[j]; lines[j]=tmp
            t2=keys[i]; keys[i]=keys[j]; keys[j]=t2
          }
          for(i=1;i<=n;i++){
            k=keys[i]; print "       * ", lines[i], " (from: ", orig[k], ")"
          }
        }'
    done <<<"$sorted_groups"

    echo
  fi
fi

if should_run 17; then
  ensure_rbac_cache
  echo "17: CRD-based secret/credential exposure (heuristic) + RBAC read grants"

  # 1) Heuristic detection of suspicious CRDs
  SUS_CRDS=$(
    $K get crd -o json 2>/dev/null |
    jq -r '
      .items[]
      | select(
          (.spec.names.kind?      // "" | ascii_downcase | test("secret|credential|token"))
          or (.spec.names.plural?   // "" | ascii_downcase | test("secret|credential|token"))
          or (.spec.names.singular? // "" | ascii_downcase | test("secret|credential|token"))
          or ( [ .. | objects | to_entries[]? | .key | ascii_downcase | test("secret|credential|token") ] | any )
          or ( [ .. | objects | .format? | select(.!=null) | tostring | ascii_downcase | (.=="byte") ] | any )
          or ( [ .. | objects | ."x-kubernetes-secret"?     | select(.!=null) | (.==true) ] | any )
          or ( [ .. | objects | ."x-kubernetes-sensitive"? | select(.!=null) | (.==true) ] | any )
        )
      | (.spec.names.plural + "." + .spec.group)
    ' | sort -u
  )

  if [[ -z "$SUS_CRDS" ]]; then
    [[ $QUIET -eq 0 ]] && echo " ✔ No suspicious CRDs detected (or no CRD access)."
    echo
  else
    echo " Potentially sensitive CRDs:"
    echo "$SUS_CRDS" | sed 's/^/   - /'
    echo

    # 2) Always enumerate RBAC readers (flag removed)
    echo "  RBAC readers for sensitive CRDs (verbs: get|list|watch|*):"

    while read -r crd; do
      [[ -z "$crd" ]] && continue

      # 3) Find roles that can read this CRD from pre-fetched cache
      matches=$(
        echo "$ALL_ROLES_AND_CR" |
        jq -r --arg res "$crd" '
          .items[] as $role
          | ($role.rules // []) as $rules
          | (
              [ $rules[]?
                | ((.resources // []) | (index($res) or index("*")))
                and ((.verbs // []) | (index("get") or index("list") or index("watch") or index("*")))
              ] | any
            ) as $has
          | select($has == true)
          | [ $role.kind,
              $role.metadata.name,
              ($role.metadata.namespace // "cluster"),
              ($role.metadata.labels."olm.owner" // "-") ] | @tsv
        '
      )

      if [[ -z "$matches" ]]; then
        [[ $QUIET -eq 0 ]] && echo "   ✔ $crd — No roles grant get/list/watch access"
        continue
      fi

      crd_roles_header_printed=0

      # 4) Build per-(kind|name|ns)
      declare -A ROLE_KIND ROLE_NAME ROLE_NS ROLE_OLM ROLE_SUBJECTS
      while IFS=$'\t' read -r kind name ns olm; do
        rkey="$kind|$name|$ns"
        ROLE_KIND[$rkey]="$kind"
        ROLE_NAME[$rkey]="$name"
        ROLE_NS[$rkey]="$ns"
        ROLE_OLM[$rkey]="$olm"
        [[ -z "${ROLE_SUBJECTS[$rkey]:-}" ]] && ROLE_SUBJECTS[$rkey]=$(get_subjects_for_role "$kind" "$name" "$ns")
      done <<<"$(echo "$matches" | sort -u)"

      # 5) Group by (kind|name)
      declare -A GROUP_NS GROUP_OLM GROUP_ALLOWLIST
      for k in "${!ROLE_KIND[@]}"; do
        kind="${ROLE_KIND[$k]}"; name="${ROLE_NAME[$k]}"; ns="${ROLE_NS[$k]}"; olm="${ROLE_OLM[$k]}"
        g="$kind|$name"
        if [[ -z "${GROUP_NS[$g]}" ]]; then GROUP_NS[$g]="$ns"
        else case ",${GROUP_NS[$g]}," in *,"$ns",*) : ;; *) GROUP_NS[$g]="${GROUP_NS[$g]},$ns" ;; esac
        fi
        [[ "$olm" != "-" ]] && GROUP_OLM[$g]=1
        is_allowlisted_role "$name" && GROUP_ALLOWLIST[$g]=1
      done

      # 6) Sort groups (cluster-admin first, ClusterRole over Role)
      groups=("${!GROUP_NS[@]}")
      sorted_groups=$(for g in "${groups[@]}"; do
          kind="${g%%|*}"; name="${g#*|}"; score=0
          [[ "$kind" == "ClusterRole" ]] && score=$((score+10))
          [[ "$name" == "cluster-admin" ]] && score=$((score+1000))
          is_allowlisted_role "$name" && score=$((score-5))
          printf '%04d\t%s\n' "$score" "$g"
        done | sort -rn | cut -f2)

      # 7) Print each role once; hide empty roles
      while IFS= read -r g; do
        kind="${g%%|*}"; name="${g#*|}"; ns_csv="${GROUP_NS[$g]}"

        # Skip system/operator-managed clusterroles (info only when not quiet)
        if [[ "$kind" == "ClusterRole" && ( -n "${GROUP_OLM[$g]:-}" || "$name" == system:* ) ]]; then
          [[ $QUIET -eq 0 ]] && echo "     - $kind/$name (ns: cluster) -> <skipped system/operator-managed>"
          continue
        fi

        # Pretty ns label
        if [[ "$kind" == "ClusterRole" ]]; then ns_pretty="cluster"
        else ns_pretty=$(echo "$ns_csv" | tr ',' '\n' | awk 'NF' | sort -u | paste -sd',' -)
        fi

        # Build consolidated subject list; if empty -> skip role
        all_subjs=$(
          IFS=',' read -r -a arr <<<"$ns_csv"
          for _ns in "${arr[@]}"; do
            rkey="$kind|$name|$_ns"
            block="${ROLE_SUBJECTS[$rkey]}"
            [[ -z "$block" || "$block" == "<no subjects>" ]] && continue
            while IFS= read -r subj; do
              subj_ns=$(echo "$subj" | sed -n 's/.*(ns: \(.*\)).*/\1/p')
              subj_name=$(echo "$subj" | awk '{print $2}')
              is_excluded_ns "$subj_ns" && continue
              [[ "$subj_name" == system:* ]] && continue
              is_baseline_identity "$subj_name" && continue
              origin="$_ns"; [[ "$kind" == "ClusterRole" ]] && origin="cluster"
              printf '%s|||%s\n' "$origin" "$subj"
            done <<<"$block"
          done
        )

        # Hide roles with no surviving subjects
        [[ -z "$all_subjs" ]] && continue

        # Allowlisted behavior
        if [[ -n "${GROUP_ALLOWLIST[$g]:-}" ]]; then
          [[ $QUIET -eq 1 ]] && continue
          ALLOWLIST_FLAG="[allowlisted]"
        else
          ALLOWLIST_FLAG=""
        fi

        if [[ $crd_roles_header_printed -eq 0 ]]; then
          echo "   ⚠ $crd — Roles granting get/list/watch:"
          crd_roles_header_printed=1
        fi

        echo "     - $kind/$name (ns: $ns_pretty) $ALLOWLIST_FLAG"

        # Deduplicate subjects; prefer canonical variant
        echo "$all_subjs" | awk '
          BEGIN { FS="\\|\\|\\|"; OFS="" }
          function parse(line,   kd,nm,ns){
            split(line,t," ")
            kd=t[1]; gsub(/^\(/,"",kd); gsub(/\)$/,"",kd)
            nm=t[2]
            ns="-"; if (match(line, /\(ns: ([^)]+)\)/, m)) ns=m[1]
            return kd SUBSEP nm SUBSEP ns
          }
          {
            o=$1; line=$2
            key=parse(line)
            iseq=index(line," via = ")>0
            if(!(key in best) || (iseq==1 && best_eq[key]==0)){ best[key]=line; best_eq[key]=iseq }
            if(!(key in origins)){ origins[key]=o }
            else{
              split(origins[key],a,", ")
              found=0; for(i in a) if(a[i]==o) found=1
              if(!found) origins[key]=origins[key] ", " o
            }
          }
          END{
            n=0; for(k in best){ lines[++n]=best[k]; keys[n]=k }
            for(i=1;i<n;i++) for(j=i+1;j<=n;j++) if(lines[i]>lines[j]){
              tmp=lines[i]; lines[i]=lines[j]; lines[j]=tmp
              t2=keys[i]; keys[i]=keys[j]; keys[j]=t2
            }
            for(i=1;i<=n;i++){
              k=keys[i]; print "       * ", lines[i], " (from: ", origins[k], ")"
            }
          }'
      done <<<"$sorted_groups"

      unset ROLE_KIND ROLE_NAME ROLE_NS ROLE_OLM ROLE_SUBJECTS
    done <<<"$SUS_CRDS"

    echo
  fi
fi

if should_run 18; then
  ensure_rbac_cache
  echo "18: Default SA & system:serviceaccounts bindings to privileged roles"

  CHECK18_FOUND_RISK=0

  # Quiet-mode progress indicator (dots); normal mode: show OK/risky only (no dots, no static scanning message)
  if [[ $QUIET -eq 1 ]]; then
    echo -n "     (quiet mode) Check 18: scanning privileged bindings"
    CHECK18_SHOW_PROGRESS=1
  else
    CHECK18_SHOW_PROGRESS=0
  fi

  # Always return 0: under pipefail this can be the last command in a `| while read` iteration (e.g. --quiet).
  check18_debug() {
    if [[ "${DEBUG_CHECK18:-0}" -eq 1 ]]; then
      printf '[debug check18] %s\n' "$*" >&2
    fi
    return 0
  }
  [[ "${DEBUG_CHECK18:-0}" -eq 1 ]] && check18_debug "debug enabled (messages on stderr)"

  # -------------------------------------------------------------------
  # Precompute "privileged" ClusterRoles and Roles ONCE (Optimization 5)
  # -------------------------------------------------------------------
  # Privileged = cluster-admin OR wildcard (verbs/resources/apiGroups/nonResourceURLs) OR can read secrets (get/list/watch/*)
  PRIV_JQ_DEF='
    def arr(x): (x // []) | if type=="array" then . else [.] end;
    def s(a):  arr(a) | map((. // "") | tostring | gsub("\\s+";""));
    def rules: arr(.rules) | map(if type=="object" then . else {} end);
    (.metadata.name == "cluster-admin")
    or ( rules | map( (s(.verbs)|index("*")) or (s(.resources)|index("*")) or (s(.apiGroups)|index("*")) or (s(.nonResourceURLs)|index("*")) ) | any )
    or ( rules | map( (s(.resources)|index("secrets")) and (s(.verbs)|(index("get") or index("list") or index("watch") or index("*"))) ) | any )
  '

  # ClusterRoles → newline list of names (from prefetch)
  PRIV_CR_NAMES=$(
    echo "$ALL_ROLES_AND_CR" | jq -r '
        .items[]
        | select(.kind=="ClusterRole")
        | select(
            '"$PRIV_JQ_DEF"'
          )
        | .metadata.name
      '
  )

  # Roles → newline list of "ns|name"
  PRIV_R_NS_NAMES=$(
    echo "$ALL_ROLES_AND_CR" | jq -r '
        .items[]
        | select(.kind=="Role")
        | select(
            '"$PRIV_JQ_DEF"'
          )
        | (.metadata.namespace + "|" + .metadata.name)
      '
  )

  # Build fast lookup caches
  declare -A PRIV_CR PRIV_R
  while IFS= read -r _n; do [[ -n "$_n" ]] && PRIV_CR["$_n"]=1; done <<<"$PRIV_CR_NAMES"
  while IFS= read -r _k; do [[ -n "$_k" ]] && PRIV_R["$_k"]=1; done <<<"$PRIV_R_NS_NAMES"

  if [[ "${DEBUG_CHECK18:-0}" -eq 1 ]]; then
    _c20_cr=$(printf '%s\n' "$PRIV_CR_NAMES" | grep -c . || true)
    _c20_r=$(printf '%s\n' "$PRIV_R_NS_NAMES" | grep -c . || true)
    check18_debug "privileged ClusterRoles (count): ${_c20_cr}; privileged Roles ns|name rows: ${_c20_r}"
  fi

  # Helper: is a binding's roleRef privileged? (uses caches only; NO kubectl)
  is_privileged_ref() {
    local refKind="$1" refName="$2" refNS="$3"
    if [[ "$refKind" == "ClusterRole" ]]; then
      [[ -n "${PRIV_CR[$refName]:-}" ]]
    else
      [[ -n "${PRIV_R[$refNS|$refName]:-}" ]]
    fi
  }

  # Dangerous-subject jq filter (declared once)
  DANGER_FILTER='
    [
      .[]? |
      select(
        (.kind=="Group" and (.name=="system:serviceaccounts"
          or (.name|startswith("system:serviceaccounts:"))))
        or (.kind=="ServiceAccount" and .name=="default")
      )
    ]
  '

  # --------------------------------------
  # helper to print risky findings
  # --------------------------------------
  report_binding() {
    local scope="$1" ns="$2" name="$3" refKind="$4" refName="$5" subjects_json="$6"
    if [[ "$scope" == "cluster" ]]; then
      printf '%s\n' "$subjects_json" \
      | jq -r --arg ref "$name" '
          .[] |
          "(\\(.kind)) \\(.name) (ns: \\(.namespace // "-")) via ClusterRoleBinding=" + $ref
        ' | sed 's/^/ ⚠ /'
    else
      printf '%s\n' "$subjects_json" \
      | jq -r --arg ref "$name" '
          .[] |
          "(\\(.kind)) \\(.name) (ns: \\(.namespace // "-")) via RoleBinding=" + $ref
        ' | sed 's/^/ ⚠ /'
    fi
  }

  # ======================================================
  # ClusterRoleBindings scan (single JSON parse) (Opt 6)
  # ======================================================
  # Emit TSV: name, refKind, refName, subjects_json_string (cached bindings)
  echo "$ALL_CRB" | jq -r '.items[]
           | [ .metadata.name
             , .roleRef.kind
             , .roleRef.name
             , ((.subjects // []) | tojson)
             ] | @tsv' \
  | while IFS=$'\t' read -r name refKind refName subjects_str; do

      [[ $CHECK18_SHOW_PROGRESS -eq 1 ]] && echo -n "."

      # Fast privileged check (no kubectl/jq on role object)
      if ! is_privileged_ref "$refKind" "$refName" "cluster"; then
        continue
      fi

      # subjects_str is a JSON string → convert to JSON array
      subjects_json=$(jq -c 'if type=="string" then fromjson else . end' <<<"$subjects_str")
      if [[ "${DEBUG_CHECK18:-0}" -eq 1 ]]; then
        _sn=$(printf '%s\n' "$subjects_json" | jq 'length' 2>/dev/null || echo "?")
        check18_debug "privileged ClusterRoleBinding: name=$name roleRef=$refKind/$refName subjects=${_sn}"
      fi

      # Dangerous hits?
      hits=$(printf '%s\n' "$subjects_json" | jq -c "$DANGER_FILTER")
      if [[ "$hits" != "[]" ]]; then
        CHECK18_FOUND_RISK=1
        check18_debug "danger-filter HIT: ClusterRoleBinding=$name hits=$hits"
        [[ $CHECK18_SHOW_PROGRESS -eq 1 ]] && echo ""
        report_binding "cluster" "-" "$name" "$refKind" "$refName" "$hits"
      else
        check18_debug "privileged but NO dangerous default/system:sa subjects: ClusterRoleBinding=$name $refKind/$refName"
        if [[ $QUIET -eq 0 ]]; then
          echo " (i) Privileged role $refKind/$refName has NO dangerous system/default SA subjects."
          if [[ "$subjects_json" == "[]" ]]; then
            echo "     (no bound subjects)"
          else
            echo "     Bound subjects:"
            printf '%s\n' "$subjects_json" | jq -r '
              .[] |
              "       - (" + (.kind // "-") + ") "
                        + (.name // "-")
                        + " (ns: " + (.namespace // "-") + ")"
            '
          fi
        fi
      fi
    done

  # ======================================================
  # RoleBindings scan (single JSON parse) (Opt 6 + early ns skip)
  # ======================================================
  # Emit TSV: ns, name, refKind, refName, subjects_json_string
  echo "$ALL_RB" | jq -r '.items[]
           | [ .metadata.namespace
             , .metadata.name
             , .roleRef.kind
             , .roleRef.name
             , ((.subjects // []) | tojson)
             ] | @tsv' \
  | while IFS=$'\t' read -r ns name refKind refName subjects_str; do

      [[ $CHECK18_SHOW_PROGRESS -eq 1 ]] && echo -n "."

      # Optimization 4 — skip excluded namespaces ASAP
      if is_excluded_ns "$ns"; then
        check18_debug "skip RoleBinding (excluded ns): ns=$ns binding=$name"
        continue
      fi

      # Fast privileged check
      if ! is_privileged_ref "$refKind" "$refName" "$ns"; then
        continue
      fi

      subjects_json=$(jq -c 'if type=="string" then fromjson else . end' <<<"$subjects_str")
      if [[ "${DEBUG_CHECK18:-0}" -eq 1 ]]; then
        _sn=$(printf '%s\n' "$subjects_json" | jq 'length' 2>/dev/null || echo "?")
        check18_debug "privileged RoleBinding: ns=$ns name=$name roleRef=$refKind/$refName subjects=${_sn}"
      fi

      hits=$(printf '%s\n' "$subjects_json" | jq -c "$DANGER_FILTER")
      if [[ "$hits" != "[]" ]]; then
        CHECK18_FOUND_RISK=1
        check18_debug "danger-filter HIT: RoleBinding=$name (ns=$ns) hits=$hits"
        [[ $CHECK18_SHOW_PROGRESS -eq 1 ]] && echo ""
        report_binding "ns" "$ns" "$name" "$refKind" "$refName" "$hits"
      else
        check18_debug "privileged but NO dangerous default/system:sa subjects: RoleBinding=$name (ns=$ns) $refKind/$refName"
        if [[ $QUIET -eq 0 ]]; then
          echo " (i) Privileged role $refKind/$refName (ns=$ns) has NO dangerous system/default SA subjects."
          if [[ "$subjects_json" == "[]" ]]; then
            echo "     (no bound subjects)"
          else
            echo "     Bound subjects:"
            printf '%s\n' "$subjects_json" | jq -r '
              .[] |
              "       - (" + (.kind // "-") + ") "
                        + (.name // "-")
                        + " (ns: " + (.namespace // "-") + ")"
            '
          fi
        fi
      fi
    done

  # Quiet-mode final summary line
  if [[ $CHECK18_SHOW_PROGRESS -eq 1 ]]; then
    if [[ $CHECK18_FOUND_RISK -eq 1 ]]; then
      echo ""
    else
      echo " → no risky bindings found"
    fi
  fi

  echo
fi

if should_run 19; then
  ensure_rbac_cache
  echo "19: Workloads using risky ServiceAccounts (exposed via RBAC)"

  EXPOSE_FOUND=0

  check19_debug() {
    if [[ "${DEBUG_CHECK19:-0}" -eq 1 ]]; then
      printf '[debug check19] %s\n' "$*" >&2
    fi
    return 0
  }
  [[ "${DEBUG_CHECK19:-0}" -eq 1 ]] && check19_debug "debug enabled (messages on stderr)"

  # -----------------------------
  # 1) jq helpers + risk predicates (top-level defs)
  # -----------------------------
  RISK_DEF_COMMON='
    def arr(x): (x // []) | if type=="array" then . else [.] end;
    def s(a):  arr(a) | map((. // "") | tostring | gsub("\\s+";""));
    def rules: arr(.rules) | map(if type=="object" then . else {} end);
  '
  PRIV_PREDICATE="$RISK_DEF_COMMON"'
    (.metadata.name == "cluster-admin")
    or ( rules | map( (s(.verbs)|index("*")) or (s(.resources)|index("*"))
                      or (s(.apiGroups)|index("*")) or (s(.nonResourceURLs)|index("*")) ) | any )
    or ( rules | map( (s(.resources)|index("secrets")) and
                      (s(.verbs)|(index("get") or index("list") or index("watch") or index("*"))) ) | any )
  '
  SECRETREAD_PREDICATE="$RISK_DEF_COMMON"'
    rules | map( (s(.resources)|index("secrets")) and
                 (s(.verbs)|(index("get") or index("list") or index("watch") or index("*"))) ) | any
  '
  PODSUB_PREDICATE="$RISK_DEF_COMMON"'
    ( rules | map( ((s(.resources)|index("pods/ephemeralcontainers") or index("pods/attach")
                    or index("pods/portforward") or index("pods/proxy") or index("pods/*") or index("*")))
                   and ((s(.verbs)|index("create") or index("update") or index("patch") or index("*"))) ) | any )
    or
    ( rules | map( ((s(.resources)|index("endpoints") or index("endpointslices") or index("*")))
                   and ((s(.verbs)|index("get") or index("list") or index("watch") or index("*"))) ) | any )
  '
  TOKEN_PREDICATE="$RISK_DEF_COMMON"'
    rules | map( ((s(.resources)|index("serviceaccounts/token")) and (s(.verbs)|index("create")))
                 or ((s(.resources)|index("tokenrequests")) and (s(.verbs)|index("create"))) ) | any
  '

  compute_risky_clusterroles() {
    local predicate="$1"
    echo "$ALL_ROLES_AND_CR" | jq -r "$RISK_DEF_COMMON (.items // [])[] | select(.kind==\"ClusterRole\") | select( $predicate ) | .metadata.name" \
    2>/dev/null || true
  }
  compute_risky_roles() {
    local predicate="$1"
    echo "$ALL_ROLES_AND_CR" | jq -r "$RISK_DEF_COMMON (.items // [])[] | select(.kind==\"Role\") | select( $predicate ) | (.metadata.namespace + \"|\" + .metadata.name)" \
    2>/dev/null || true
  }

  PRIV_CR_NAMES=$(compute_risky_clusterroles "$PRIV_PREDICATE")
  PRIV_R_NS_NAMES=$(compute_risky_roles       "$PRIV_PREDICATE")
  SEC_CR_NAMES=$(compute_risky_clusterroles   "$SECRETREAD_PREDICATE")
  SEC_R_NS_NAMES=$(compute_risky_roles        "$SECRETREAD_PREDICATE")
  POD_CR_NAMES=$(compute_risky_clusterroles   "$PODSUB_PREDICATE")
  POD_R_NS_NAMES=$(compute_risky_roles        "$PODSUB_PREDICATE")
  TOK_CR_NAMES=$(compute_risky_clusterroles   "$TOKEN_PREDICATE")
  TOK_R_NS_NAMES=$(compute_risky_roles        "$TOKEN_PREDICATE")

  declare -A CR_PRIV CR_SEC CR_POD CR_TOK R_PRIV R_SEC R_POD R_TOK
  while IFS= read -r n;  do [[ -n "$n"  ]] && CR_PRIV["$n"]=1; done <<<"$PRIV_CR_NAMES"
  while IFS= read -r n;  do [[ -n "$n"  ]] && CR_SEC["$n"]=1;  done <<<"$SEC_CR_NAMES"
  while IFS= read -r n;  do [[ -n "$n"  ]] && CR_POD["$n"]=1;  done <<<"$POD_CR_NAMES"
  while IFS= read -r n;  do [[ -n "$n"  ]] && CR_TOK["$n"]=1;  done <<<"$TOK_CR_NAMES"
  while IFS= read -r nk; do [[ -n "$nk" ]] && R_PRIV["$nk"]=1; done <<<"$PRIV_R_NS_NAMES"
  while IFS= read -r nk; do [[ -n "$nk" ]] && R_SEC["$nk"]=1;  done <<<"$SEC_R_NS_NAMES"
  while IFS= read -r nk; do [[ -n "$nk" ]] && R_POD["$nk"]=1;  done <<<"$POD_R_NS_NAMES"
  while IFS= read -r nk; do [[ -n "$nk" ]] && R_TOK["$nk"]=1;  done <<<"$TOK_R_NS_NAMES"

  if [[ "${DEBUG_CHECK19:-0}" -eq 1 ]]; then
    check19_debug "risky role counts (CR / Role ns|name lines): priv=$(printf '%s\n' "$PRIV_CR_NAMES" | grep -c .)/$(printf '%s\n' "$PRIV_R_NS_NAMES" | grep -c .) sec=$(printf '%s\n' "$SEC_CR_NAMES" | grep -c .)/$(printf '%s\n' "$SEC_R_NS_NAMES" | grep -c .) pod=$(printf '%s\n' "$POD_CR_NAMES" | grep -c .)/$(printf '%s\n' "$POD_R_NS_NAMES" | grep -c .) tok=$(printf '%s\n' "$TOK_CR_NAMES" | grep -c .)/$(printf '%s\n' "$TOK_R_NS_NAMES" | grep -c .)"
  fi

  risk_categories_for_ref() {
    local kind="$1" name="$2" ns="$3" parts=()
    if [[ "$kind" == "ClusterRole" ]]; then
      [[ -n "${CR_PRIV[$name]:-}" ]] && parts+=("privileged")
      [[ -n "${CR_SEC[$name]:-}"  ]] && parts+=("secrets-read")
      [[ -n "${CR_POD[$name]:-}"  ]] && parts+=("pod-subresources")
      [[ -n "${CR_TOK[$name]:-}"  ]] && parts+=("token-mint")
    else
      local key="$ns|$name"
      [[ -n "${R_PRIV[$key]:-}" ]] && parts+=("privileged")
      [[ -n "${R_SEC[$key]:-}"  ]] && parts+=("secrets-read")
      [[ -n "${R_POD[$key]:-}"  ]] && parts+=("pod-subresources")
      [[ -n "${R_TOK[$key]:-}"  ]] && parts+=("token-mint")
    fi
    (IFS=,; echo "${parts[*]}")
  }

  # Allowlist regex compiled once for backpointer matching (Option A)
  build_allowlist_ere() {
    # Escape ERE metacharacters; commas -> '|'; '*' -> '.*' (third pass; '*' is escaped first).
    # Bracket class must be [] then [ — not ][ — or sed reports an unterminated `s' command.
    printf '%s' "${ALLOWLIST_ROLES:-}" \
      | sed 's/[][\^$.|?*+(){}]/\\&/g; s/,/|/g; s/\*/.*/g'
  }
  ALLOWLIST_ERE="$(build_allowlist_ere)"

  # Risk stores
  declare -A RISKY_SA RISKY_NS_ALLSA
  RISKY_CLUSTER_ALLSA=""
  declare -A AFFECTED_BINDINGS AFFECTED_BINDINGS_NS_ALLSA
  AFFECTED_BINDINGS_CLUSTER_ALLSA=""

  merge_csv()  { (echo "$1"; echo "$2") | tr ',' '\n' | awk 'NF' | sort -u | paste -sd',' -; }
  merge_list() { (printf '%s\n' "$1" | tr ';' '\n'; printf '%s\n' "$2" | tr ';' '\n') \
                  | sed 's/^[[:space:]]\+//;s/[[:space:]]\+$//' | awk 'NF' | sort -u | paste -sd' ; ' -; }

  # CSV set operations used for the enhancement
  csv_union() { (printf '%s\n' "$1"; printf '%s\n' "$2") | tr ',' '\n' | awk 'NF' | sort -u | paste -sd',' -; }
  csv_diff()  {
    local A="$1" B="$2"
    comm -23 <(tr ',' '\n' <<<"$A" | awk 'NF' | sort -u) <(tr ',' '\n' <<<"$B" | awk 'NF' | sort -u) | paste -sd',' -
  }

  process_binding_tsv() {
    # scope="cluster": a=name, b=refKind, c=refName, d=subjects_json
    # scope="ns"     : a=ns, b=name,  c=refKind, d=refName,    e=subjects_json
    local scope="$1"
    while IFS=$'\t' read -r a b c d e; do
      local ns="" bname refKind refName subjects_str
      if [[ "$scope" == "cluster" ]]; then
        bname="$a"; refKind="$b"; refName="$c"; subjects_str="$d"
      else
        ns="$a";   bname="$b"; refKind="$c"; refName="$d"; subjects_str="$e"
        is_excluded_ns "$ns" && continue
      fi

      local risk_csv=""
      if [[ "$refKind" == "ClusterRole" ]]; then
        risk_csv=$(risk_categories_for_ref "$refKind" "$refName" "cluster")
      else
        [[ -z "$ns" ]] && continue
        risk_csv=$(risk_categories_for_ref "$refKind" "$refName" "$ns")
      fi
      [[ -z "$risk_csv" ]] && { check19_debug "skip binding (no risk categories): scope=$scope $bname -> $refKind/$refName"; continue; }

      local subjects_json
      subjects_json=$(jq -c 'if type=="string" then fromjson else . end' <<<"$subjects_str" 2>/dev/null || echo '[]')

      while IFS=$'\t' read -r skind sname sns; do
        local bp
        if [[ "$scope" == "cluster" ]]; then
          bp="ClusterRoleBinding=$bname → $refKind/$refName"
        else
          bp="RoleBinding=$bname (ns=$ns) → $refKind/$refName"
        fi

        # system:serviceaccounts (cluster)
        if [[ "$skind" == "Group" && "$sname" == "system:serviceaccounts" ]]; then
          check19_debug "merge cluster-wide ALL SA risks: +[$risk_csv] via $bp"
          RISKY_CLUSTER_ALLSA="$(merge_csv "$RISKY_CLUSTER_ALLSA" "$risk_csv")"
          AFFECTED_BINDINGS_CLUSTER_ALLSA="$(merge_list "$AFFECTED_BINDINGS_CLUSTER_ALLSA" "$bp")"
          continue
        fi
        # system:serviceaccounts:<ns>
        if [[ "$skind" == "Group" && "$sname" == system:serviceaccounts:* ]]; then
          local gns="${sname#system:serviceaccounts:}"
          check19_debug "merge ns-wide ALL SA risks: ns=$gns +[$risk_csv] via $bp"
          RISKY_NS_ALLSA["$gns"]="$(merge_csv "${RISKY_NS_ALLSA[$gns]:-}" "$risk_csv")"
          AFFECTED_BINDINGS_NS_ALLSA["$gns"]="$(merge_list "${AFFECTED_BINDINGS_NS_ALLSA[$gns]:-}" "$bp")"
          continue
        fi
        # Specific ServiceAccount
        if [[ "$skind" == "ServiceAccount" ]]; then
          local key
          if [[ "$sns" != "-" ]]; then key="$sns|$sname"
          elif [[ "$scope" == "ns" && -n "$ns" ]]; then key="$ns|$sname"
          else continue; fi
          check19_debug "merge per-SA risks: key=$key +[$risk_csv] via $bp"
          RISKY_SA["$key"]="$(merge_csv "${RISKY_SA[$key]:-}" "$risk_csv")"
          AFFECTED_BINDINGS["$key"]="$(merge_list "${AFFECTED_BINDINGS[$key]:-}" "$bp")"
        fi
      done < <(printf '%s\n' "$subjects_json" | jq -r '.[]? | [ (.kind // "-"), (.name // "-"), (.namespace // "-") ] | @tsv' 2>/dev/null)
    done
  }

  # Feed bindings from prefetch (single parse → TSV; no subshell state loss)
  crb_tsv="$(
    echo "$ALL_CRB" | jq -r '(.items // [])[] | [ .metadata.name, .roleRef.kind, .roleRef.name, ((.subjects // []) | tojson) ] | @tsv' \
    2>/dev/null || true
  )"
  process_binding_tsv "cluster" <<< "$crb_tsv"
  rb_tsv="$(
    echo "$ALL_RB" | jq -r '(.items // [])[] | [ .metadata.namespace, .metadata.name, .roleRef.kind, .roleRef.name, ((.subjects // []) | tojson) ] | @tsv' \
    2>/dev/null || true
  )"
  process_binding_tsv "ns" <<< "$rb_tsv"

  if [[ "${DEBUG_CHECK19:-0}" -eq 1 ]]; then
    check19_debug "after binding ingest: RISKY_SA keys=${#RISKY_SA[@]} RISKY_NS_ALLSA=${#RISKY_NS_ALLSA[@]} cluster_csv=${RISKY_CLUSTER_ALLSA:-<empty>}"
  fi

  # -----------------------------
  # 2) Consolidated summaries (cluster-wide and ns-wide)
  # -----------------------------
  print_cluster_summary() {
    local risks="$1" bps="$2"
    local pods dep ds sts jobs cjs
    pods=$( ($K get pods         -A --no-headers 2>/dev/null || true) | wc -l | tr -d ' ' )
    dep=$( ($K get deployments   -A --no-headers 2>/dev/null || true) | wc -l | tr -d ' ' )
    ds=$( ($K get daemonsets     -A --no-headers 2>/dev/null || true) | wc -l | tr -d ' ' )
    sts=$( ($K get statefulsets  -A --no-headers 2>/dev/null || true) | wc -l | tr -d ' ' )
    jobs=$( ($K get jobs         -A --no-headers 2>/dev/null || true) | wc -l | tr -d ' ' )
    cjs=$( ($K get cronjobs      -A --no-headers 2>/dev/null || true) | wc -l | tr -d ' ' )
    echo " ⚠ All ServiceAccounts in the entire cluster are risky — RBAC risk: $risks (via subject: system:serviceaccounts)"
    echo "    ↳ backpointers: $bps"
    echo "    Affects workloads: pods=$pods, deployments=$dep, daemonsets=$ds, statefulsets=$sts, jobs=$jobs, cronjobs=$cjs"
    EXPOSE_FOUND=1
  }

  print_ns_summary() {
    local ns="$1" risks="$2" bps="$3"
    local pods dep ds sts jobs cjs
    pods=$( ($K get pods        -n "$ns" --no-headers 2>/dev/null || true) | wc -l | tr -d ' ' )
    dep=$( ($K get deployments  -n "$ns" --no-headers 2>/dev/null || true) | wc -l | tr -d ' ' )
    ds=$( ($K get daemonsets    -n "$ns" --no-headers 2>/dev/null || true) | wc -l | tr -d ' ' )
    sts=$( ($K get statefulsets -n "$ns" --no-headers 2>/dev/null || true) | wc -l | tr -d ' ' )
    jobs=$( ($K get jobs        -n "$ns" --no-headers 2>/dev/null || true) | wc -l | tr -d ' ' )
    cjs=$( ($K get cronjobs     -n "$ns" --no-headers 2>/dev/null || true) | wc -l | tr -d ' ' )
    echo " ⚠ All ServiceAccounts in namespace '$ns' are risky — RBAC risk: $risks (via subject: system:serviceaccounts:$ns)"
    echo "    ↳ backpointers: $bps"
    echo "    Affects workloads: pods=$pods, deployments=$dep, daemonsets=$ds, statefulsets=$sts, jobs=$jobs, cronjobs=$cjs"
    EXPOSE_FOUND=1
  }

  # Cluster-wide consolidation
  if [[ -n "$RISKY_CLUSTER_ALLSA" ]]; then
    print_cluster_summary "$RISKY_CLUSTER_ALLSA" "$AFFECTED_BINDINGS_CLUSTER_ALLSA"
  fi

  # Namespace-wide consolidation
  if [[ ${#RISKY_NS_ALLSA[@]} -gt 0 ]]; then
    for ns in $(printf '%s\n' "${!RISKY_NS_ALLSA[@]}" | sort); do
      print_ns_summary "$ns" "${RISKY_NS_ALLSA[$ns]}" "${AFFECTED_BINDINGS_NS_ALLSA[$ns]}"
    done
  fi

  # -----------------------------
  # 3) Per-SA exposures (Option 2 + Enhancement)
  #    - Always evaluate per-SA items, even if cluster/ns-wide summaries exist.
  #    - Show ONLY SAs that have an explicit binding (RISKY_SA).
  #    - Show ONLY incremental risk categories (those not already provided by cluster/ns-wide).
  #    - Quiet mode filters by allowlist via backpointers (Option A).
  # -----------------------------
  suppress_by_allowlist_bp() {
    local bps="$1"
    if [[ -n "$ALLOWLIST_ERE" && $QUIET -eq 1 ]]; then
      grep -Eq "$ALLOWLIST_ERE" <<< "$bps" && return 0
    fi
    return 1
  }

  base_risks_for_ns() {
    local ns="$1"
    local base="$RISKY_CLUSTER_ALLSA"
    if [[ -n "${RISKY_NS_ALLSA[$ns]:-}" ]]; then
      base="$(csv_union "$base" "${RISKY_NS_ALLSA[$ns]}")"
    fi
    printf '%s' "$base"
  }

  print_exposure() {
    local ns="$1" kind="$2" name="$3" sa="$4" reasons="$5" backpointers="$6"
    EXPOSE_FOUND=1
    echo " ⚠ ($ns) $kind/$name uses SA $sa — RBAC risk: $reasons"
    [[ -n "$backpointers" ]] && echo "        ↳ backpointers: $backpointers"
  }

  # Pods
  while IFS=$'\t' read -r ns kind name sa; do
    key="$ns|$sa"
    rs1="${RISKY_SA[$key]:-}"              # per-SA reasons only
    [[ -z "$rs1" ]] && continue            # only explicit SA bindings
    # Enhancement: show only incremental categories vs union(cluster-wide, ns-wide for this ns)
    base="$(base_risks_for_ns "$ns")"
    rs1_new="$(csv_diff "$rs1" "$base")"
    [[ -z "$rs1_new" ]] && { check19_debug "skip Pod (no incremental risk vs cluster/ns-wide): $ns/$name SA=$sa rs1=$rs1 base_union=$base"; continue; }
    bps1="${AFFECTED_BINDINGS[$key]:-}"    # per-SA backpointers only
    [[ -z "$bps1" ]] && { check19_debug "skip Pod (no backpointers): $ns/$name SA=$sa"; continue; }
    if suppress_by_allowlist_bp "$bps1"; then
      check19_debug "skip Pod (quiet allowlist match on backpointers): $ns/$name SA=$sa"
      continue
    fi
    print_exposure "$ns" "$kind" "$name" "$sa" "$rs1_new" "$bps1"
  done < <(
    $K get pods -A -o json 2>/dev/null \
    | jq -r '(.items // [])[] | [ .metadata.namespace, "Pod", .metadata.name, (.spec.serviceAccountName // "default") ] | @tsv' \
    2>/dev/null
  )

  # Controllers
  while IFS=$'\t' read -r ns kind name sa; do
    key="$ns|$sa"
    rs1="${RISKY_SA[$key]:-}"
    [[ -z "$rs1" ]] && continue
    base="$(base_risks_for_ns "$ns")"
    rs1_new="$(csv_diff "$rs1" "$base")"
    [[ -z "$rs1_new" ]] && { check19_debug "skip workload (no incremental risk vs cluster/ns-wide): $ns $kind/$name SA=$sa rs1=$rs1 base_union=$base"; continue; }
    bps1="${AFFECTED_BINDINGS[$key]:-}"
    [[ -z "$bps1" ]] && { check19_debug "skip workload (no backpointers): $ns $kind/$name SA=$sa"; continue; }
    if suppress_by_allowlist_bp "$bps1"; then
      check19_debug "skip workload (quiet allowlist match on backpointers): $ns $kind/$name SA=$sa"
      continue
    fi
    print_exposure "$ns" "$kind" "$name" "$sa" "$rs1_new" "$bps1"
  done < <(
    {
      $K get deployments  -A -o json 2>/dev/null | jq -r '(.items // [])[] | [ .metadata.namespace, "Deployment",  .metadata.name, (.spec.template.spec.serviceAccountName // "default") ] | @tsv'
      $K get daemonsets   -A -o json 2>/dev/null | jq -r '(.items // [])[] | [ .metadata.namespace, "DaemonSet",   .metadata.name, (.spec.template.spec.serviceAccountName // "default") ] | @tsv'
      $K get statefulsets -A -o json 2>/dev/null | jq -r '(.items // [])[] | [ .metadata.namespace, "StatefulSet", .metadata.name, (.spec.template.spec.serviceAccountName // "default") ] | @tsv'
      $K get jobs         -A -o json 2>/dev/null | jq -r '(.items // [])[] | [ .metadata.namespace, "Job",         .metadata.name, (.spec.template.spec.serviceAccountName // "default") ] | @tsv'
      $K get cronjobs     -A -o json 2>/dev/null | jq -r '(.items // [])[] | [ .metadata.namespace, "CronJob",     .metadata.name, (.spec.jobTemplate.spec.template.spec.serviceAccountName // "default") ] | @tsv'
    } 2>/dev/null
  )

  # Final OK (always print even in quiet)
  if [[ $EXPOSE_FOUND -eq 0 ]]; then
    echo " ✔ No workloads found using ServiceAccounts with risky RBAC"
  fi

  echo
fi

# All checks complete
echo "===== RBAC Audit Complete (Vanilla) ====="
