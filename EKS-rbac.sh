#!/usr/bin/env bash

# Record audit start time in nanoseconds for final execution duration calculation
START_TIME_NS=$(date +%s%N)

##########################################################################
# KUBERNETES RBAC AUDIT SCRIPT — ARCHITECTURE, SEMANTICS & USAGE GUIDE
#
# This script performs a deep RBAC audit on Kubernetes/EKS clusters.
# The logic is optimized, safe, and explicit about what Kubernetes RBAC
# *can* and *cannot* do. Please read this section carefully before making
# modifications or interpreting results.
#
# ========================================================================
# 1. HOW KUBERNETES RBAC *ACTUALLY* WORKS — IMPORTANT FOUNDATIONS
# ========================================================================
#
# Kubernetes RBAC NEVER performs:
#
#   ✘ privilege inheritance
#   ✘ recursion or transitive permissions
#   ✘ delegation across roles
#   ✘ “indirect” or “cross-role” privilege flows
#   ✘ permissions due to matching subjects in other roles
#
# These mechanisms DO NOT EXIST in Kubernetes.
#
# The ONLY privilege path is:
#
#       ROLE  →  Binding (RoleBinding/ClusterRoleBinding)  →  SUBJECT
#
# A subject gets a permission **only** if:
#
#   (A) A Role/ClusterRole defines a rule (verbs + resources)
#   (B) A Binding references that role via roleRef.name
#   (C) The subject is listed in that binding
#
# There is NO transitive evaluation. NO inheritance. NO escalation across
# different roles. Every privilege is a DIRECT edge.
#
#
# ========================================================================
# 2. WHAT “via = …” AND “via ≠ …” REALLY MEAN IN THIS SCRIPT
# ========================================================================
#
# When the script prints subjects under a role, you may see:
#
#     via = <bindingName>
#     via ≠ <bindingName>
#
# These DO NOT indicate different privilege origins.
# They DO NOT represent “indirect” vs “direct” permissions.
#
# They mean ONLY this:
#
#     via = X     → The binding’s metadata.name MATCHES the role’s name
#     via ≠ X     → The binding’s metadata.name DIFFERS from the role’s name
#
# BOTH bindings reference the SAME ROLE and grant the SAME permissions.
# This annotation is purely cosmetic to help group/clean output. It is NOT
# an RBAC semantic concept. Kubernetes makes NO distinction.
#
#
# ========================================================================
# 3. SUBJECT RESOLUTION — WHAT THE SCRIPT DOES (AND DOESN'T DO)
# ========================================================================
#
# For a role named R, subjects are collected ONLY via:
#
#   • ClusterRoleBindings where roleRef.name == R
#   • RoleBindings       where roleRef.name == R
#
# The script DOES NOT:
#
#   ✘ pull subjects from other roles
#   ✘ infer or guess permission across roles
#   ✘ resolve indirect chains
#   ✘ “merge” permission graphs
#
# All subject entries under a role block correspond to DIRECT RBAC edges.
#
#
# ========================================================================
# 4. WHY “(from: dev,prod,test)” APPEARS IN OUTPUT
# ========================================================================
#
# A Role with the same name in multiple namespaces is *one logical role*
# for audit purposes. Instead of printing it 3 times, the script merges:
#
#     Role/myRole (ns: dev,prod,test)
#
# Subject lines then show:
#
#     (from: dev, prod, test)
#
# This means:
#     “This subject appeared in RoleBindings for this role name in these
#      namespaces.”
#
# It does NOT mean:
#     “the subject inherited privileges across namespaces.” (Impossible)
#
#
# ========================================================================
# 5. WHY ROLES WITH NO SUBJECTS ARE HIDDEN
# ========================================================================
#
# A role that can read a CRD but has ZERO subjects:
#     → cannot leak anything
#     → cannot be exploited
#     → is pure noise
#
# Therefore, roles with no surviving subjects after filtering are **hidden**
# in Check 18 and 19.
#
#
# ========================================================================
# 6. ALLOWLIST BEHAVIOR FOR CONTROLLERS (QUIET MODE)
# ========================================================================
#
# Some components (ArgoCD, Istio, Kyverno, Cilium, AWS controllers, etc.)
# MUST read secrets, CRDs, webhooks, endpoints, etc. These appear noisy but
# are expected. Patterns are defined in ALLOWLIST_ROLES.
#
# Quiet Mode (--quiet):
#     → allowlisted roles are hidden
#
# Normal Mode:
#     → allowlisted roles appear with “[allowlisted]”
#
#
# ========================================================================
# 7. PERFORMANCE DESIGN — WHY CHECK 19 IS ALWAYS SAFE TO RUN
# ========================================================================
#
# This script pre-fetches all RBAC objects once:
#
#     ALL_ROLES_AND_CR   ← all ClusterRoles + Roles
#     ALL_CRB            ← all ClusterRoleBindings
#     ALL_RB             ← all RoleBindings
#
# All expensive checks (17,18,19) run IN-MEMORY with no additional kubectl
# calls. Therefore, Check 19 can always enumerate RBAC readers without the
# need for previous "--crd-rbac" flag.
#
#
# ========================================================================
# SECURITY ANALYST QUICKSTART
# ========================================================================
#
# This script answers:
#
#     “WHO in this cluster can perform WHICH dangerous action?”
#
# Key outputs:
#
#   ⚠   → A real security concern (role grants risky privileges)
#   *   → A subject that actually receives the privilege
#   ns: → Namespaces in which the role appears
# (from:) → Where the subject-bound bindings were found
#
#
# HIGH-VALUE CHECKS:
# ------------------
#   1  → system:masters exposures in RBAC
#   2  → EKS aws-auth ConfigMap (mapRoles/mapUsers → system:masters); not all AWS/EKS access paths
#   4  → Non-system users with cluster-admin
#   6  → pod exec
#   9  → secrets read (get/list/watch)
#   16 → token minting
#   18 → sensitive pod subresources + endpoints
#   19 → CRD-based secret/credential exposure  (MOST IMPORTANT)
#   20 → privileged serviceaccount bindings
#
#
# USE MODES:
# ----------
# ./EKS-rbac.sh
#       → Full audit
#
# ./EKS-rbac.sh --quiet
#       → Only actionable findings (hides system/operator roles)
#
# ./EKS-rbac.sh --checks=19
#       → CRD exposure audit only
#
# ./EKS-rbac.sh --critical
#       → Only high-severity checks
#
#
# NOTES FOR ANALYSTS:
# -------------------
# • “via =/≠” does NOT imply indirect privileges.
# • “from:” shows WHERE bindings were found, not privilege flow.
# • A role with no subjects is ignored — it exposes nothing.
# • Allowlisted roles are expected controller noise.
# • EKS check 2 reads kube-system/aws-auth only for entries mapping to system:masters. It does not cover
#   every path to cluster admin (e.g. EKS access APIs / AccessEntry, IRSA, node/instance roles, broader IAM).
#
#
# ========================================================================
# MAINTAINER NOTES
# ========================================================================
#
# 1) SAFE EDITING GUIDELINES
# --------------------------
# • NEVER introduce cross-role privilege logic. RBAC is not transitive.
# • ALWAYS use get_subjects_for_role() when resolving subjects.
# • NEVER add kubectl calls inside loops — rely on cached ALL_* objects.
# • KEEP the “hide empty roles” logic in Check 18/19.
#
#
# 2) HOW TO ADD A NEW CHECK
# --------------------------
# • Add:   if should_run N; then ... fi
# • Use ALL_ROLES_AND_CR for rules evaluation.
# • Use get_subjects_for_role for subject listing.
# • Respect quiet mode and allowlist patterns.
#
#
# 3) HOW SUBJECT CONSOLIDATION WORKS
# -----------------------------------
# For each role:
#    • All namespaces where the role name appears are merged.
#    • Subjects across those namespaces are merged.
#    • Canonical binding entries override mismatched names.
#    • Origins record the namespaces from which each subject came.
#
#
# 4) MODIFYING THE ALLOWLIST
# --------------------------
# ALLOWLIST_ROLES is a comma-separated list of glob patterns, e.g.:
#     istiod-*, kyverno-*, cilium-*, argo-cd-*
#
# These represent controller/operator roles that frequently appear with
# wildcard rules or CRD reads. They are hidden in quiet mode.
#
#
# 5) DEBUGGING TIPS
# -----------------
# • bash -n EKS-rbac.sh
#       Validate syntax.
#
# • K=/path/to/kubectl ./EKS-rbac.sh
#       Use a different kubectl binary.
#
# • DEBUG_CHECK20=1 / DEBUG_CHECK21=1 (or --debug-check20 / --debug-check21):
#       Verbose Check 20 / 21 diagnostics on stderr.
#
##########################################################################

# Exit immediately on any unhandled error; propagate failures through pipelines (kubectl | jq | …).
set -e
set -o pipefail

# Allow overriding kubectl via env: K=/path/to/kubectl ./EKS-rbac.sh
K="${K:-kubectl}"

# ------------------------------------------------------------
# Robust flag parsing
#   --checks        (numbers with ranges) e.g. "1,3-5,17,20"
#   --list-checks   or --list
#   --quiet         (suppress OK/Info and "skipped system/operator-managed" lines)
#   --critical      (run only critical checks; NOTE: Check 19 is skipped in this mode)
#   --debug-check20 (debug output for Check 20)
#   --debug-check21 (debug output for Check 21)
# ------------------------------------------------------------
# Default values for all CLI flags before argument parsing
CHECKS_SPEC=""
LIST_CHECKS=0
QUIET=0
CRITICAL_ONLY=0
# Debug: env DEBUG_CHECK20=1 / DEBUG_CHECK21=1 or flags below (flags win if both set)
[[ "${DEBUG_CHECK20:-}" == "1" ]] && DEBUG_CHECK20=1 || DEBUG_CHECK20=0
[[ "${DEBUG_CHECK21:-}" == "1" ]] && DEBUG_CHECK21=1 || DEBUG_CHECK21=0

# Parse all CLI arguments; unknown flags are silently ignored for forward-compatibility
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
    --debug-check20)
      DEBUG_CHECK20=1
      shift
      ;;
    --debug-check21)
      DEBUG_CHECK21=1
      shift
      ;;
    -h|--help)
      SHOW_HELP=1
      shift
      ;;
    *)
      # Unknown flags are ignored for forward-compatibility
      shift
      ;;
  esac
done

# If --help/-h was passed, print usage text and exit immediately
if [[ ${SHOW_HELP:-0} -eq 1 ]]; then
  cat <<'EOF'
Kubernetes/EKS RBAC Security Audit
----------------------------------

Usage:
  EKS-rbac.sh [--checks LIST] [--critical] [--quiet] [--debug-check20] [--debug-check21]
                [--help | -h]

Flags:
  --checks=LIST      Run only specific checks; LIST can contain numbers,
                     ranges, comma-separated groups (e.g. 1,3-5,10).
  --critical         Run only high-severity checks (1,2,4,16,17,18,20,21; not 19).
  --quiet            Hide allowlisted/system-managed roles and OK lines.
  --debug-check20    Verbose Check 20 diagnostics on stderr (or DEBUG_CHECK20=1).
  --debug-check21    Verbose Check 21 diagnostics on stderr (or DEBUG_CHECK21=1).
  -h, --help         Show this help and exit.

Examples:
  EKS-rbac.sh --quiet
  EKS-rbac.sh --checks=19
  EKS-rbac.sh --checks=1,2,4-6 --quiet

Description:
  This script performs a comprehensive RBAC audit of a Kubernetes/EKS
  cluster, including secret/credential CRD exposure, wildcard detection,
  pod exec & sensitive subresources, token minting, cluster-admin misuse,
  and more. Check 2 scans aws-auth mapRoles/mapUsers for system:masters only—not a full AWS/EKS access audit.
  See header comments for full details on semantics.
EOF
  exit 0
fi

# ------------------------------
# Selection builder
# ------------------------------
declare -A RUN
RUN_ALL=0

# --- Fix for add_check_id
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
      start="${BASH_REMATCH[1]}"; end="${BASH_REMATCH[2]}"
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

# ------------------------------
# Critical set wiring
# NOTE: Check 19 is intentionally excluded from the critical set.
# ------------------------------
CRITICAL_CHECKS=(1 2 4 16 17 18 20 21)  # 19 omitted by design

if [[ $CRITICAL_ONLY -eq 1 ]]; then
  RUN_ALL=0
  unset RUN
  declare -A RUN
  for c in "${CRITICAL_CHECKS[@]}"; do
    RUN["$c"]=1
  done
fi

# Returns 0 (true) if the given check ID should be executed under the current run mode
should_run() {
  local id="$1"
  if [[ $RUN_ALL -eq 1 ]]; then return 0; fi
  [[ -n "${RUN[$id]:-}" ]] && return 0 || return 1
}

# If --list/--list-checks was passed, print the full check catalogue and exit
if [[ $LIST_CHECKS -eq 1 ]]; then
  cat <<'EOF'
Available checks (use --checks to select, comma-separated, ranges allowed):
  1  : RBAC bindings referencing system:masters (ClusterRoleBindings/RoleBindings)
  2  : EKS aws-auth mapRoles/mapUsers → system:masters only (not full AWS/EKS admin paths)
  3  : System groups do NOT have cluster-admin
  4  : No non-system subjects have cluster-admin
  5  : No custom subjects can create workload resources (pods/deployments/statefulsets)
  6  : No permission to exec into pods (pods/exec)
  7  : Only control-plane can create persistentvolumes
  8  : No 'escalate' on clusterroles; no 'bind' on (cluster)rolebindings; no impersonate
  9  : No custom subjects can read secrets (get|list|watch|*)
  10 : No subject should patch namespaces
  11 : No subject should CRUD validating/mutating webhook configurations
  12 : No subject should create tokenreviews
  13 : No subject should create subjectaccessreviews
  14 : Restricted access to nodes (read: get|list|watch and write: patch)
  15 : Read access to kube-system configmaps (RB & CRB paths) [optimized]
  16 : ServiceAccount token minting (serviceaccounts/token, tokenrequests)
  17 : Enhanced wildcards (arrays) + nonResourceURLs wildcards
  18 : Sensitive subresources (pods/ephemeralcontainers, attach, portforward, proxy) + endpoints
  19 : CRD-based secret/credential exposure (heuristic) + RBAC read grants
  20 : Default SA & system:serviceaccounts bindings to privileged roles (with informational output)
  21 : Workloads using risky ServiceAccounts via RBAC, with backpointers
EOF
  exit 0
fi

# Print audit banner: cluster context, active user, selected checks, quiet mode, and output legend
echo "===== Kubernetes/EKS RBAC Security Audit ====="
echo "Context: $($K config current-context 2>/dev/null || echo unknown)"
echo "User: $($K config view --minify -o jsonpath='{.users[0].name}' 2>/dev/null || echo unknown)"
if [[ $RUN_ALL -eq 0 ]]; then
  echo "Selected checks: $(printf '%s\n' "${!RUN[@]}" | sort -n | paste -sd, -)"
  if [[ $CRITICAL_ONLY -eq 1 ]]; then echo "(--critical active: running only critical checks)"; fi
else
  echo "(No --checks specified: running ALL checks)"
fi
if [[ $QUIET -eq 1 ]]; then echo "(--quiet active: suppressing OK/Info and 'skipped system/operator-managed' lines)"; fi
echo
echo "Legend:"
echo " ⚠ Check reported potential issues"
if [[ $QUIET -eq 0 ]]; then echo " ✔ OK / no issues"; fi
echo " = Role name = binding name"
echo " ≠ Role name ≠ binding name"
echo " [known EKS platform break-glass] = IAM→system:masters / cluster-admin path (still listed; not suppressed)"
echo
echo "Platform break-glass (documented, not filtered):"
echo "  • Check 2: aws-auth mapRoles/mapUsers → system:masters (IAM bridge to cluster-admin)"
echo "  • Check 1: Group system:masters bindings; ClusterRole/cluster-admin"
echo "  • EKS has no AKS-style ClusterRole/aks-service; break-glass is mainly aws-auth + cluster-admin"
echo

##############################################
# Excluded namespaces
##############################################
EXCLUDED_NS=(
  "kube-system"
  "kube-public"
  "kube-node-lease"
  "aws-load-balancer-controller"
  "external-dns"
  "karpenter"
  "metrics-server"
  "cluster-autoscaler"
)

# Add operator-managed namespaces dynamically (no-op on EKS unless OLM installed)
while IFS= read -r _op_ns; do
  [[ -n "$_op_ns" ]] && EXCLUDED_NS+=("$_op_ns")
done < <(
  $K get ns -o json 2>/dev/null \
    | jq -r '.items[] | select(.metadata.labels."olm.owner") | .metadata.name' 2>/dev/null \
    || true
)

# Allow callers to inject more excludes via env var (comma-separated)
if [[ -n "${EXTRA_EXCLUDED_NS:-}" ]]; then
  IFS=',' read -r -a _extra <<< "$EXTRA_EXCLUDED_NS"
  EXCLUDED_NS+=("${_extra[@]}")
fi

echo "Excluding system/operator namespaces from checks: ${EXCLUDED_NS[*]}"
echo

# -----------------------------------------------------------------
# RBAC PREFETCH CACHE (single kubectl calls with safe JSON fallback)
# -----------------------------------------------------------------
# Used by get_subjects_for_role() and Check 19.
ALL_CRB="$($K get clusterrolebinding -o json 2>/dev/null || echo '{"items": []}')"
ALL_RB="$($K get rolebinding -A -o json 2>/dev/null || echo '{"items": []}')"
ALL_ROLES_AND_CR="$($K get clusterrole,role -A -o json 2>/dev/null || echo '{"items": []}')"

# Wildcard-safe namespace exclusion
is_excluded_ns() {
  local ns="$1"
  for ex in "${EXCLUDED_NS[@]}"; do
    if [[ "$ex" == *"*"* ]]; then
      # Escape regex meta chars except *, then translate * to .*
      local safe_ex
      safe_ex="$(printf '%s' "$ex" | sed -e 's/[.[\^$+?(){|]/\\&/g' -e 's/*/.*/g')"
      [[ "$ns" =~ ^${safe_ex}$ ]] && return 0
    else
      [[ "$ns" == "$ex" ]] && return 0
    fi
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
# Known EKS platform break-glass (annotate only — never suppress)
##############################################
# Primary surface is aws-auth → system:masters (Check 2) and ClusterRole/cluster-admin.
platform_breakglass_role_note() {
  case "$1" in
    cluster-admin) printf '%s' " [known Kubernetes break-glass ClusterRole]" ;;
  esac
}

platform_breakglass_subject_note() {
  case "$1" in
    system:masters) printf '%s' " [known EKS/Kubernetes platform break-glass]" ;;
  esac
}

extract_subject_name() {
  local s="$1" n
  n=$(printf '%s\n' "$s" | sed -nE 's/.*\((User|Group|ServiceAccount)\)[[:space:]]+([^[:space:]]+).*/\2/p')
  if [[ -n "$n" ]]; then
    printf '%s' "$n"
    return
  fi
  printf '%s\n' "$s" | awk '{print $2}'
}

print_rbac_role_finding() {
  local kind="$1" name="$2" ns="$3" extra="${4:-}"
  echo " - $kind/$name (ns: $ns)${extra}$(platform_breakglass_role_note "$name")"
}

print_rbac_subject_finding() {
  local subj="$1"
  local name
  name=$(extract_subject_name "$subj")
  echo " * ${subj}$(platform_breakglass_subject_note "$name")"
}


##############################################
# Allowlist for benign/noisy controller roles (used in Check 19 RBAC print)
##############################################
ALLOWLIST_ROLES="\
system:node,system:node-proxier,system:kube-controller-manager,system:kube-scheduler,system:kube-proxy,system:coredns,system:aggregated-metrics-reader,system:public-info-viewer,\
eks:cloud-controller-manager,eks:addon-manager,eks:service-operations,kube-proxy,\
aws-load-balancer-controller-role,aws-load-balancer-controller-rolebinding,cluster-autoscaler,\
cilium,cilium-*,cilium-operator,hubble-ui,hubble-relay,\
istiod,istiod-*,istio-reader-*,istio-gateway-*,\
argo-cd-application-controller,argo-cd-applicationset-controller,argo-cd-server,argocd-ecr-updater,argocd-dex-server,\
kyverno-*,kyverno-background-controller,kyverno-cleanup-controller,kyverno-0-eks-kyverno:*,\
keda-operator,keda-operator-certs,keda-*,\
external-dns,external-dns-viewer,\
external-secrets,external-secrets-controller,external-secrets-cert-controller,\
datadog,datadog-*,datadog-cluster-agent,datadog-ksm-core,\
trivy-operator,trivy-adapter,\
reloader-*,reloader-0-eks-reloader-role,\
k8sensor,instana-*,policy-reporter-*,coredns-eks-coredns,nginx-gateway-internal"

is_allowlisted_role() {
  local name="$1"
  IFS=',' read -r -a _arr <<< "$ALLOWLIST_ROLES"
  for pat in "${_arr[@]}"; do
    # Patterns are globs (e.g. reloader-*); unquoted $pat is required for glob matching.
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
###############################################################
# SUBJECT CACHE + RBAC LOOKUP WITHOUT ADDITIONAL kubectl CALLS
###############################################################
declare -A SUBJECT_CACHE

get_subjects_for_role() {
  local kind="$1"
  local name="$2"
  local ns="$3"

  # cache key
  local key="${kind}|${name}|${ns}"

  # return cached value if present
  if [[ -n "${SUBJECT_CACHE[$key]:-}" ]]; then
    echo "${SUBJECT_CACHE[$key]}"
    return
  fi

  local subjects

  if [[ "$kind" == "ClusterRole" ]]; then
    # Lookup subjects bound to this ClusterRole via $ALL_CRB
    subjects=$(echo "$ALL_CRB" \
      | jq -r --arg ROLE "$name" '
          .items[]
          | select(.roleRef.name == $ROLE)
          | . as $b
          | (.subjects // [])[]?
          | {kind:.kind,name:.name,namespace:(.namespace//"-"),binding:($b.metadata.name)}
      ' | jq -s 'unique_by(.kind + .name + .namespace + .binding)')
  else
    # Lookup subjects bound to this namespaced Role via $ALL_RB
    subjects=$(echo "$ALL_RB" \
      | jq -r --arg ROLE "$name" --arg NS "$ns" '
          .items[]
          | select(.metadata.namespace == $NS)
          | select(.roleRef.name == $ROLE)
          | . as $b
          | (.subjects // [])[]?
          | {kind:.kind,name:.name,namespace:(.namespace//"-"),binding:($b.metadata.name)}
      ' | jq -s 'unique_by(.kind + .name + .namespace + .binding)')
  fi

  if [[ -z "$subjects" || "$subjects" == "[]" ]]; then
    SUBJECT_CACHE["$key"]="<no subjects>"
    echo "<no subjects>"
    return
  fi

  # Convert to the formatted list
  local formatted
  formatted=$(echo "$subjects" \
    | jq -r --arg ROLE "$name" '.[] |
        if .binding == $ROLE
        then "(\(.kind)) \(.name) (ns: \(.namespace)) via = \(.binding)"
        else "(\(.kind)) \(.name) (ns: \(.namespace)) via ≠ \(.binding)"
        end')

  SUBJECT_CACHE["$key"]="$formatted"
  echo "$formatted"
}

##############################################
# Generic permission check helper (supports comma-separated verbs)
##############################################
check_permission() {
  local verbs_in="$1"    # may be "verb" or "v1,v2,v3,*"
  local resource="$2"
  local msg="$3"
  local empty_msg="${4:-✔ No matching roles found.}"
  local matches
  local ap_key="${verbs_in}:${resource}"
  echo "Checking: $msg ($verbs_in $resource)"
  if [[ -n "${ATTACK_PATH[$ap_key]:-}" ]]; then
    echo "  Attack path: ${ATTACK_PATH[$ap_key]}"
  fi

  matches=$(
    $K get clusterrole,role -A -o json \
    | jq -r --arg verbs "$verbs_in" --arg res "$resource" '
      def anyWanted($arr; $verbs):
        ($verbs | split(",") | map(select(. != ""))) as $want
        | ( ($arr // []) as $have
            | ( [ $want[] | $have | index(.) ] | any ) or ($have | index("*")) );

      .items[] as $role
      | ($role.rules // []) as $rules
      | ( [ $rules[]?
            | ( anyWanted((.verbs // []); $verbs) )
              and
              ( ((.resources // []) | (index($res) or index("*"))) )
          ] | any ) as $has
      | select($has == true)
      | [ $role.kind,
          $role.metadata.name,
          ($role.metadata.namespace // "cluster"),
          ($role.metadata.labels."olm.owner" // "-")
        ] | @tsv
    '
  )

  if [[ -z "$matches" ]]; then
    if [[ $QUIET -eq 0 ]]; then
      echo " $empty_msg"
    fi
    echo
    return
  fi

  local SYSTEM_ROLES=(
    "admin"
    "edit"
    "view"
    "cluster-admin"
    "basic-user"
    "cluster-reader"
    "system:discovery"
    "system:heapster"
    "system:node"
    "system:controller"
    "system:aggregate-to-admin"
    "system:aggregate-to-edit"
    "system:aggregate-to-view"
  )

  _clusterrole_is_system_managed_name() {
    local cand="$1" r
    for r in "${SYSTEM_ROLES[@]}"; do
      [[ "$r" == "$cand" ]] && return 0
    done
    return 1
  }

  local roles_header_printed=0
  echo "$matches" | sort -u | while IFS=$'\t' read -r kind name ns olm; do
    if [[ "$kind" == "ClusterRole" ]]; then
      if [[ "$olm" != "-" || "$name" == system:* ]] || _clusterrole_is_system_managed_name "$name"; then
        if [[ $QUIET -eq 0 ]]; then
          echo " - $kind/$name (ns: $ns) -> <skipped system/operator-managed clusterrole>"
        fi
        continue
      fi
    else
      if [[ -n "$ns" ]] && is_excluded_ns "$ns"; then continue; fi
    fi

    local subjects filtered_subjects
    subjects=$(get_subjects_for_role "$kind" "$name" "$ns")
    if [[ "$subjects" != "<no subjects>" ]]; then
      filtered_subjects=$(echo "$subjects" | while read -r subj; do
        local subj_ns subj_name
        subj_ns=$(echo "$subj" | sed -n 's/.*(ns: \(.*\)).*/\1/p')
        subj_name=$(echo "$subj" | awk '{print $2}')
        is_excluded_ns "$subj_ns" && continue
        [[ "$subj_name" == system:* ]] && continue
        is_baseline_identity "$subj_name" && continue
        echo "$subj"
      done)
    else
      filtered_subjects=""
    fi

    if [[ $QUIET -eq 1 ]]; then
      if [[ "$subjects" == "<no subjects>" || -z "$filtered_subjects" ]]; then
        continue
      fi
    fi

    if [[ $roles_header_printed -eq 0 ]]; then
      echo " ⚠ Roles with this permission:"
      roles_header_printed=1
    fi

    print_rbac_role_finding "$kind" "$name" "$ns"
    if [[ "$subjects" == "<no subjects>" ]]; then
      if [[ $QUIET -eq 0 ]]; then echo " <no subjects>"; fi
      continue
    fi
    if [[ -z "$filtered_subjects" ]]; then
      if [[ $QUIET -eq 0 ]]; then echo " ✔ All subjects are in excluded namespaces"; fi
    else
      echo "$filtered_subjects" | while read -r subj; do print_rbac_subject_finding "$subj"; done
    fi
  done
  echo
}

# =====================================================================
# CHECKS 1..20
# =====================================================================
# Each check is guarded by should_run N so only selected checks execute.
# Findings are printed inline; ⚠ marks issues, ✔ marks clean results.

# Check 1: Detect any ClusterRoleBinding or RoleBinding that grants the system:masters group,
# which bypasses all RBAC authorization in Kubernetes.
if should_run 1; then
  echo "1: RBAC bindings referencing system:masters"
  out=$(
    $K get clusterrolebindings,rolebindings -A -o json \
    | jq -r '
        .items[] as $b
        | (.subjects // [])[]? | select(.kind=="Group" and .name=="system:masters")
        | "\($b.kind) \($b.metadata.name) (ns: \($b.metadata.namespace // "-")) -> roleRef=\($b.roleRef.kind)/\($b.roleRef.name)"
      '
  )
  if [[ -z "$out" ]]; then
    if [[ $QUIET -eq 0 ]]; then echo " ✔ None found in RBAC bindings"; fi
  else
    printf "%s\n" "$out" | while IFS= read -r line; do
      [[ -z "$line" ]] && continue
      echo " ⚠ ${line} [known EKS/Kubernetes platform break-glass]"
    done
  fi
  echo
fi

# Check 2: Scan aws-auth ConfigMap (mapRoles / mapUsers) for mappings to system:masters (cluster-admin via IAM bridge).
# Does not enumerate all EKS/AWS paths to admin (AccessEntry, IRSA, node roles, etc.).
if should_run 2; then
  echo "2: EKS aws-auth mappings that grant system:masters"
  if [[ $QUIET -eq 0 ]]; then
    echo " (Check 2 scope: kube-system/aws-auth mapRoles/mapUsers only; not full AWS/EKS access picture—see script header.)"
  fi
  if $K -n kube-system get configmap aws-auth >/dev/null 2>&1; then
    out=$(
      $K -n kube-system get configmap aws-auth -o json \
      | jq -r '
          # Helper: parse YAML-like list strings stored in ConfigMap data.
          def report_items($kind; s):
            (s // "")
            | ( if length == 0 then [] else
                  (split("\n- ") | map(if startswith("- ") then .[2:] else . end))
                end ) as $chunks
            | ($chunks
               | map(select(type=="string"))
               | map(select(test("system:masters")))
               | map({
                   kind: $kind,
                   raw: .,
                   rolearn:   ( . | capture("(?mi)^\\s*rolearn:\\s*(?<v>\\S+)")?.v   // "-" ),
                   userarn:   ( . | capture("(?mi)^\\s*userarn:\\s*(?<v>\\S+)")?.v   // "-" ),
                   username:  ( . | capture("(?mi)^\\s*username:\\s*(?<v>\\S+)")?.v  // "-" )
                 })
              );

          .data as $d
          | (report_items("mapRoles"; $d."mapRoles")) as $r
          | (report_items("mapUsers"; $d."mapUsers")) as $u
          | ($r + $u)
          | if length == 0 then
              "✔ No aws-auth entries into system:masters found"
            else
              ( .[]
                | " ⚠ aws-auth grants system:masters -> "
                  + (if .rolearn != "-" then .rolearn else .userarn end)
                  + " ; username=" + .username
                  + " (from " + .kind + ") [known EKS platform break-glass]"
              )
            end
        '
    )
    if [[ $QUIET -eq 1 ]]; then
      echo "$out" | grep -v '^✔ ' || true
    else
      echo "$out"
    fi
  else
    echo " (No aws-auth ConfigMap found or not an EKS control-plane context)"
  fi
  echo
fi

# Check 3: Verify that broad system groups (authenticated, unauthenticated, anonymous,
# all serviceaccounts) are NOT bound to cluster-admin.
if should_run 3; then
  echo "3: System groups do NOT have cluster-admin"
  check_system_group() {
    local group="$1"
    local hits
    echo " Checking: $group"
    hits=$(
      $K get clusterrolebinding -o json \
      | jq -r --arg GRP "$group" '
          .items[]
          | select( (.subjects // []) | any(.kind=="Group" and .name==$GRP) )
          | select(.roleRef.name=="cluster-admin")
          | select(.metadata.labels."olm.owner"? | not)
          | .metadata.name
        '
    )
    if [[ -z "$hits" ]]; then
      if [[ $QUIET -eq 0 ]]; then echo "  ✔ OK"; fi
    else
      echo "  ⚠ VIOLATION: $group has cluster-admin:"
      echo "$hits" | sed 's/^/   - /'
    fi
  }
  for grp in system:authenticated system:unauthenticated system:anonymous system:serviceaccounts; do
    check_system_group "$grp"
  done
  echo
fi

# Check 4: Find non-system (i.e. custom) subjects bound to cluster-admin via ClusterRoleBindings,
# excluding OLM-managed and system: prefixed subjects.
if should_run 4; then
  echo "4: No non-system subjects have cluster-admin…"
  found=0
  while IFS= read -r line; do
    ns=$(echo "$line" | sed -n 's/.*(ns: \(.*\)).*/\1/p')
    binding_olm=$(echo "$line" | awk '{print $NF}')
    if is_excluded_ns "$ns"; then continue; fi
    if [[ "$binding_olm" != "-" ]]; then continue; fi
    print_rbac_subject_finding "$line"
    found=1
  done < <(
    $K get clusterrolebinding -o json \
    | jq -r '
        .items[]
        | select(.roleRef.name=="cluster-admin") as $b
        | (.subjects // [])[]?
        | select(.name | startswith("system:") | not)
        | "\(.kind) \(.name) (ns: \(.namespace // "-")) via ClusterRoleBinding: \($b.metadata.name) \($b.metadata.labels."olm.owner" // "-")"
      ' | sort -u
  )
  if [[ $found -eq 0 ]]; then
    if [[ $QUIET -eq 0 ]]; then echo " ✔ OK: No custom subjects have cluster-admin."; fi
  fi
  echo
fi

# Check 5: Identify roles that allow creating pods, deployments, or statefulsets,
# as these can be used to introduce privileged workloads into the cluster.
if should_run 5; then
  echo "5: No custom subjects can create workload resources"
  for res in pods deployments statefulsets; do
    check_permission create "$res" "No custom subjects should create workload resources ($res)"
  done
fi

# Check 6: Find roles that allow pods/exec, which enables arbitrary command execution
# inside running containers — a critical lateral-movement vector.
if should_run 6; then
  check_permission create pods/exec "6: No subjects should have permission to exec into pods"
fi

# Check 7: Verify only control-plane components can create PersistentVolumes;
# unrestricted PV creation can expose host paths or cloud storage.
if should_run 7; then
  check_permission create persistentvolumes "7: Only control plane components should create persistentvolumes"
fi

# Check 8: Detect privilege-escalation verbs (escalate, bind) on role resources and
# impersonate verb on users/groups/serviceaccounts — all allow bypassing intended RBAC boundaries.
if should_run 8; then
  echo "8: No escalate/bind/impersonate permissions"
  check_permission escalate clusterroles "No subject should have 'escalate' verb on clusterroles"
  check_permission bind clusterrolebindings "No subject should have 'bind' verb on clusterrolebindings" "✔ No subjects found with bind permissions"
  check_permission bind rolebindings "No subject should have 'bind' verb on rolebindings" "✔ No subjects found with bind permissions"
  for res in users groups serviceaccounts userextras; do
    check_permission impersonate "$res" "No subject should 'impersonate' verb on $res"
  done
fi

# Check 9: Find roles that can read Secrets (get/list/watch/*); reading secrets enables
# credential harvesting for service accounts, TLS keys, and API tokens.
# ---------- Optimized Check 9 ----------
if should_run 9; then
  echo "9: No custom subjects can read secrets"
  # Combined read verbs: get | list | watch | *
  check_permission "get,list,watch,*" secrets \
    "No custom subjects should be able to read secrets (any of: get|list|watch|*)"
  echo
fi

# Check 10: Detect roles that can patch namespaces; namespace labels/annotations control
# admission policies (e.g. PodSecurity, Kyverno) so patching them can disable security controls.
if should_run 10; then
  check_permission patch namespaces "10: No subject should patch namespaces"
fi

# Check 11: Identify roles that can create/update/patch/delete ValidatingWebhookConfigurations
# or MutatingWebhookConfigurations — modifying these can intercept or silently mutate all API calls.
if should_run 11; then
  echo "11: No subject should CRUD webhook configurations"
  for res in validatingwebhookconfigurations mutatingwebhookconfigurations; do
    for verb in create delete update patch; do
      check_permission "$verb" "$res" "No subject should $verb $res"
    done
  done
fi

# Check 12: Find roles that can create TokenReviews; this allows a subject to validate
# arbitrary bearer tokens and probe for valid credentials cluster-wide.
if should_run 12; then
  check_permission create tokenreviews "12: No subject should create tokenreviews"
fi

# Check 13: Find roles that can create SubjectAccessReviews; this allows a subject to
# enumerate what permissions any other identity holds — useful for privilege mapping attacks.
if should_run 13; then
  check_permission create subjectaccessreviews "13: No subject should create subjectaccessreviews"
fi

# Check 14: Detect over-permissive node access: read access (get/list/watch) exposes
# pod/token inventory; patch access can modify node taints, labels, and conditions.
# ---------- Optimized Check 14 ----------
if should_run 14; then
  echo "14: Restricted access to nodes"
  # Combined read verbs
  check_permission "get,list,watch,*" nodes \
    "No subject should get/list/watch nodes (read access)"
  # Write verb remains separate (do not consolidate)
  check_permission patch nodes \
    "No subject should patch nodes"
  echo
fi

# Check 15: Find subjects that can read ConfigMaps in kube-system; these may contain
# kubeconfig data, bootstrap tokens, or other sensitive cluster configuration.
# ---------- Optimized Check 15 ----------
if should_run 15; then
  echo "15: Read access to kube-system configmaps (RoleBindings and ClusterRoleBindings)"

  # Pre-fetch Roles in kube-system and ClusterRoles once
  ROLES_JSON=$($K get role -n kube-system -o json 2>/dev/null || echo '{"items":[]}')
  CROLE_JSON=$($K get clusterrole -o json 2>/dev/null || echo '{"items":[]}')
  RB_JSON=$($K get rolebinding -n kube-system -o json 2>/dev/null || echo '{"items":[]}')
  CRB_JSON=$($K get clusterrolebinding -o json 2>/dev/null || echo '{"items":[]}')

  # Build lookup sets of Role/ClusterRole names that grant get|list|watch|* on configmaps
  ALLOW_ROLES=$(echo "$ROLES_JSON" | jq -r '
    .items[]
    | select([ .rules[]?
               | ((.resources // []) | index("configmaps") or index("*"))
               and ((.verbs // []) | (index("get") or index("list") or index("watch") or index("*")))
             ] | any)
    | .metadata.name
  ' | sort -u)

  ALLOW_CROLES=$(echo "$CROLE_JSON" | jq -r '
    .items[]
    | select([ .rules[]?
               | ((.resources // []) | index("configmaps") or index("*"))
               and ((.verbs // []) | (index("get") or index("list") or index("watch") or index("*")))
             ] | any)
    | .metadata.name
  ' | sort -u)

  # Print kube-system RoleBindings that reference allowed Roles/ClusterRoles
  echo "  Checking kube-system RoleBindings…"
  echo "$RB_JSON" \
  | jq -rc '
      .items[] |
      { binding: .metadata.name,
        refKind: .roleRef.kind,
        refName: .roleRef.name,
        subjects: (.subjects // []) }
    ' \
  | while IFS= read -r json; do
      refKind=$(echo "$json" | jq -r '.refKind')
      refName=$(echo "$json" | jq -r '.refName')

      allowed=0
      if [[ "$refKind" == "Role" ]]; then
        if echo "$ALLOW_ROLES" | grep -qx "$refName"; then allowed=1; fi
      else
        if echo "$ALLOW_CROLES" | grep -qx "$refName"; then allowed=1; fi
      fi
      if [[ $allowed -eq 0 ]]; then continue; fi

      # Emit subjects
      echo "$json" | jq -r '
        .binding as $b |
        (.subjects // [])[]? |
        "(\(.kind)) \(.name) (ns: \(.namespace // "-")) via RoleBinding=" + $b
      ' | sed 's/^/ ⚠ /'
    done
  echo

  echo "  Checking ClusterRoleBindings granting global configmap access…"
  echo "$CRB_JSON" \
  | jq -rc '
      .items[] |
      { binding: .metadata.name,
        refName: .roleRef.name,
        subjects: (.subjects // []) }
    ' \
  | while IFS= read -r json; do
      ref=$(echo "$json" | jq -r '.refName')
      if echo "$ALLOW_CROLES" | grep -qx "$ref"; then
        echo "$json" | jq -r '
          .binding as $b |
          (.subjects // [])[]? |
          "(\(.kind)) \(.name) (ns: \(.namespace // "-")) via ClusterRoleBinding=" + $b
        ' | sed 's/^/ ⚠ /'
      fi
    done
  echo
fi

# Check 16: Detect roles that can mint ServiceAccount tokens (serviceaccounts/token or
# tokenrequests); minting tokens allows impersonating any SA the subject can target.
if should_run 16; then
  echo "16: ServiceAccount token minting (TokenVolumeProjection)"
  check_permission create "serviceaccounts/token" "No subjects should be allowed to mint service account tokens"
  check_permission create "tokenrequests" "No subjects should be allowed to create tokenrequests" "✔ No roles found with tokenrequests create"
fi

# Check 17: Detect roles using wildcards (*) in verbs, resources, apiGroups, or
# nonResourceURLs — wildcards silently cover future resource types and API additions.
if should_run 17; then
  echo "17: Enhanced wildcard usage (arrays, apiGroups, nonResourceURLs)"
  wild_rules=$(
    $K get clusterrole,role -A -o json 2>/dev/null \
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
          ] | @tsv
      '
  )
  if [[ -z "$wild_rules" ]]; then
    if [[ $QUIET -eq 0 ]]; then echo " ✔ No critical wildcard usage detected."; fi
    echo
  else
    echo "$wild_rules" \
    | awk -F'\t' '!seen[$2,$3,$4,$5,$6,$7]++' \
    | while IFS=$'\t' read -r kind name ns verbs resources apigroups nresurls olm; do
        if [[ "$kind" == "ClusterRole" ]] && { [[ "$olm" != "-" ]] || [[ "$name" == system:* ]]; }; then
          if [[ $QUIET -eq 0 ]]; then
            echo " - $kind/$name (ns: $ns) -> <skipped system/operator-managed>"
          fi
          continue
        fi
        print_rbac_role_finding "$kind" "$name" "$ns" " (rule: verbs=$verbs, resources=$resources, apiGroups=$apigroups, nonResourceURLs=$nresurls)"
        subjects=$(get_subjects_for_role "$kind" "$name" "${ns:-cluster}")
        if [[ "$subjects" == "<no subjects>" ]]; then
          if [[ $QUIET -eq 0 ]]; then echo " <no subjects>"; fi
          continue
        fi
        filtered_subjects=$(echo "$subjects" | while read -r subj; do
          subj_ns=$(echo "$subj" | sed -n 's/.*(ns: \(.*\)).*/\1/p')
          is_excluded_ns "$subj_ns" && continue
          subj_name=$(echo "$subj" | awk '{print $2}')
          [[ "$subj_name" == system:* ]] && continue
          is_baseline_identity "$subj_name" && continue
          echo "$subj"
        done)
        if [[ -z "$filtered_subjects" ]]; then
          if [[ $QUIET -eq 0 ]]; then echo " ✔ All subjects are system/operator accounts or in excluded namespaces"; fi
        else
          echo "$filtered_subjects" | while read -r s; do print_rbac_subject_finding "$s"; done
        fi
      done
    echo
  fi
fi

# ---------- Optimized Check 18 (Consolidated + subject origins; hides empty roles) ----------
if should_run 18; then
  echo "18: Sensitive subresources (ephemeralcontainers, attach, portforward, proxy) + endpoints"

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
            is_excluded_ns "$subj_ns" && continue
            subj_name=$(echo "$subj" | awk '{print $2}')
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

      echo "     - $kind/$name (ns: $ns_pretty) $AL$(platform_breakglass_role_note "$name")"

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

# Check 19: Heuristically detect CRDs whose names/schemas suggest they store secrets or
# credentials, then identify which roles can read them — the highest-value check for
# detecting secret exfiltration paths through custom resources.
# ---------- Optimized Check 19 (Consolidated + subject origins; hides empty roles; no --crd-rbac) ----------
if should_run 19; then
  echo "19: CRD-based secret/credential exposure (heuristic) + RBAC read grants"

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
              is_excluded_ns "$subj_ns" && continue
              subj_name=$(echo "$subj" | awk '{print $2}')
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

        echo "     - $kind/$name (ns: $ns_pretty) $ALLOWLIST_FLAG$(platform_breakglass_role_note "$name")"

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

# Check 20: Find privileged roles (cluster-admin, wildcard, secrets-read) bound to the
# default ServiceAccount or the system:serviceaccounts group — these are common misconfigurations
# that grant broad permissions to every workload that doesn't explicitly set a ServiceAccount.
# ---------- Check 20 (privileged SA bindings; optimized with precomputed privileged roles + single-parse bindings) ----------
if should_run 20; then
  echo "20: Default SA & system:serviceaccounts bindings to privileged roles"

  CHECK20_FOUND_RISK=0

  # Quiet-mode progress indicator (dots); normal mode: show OK/risky only (no dots, no static scanning message)
  if [[ $QUIET -eq 1 ]]; then
    echo -n "     (quiet mode) Check 20: scanning privileged bindings"
    CHECK20_SHOW_PROGRESS=1
  else
    CHECK20_SHOW_PROGRESS=0
  fi

  # Always return 0: under pipefail this can be the last command in a `| while read` iteration (e.g. --quiet).
  check20_debug() {
    if [[ "${DEBUG_CHECK20:-0}" -eq 1 ]]; then
      printf '[debug check20] %s\n' "$*" >&2
    fi
    return 0
  }
  [[ "${DEBUG_CHECK20:-0}" -eq 1 ]] && check20_debug "debug enabled (messages on stderr)"

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

  # ClusterRoles → newline list of names
  PRIV_CR_NAMES=$(
    $K get clusterrole -o json 2>/dev/null \
    | jq -r '
        .items[]
        | select(
            '"$PRIV_JQ_DEF"'
          )
        | .metadata.name
      '
  )

  # Roles → newline list of "ns|name"
  PRIV_R_NS_NAMES=$(
    $K get role -A -o json 2>/dev/null \
    | jq -r '
        .items[]
        | select(
            '"$PRIV_JQ_DEF"'
          )
        | (.metadata.namespace + "|" + .metadata.name)
      '
  )

  # Build fast lookup caches
  declare -A PRIV_CR PRIV_R
  while IFS= read -r _n; do if [[ -n "$_n" ]]; then PRIV_CR["$_n"]=1; fi; done <<<"$PRIV_CR_NAMES"
  while IFS= read -r _k; do if [[ -n "$_k" ]]; then PRIV_R["$_k"]=1; fi; done <<<"$PRIV_R_NS_NAMES"

  if [[ "${DEBUG_CHECK20:-0}" -eq 1 ]]; then
    _c20_cr=$(printf '%s\n' "$PRIV_CR_NAMES" | grep -c . || true)
    _c20_r=$(printf '%s\n' "$PRIV_R_NS_NAMES" | grep -c . || true)
    check20_debug "privileged ClusterRoles (count): ${_c20_cr}; privileged Roles ns|name rows: ${_c20_r}"
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
  # Emit TSV: name, refKind, refName, subjects_json_string
  $K get clusterrolebinding -o json 2>/dev/null \
  | jq -r '.items[]
           | [ .metadata.name
             , .roleRef.kind
             , .roleRef.name
             , ((.subjects // []) | tojson)
             ] | @tsv' \
  | while IFS=$'\t' read -r name refKind refName subjects_str; do

      [[ $CHECK20_SHOW_PROGRESS -eq 1 ]] && echo -n "."

      # Fast privileged check (no kubectl/jq on role object)
      if ! is_privileged_ref "$refKind" "$refName" "cluster"; then
        continue
      fi

      # subjects_str is a JSON string → convert to JSON array
      subjects_json=$(jq -c 'if type=="string" then fromjson else . end' <<<"$subjects_str")
      if [[ "${DEBUG_CHECK20:-0}" -eq 1 ]]; then
        _sn=$(printf '%s\n' "$subjects_json" | jq 'length' 2>/dev/null || echo "?")
        check20_debug "privileged ClusterRoleBinding: name=$name roleRef=$refKind/$refName subjects=${_sn}"
      fi

      # Dangerous hits?
      hits=$(printf '%s\n' "$subjects_json" | jq -c "$DANGER_FILTER")
      if [[ "$hits" != "[]" ]]; then
        CHECK20_FOUND_RISK=1
        check20_debug "danger-filter HIT: ClusterRoleBinding=$name hits=$hits"
        [[ $CHECK20_SHOW_PROGRESS -eq 1 ]] && echo ""
        report_binding "cluster" "-" "$name" "$refKind" "$refName" "$hits"
      else
        check20_debug "privileged but NO dangerous default/system:sa subjects: ClusterRoleBinding=$name $refKind/$refName"
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
  $K get rolebinding -A -o json 2>/dev/null \
  | jq -r '.items[]
           | [ .metadata.namespace
             , .metadata.name
             , .roleRef.kind
             , .roleRef.name
             , ((.subjects // []) | tojson)
             ] | @tsv' \
  | while IFS=$'\t' read -r ns name refKind refName subjects_str; do

      [[ $CHECK20_SHOW_PROGRESS -eq 1 ]] && echo -n "."

      # Optimization 4 — skip excluded namespaces ASAP
      if is_excluded_ns "$ns"; then
        check20_debug "skip RoleBinding (excluded ns): ns=$ns binding=$name"
        continue
      fi

      # Fast privileged check
      if ! is_privileged_ref "$refKind" "$refName" "$ns"; then
        continue
      fi

      subjects_json=$(jq -c 'if type=="string" then fromjson else . end' <<<"$subjects_str")
      if [[ "${DEBUG_CHECK20:-0}" -eq 1 ]]; then
        _sn=$(printf '%s\n' "$subjects_json" | jq 'length' 2>/dev/null || echo "?")
        check20_debug "privileged RoleBinding: ns=$ns name=$name roleRef=$refKind/$refName subjects=${_sn}"
      fi

      hits=$(printf '%s\n' "$subjects_json" | jq -c "$DANGER_FILTER")
      if [[ "$hits" != "[]" ]]; then
        CHECK20_FOUND_RISK=1
        check20_debug "danger-filter HIT: RoleBinding=$name (ns=$ns) hits=$hits"
        [[ $CHECK20_SHOW_PROGRESS -eq 1 ]] && echo ""
        report_binding "ns" "$ns" "$name" "$refKind" "$refName" "$hits"
      else
        check20_debug "privileged but NO dangerous default/system:sa subjects: RoleBinding=$name (ns=$ns) $refKind/$refName"
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
  if [[ $CHECK20_SHOW_PROGRESS -eq 1 ]]; then
    if [[ $CHECK20_FOUND_RISK -eq 1 ]]; then
      echo ""
    else
      echo " → no risky bindings found"
    fi
  fi

  echo
fi

# Check 21: Cross-reference all running workloads (Pods, Deployments, DaemonSets, StatefulSets,
# Jobs, CronJobs) against the risky-SA map built from RBAC bindings. Reports only workloads
# with incremental risk beyond what cluster-wide or namespace-wide SA escalation already covers.
# ---------- Check 21 (Consolidated + Option 2 + Enhancement) ----------
# Workloads using risky ServiceAccounts via RBAC
# - Cluster-wide SA escalation (system:serviceaccounts) => ONE summary block
# - Namespace-wide SA escalation (system:serviceaccounts:<ns>) => ONE block per ns
# - Per-SA exposures are ALWAYS printed (even if cluster/ns-wide exist) BUT ONLY for SAs with explicit bindings,
#   and ONLY the incremental risk categories (those not already provided by cluster/ns-wide escalation).
# - Quiet mode behaves the same as consolidated normal mode MINUS allowlisted controllers
#   (filtering is done by scanning backpointers for allowlisted roleRef/binding names)

if should_run 21; then
  echo "21: Workloads using risky ServiceAccounts (exposed via RBAC)"

  EXPOSE_FOUND=0

  check21_debug() {
    if [[ "${DEBUG_CHECK21:-0}" -eq 1 ]]; then
      printf '[debug check21] %s\n' "$*" >&2
    fi
    return 0
  }
  [[ "${DEBUG_CHECK21:-0}" -eq 1 ]] && check21_debug "debug enabled (messages on stderr)"

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
    $K get clusterrole -o json 2>/dev/null \
    | jq -r "$RISK_DEF_COMMON (.items // [])[] | select( $predicate ) | .metadata.name" \
    2>/dev/null || true
  }
  compute_risky_roles() {
    local predicate="$1"
    $K get role -A -o json 2>/dev/null \
    | jq -r "$RISK_DEF_COMMON (.items // [])[] | select( $predicate ) | (.metadata.namespace + \"|\" + .metadata.name)" \
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
  while IFS= read -r n;  do if [[ -n "$n" ]]; then CR_PRIV["$n"]=1; fi; done <<<"$PRIV_CR_NAMES"
  while IFS= read -r n;  do if [[ -n "$n" ]]; then CR_SEC["$n"]=1; fi; done <<<"$SEC_CR_NAMES"
  while IFS= read -r n;  do if [[ -n "$n" ]]; then CR_POD["$n"]=1; fi; done <<<"$POD_CR_NAMES"
  while IFS= read -r n;  do if [[ -n "$n" ]]; then CR_TOK["$n"]=1; fi; done <<<"$TOK_CR_NAMES"
  while IFS= read -r nk; do if [[ -n "$nk" ]]; then R_PRIV["$nk"]=1; fi; done <<<"$PRIV_R_NS_NAMES"
  while IFS= read -r nk; do if [[ -n "$nk" ]]; then R_SEC["$nk"]=1; fi; done <<<"$SEC_R_NS_NAMES"
  while IFS= read -r nk; do if [[ -n "$nk" ]]; then R_POD["$nk"]=1; fi; done <<<"$POD_R_NS_NAMES"
  while IFS= read -r nk; do if [[ -n "$nk" ]]; then R_TOK["$nk"]=1; fi; done <<<"$TOK_R_NS_NAMES"

  if [[ "${DEBUG_CHECK21:-0}" -eq 1 ]]; then
    check21_debug "risky role counts (CR / Role ns|name lines): priv=$(printf '%s\n' "$PRIV_CR_NAMES" | grep -c .)/$(printf '%s\n' "$PRIV_R_NS_NAMES" | grep -c .) sec=$(printf '%s\n' "$SEC_CR_NAMES" | grep -c .)/$(printf '%s\n' "$SEC_R_NS_NAMES" | grep -c .) pod=$(printf '%s\n' "$POD_CR_NAMES" | grep -c .)/$(printf '%s\n' "$POD_R_NS_NAMES" | grep -c .) tok=$(printf '%s\n' "$TOK_CR_NAMES" | grep -c .)/$(printf '%s\n' "$TOK_R_NS_NAMES" | grep -c .)"
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
      [[ -z "$risk_csv" ]] && { check21_debug "skip binding (no risk categories): scope=$scope $bname -> $refKind/$refName"; continue; }

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
          check21_debug "merge cluster-wide ALL SA risks: +[$risk_csv] via $bp"
          RISKY_CLUSTER_ALLSA="$(merge_csv "$RISKY_CLUSTER_ALLSA" "$risk_csv")"
          AFFECTED_BINDINGS_CLUSTER_ALLSA="$(merge_list "$AFFECTED_BINDINGS_CLUSTER_ALLSA" "$bp")"
          continue
        fi
        # system:serviceaccounts:<ns>
        if [[ "$skind" == "Group" && "$sname" == system:serviceaccounts:* ]]; then
          local gns="${sname#system:serviceaccounts:}"
          check21_debug "merge ns-wide ALL SA risks: ns=$gns +[$risk_csv] via $bp"
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
          check21_debug "merge per-SA risks: key=$key +[$risk_csv] via $bp"
          RISKY_SA["$key"]="$(merge_csv "${RISKY_SA[$key]:-}" "$risk_csv")"
          AFFECTED_BINDINGS["$key"]="$(merge_list "${AFFECTED_BINDINGS[$key]:-}" "$bp")"
        fi
      done < <(printf '%s\n' "$subjects_json" | jq -r '.[]? | [ (.kind // "-"), (.name // "-"), (.namespace // "-") ] | @tsv' 2>/dev/null)
    done
  }

  # Feed bindings (single parse → TSV; no subshell state loss)
  crb_tsv="$(
    $K get clusterrolebinding -o json 2>/dev/null \
    | jq -r '(.items // [])[] | [ .metadata.name, .roleRef.kind, .roleRef.name, ((.subjects // []) | tojson) ] | @tsv' \
    2>/dev/null || true
  )"
  process_binding_tsv "cluster" <<< "$crb_tsv"
  rb_tsv="$(
    $K get rolebinding -A -o json 2>/dev/null \
    | jq -r '(.items // [])[] | [ .metadata.namespace, .metadata.name, .roleRef.kind, .roleRef.name, ((.subjects // []) | tojson) ] | @tsv' \
    2>/dev/null || true
  )"
  process_binding_tsv "ns" <<< "$rb_tsv"

  if [[ "${DEBUG_CHECK21:-0}" -eq 1 ]]; then
    check21_debug "after binding ingest: RISKY_SA keys=${#RISKY_SA[@]} RISKY_NS_ALLSA=${#RISKY_NS_ALLSA[@]} cluster_csv=${RISKY_CLUSTER_ALLSA:-<empty>}"
  fi

  # -----------------------------
  # 2) Consolidated summaries (cluster-wide and ns-wide)
  # -----------------------------
  print_cluster_summary() {
    local risks="$1" bps="$2"
    local pods dep ds sts jobs cjs
    pods=$($K get pods         -A -o json 2>/dev/null | jq '.items|length' 2>/dev/null || echo 0)
    dep=$($K get deployments   -A -o json 2>/dev/null | jq '.items|length' 2>/dev/null || echo 0)
    ds=$($K get daemonsets     -A -o json 2>/dev/null | jq '.items|length' 2>/dev/null || echo 0)
    sts=$($K get statefulsets  -A -o json 2>/dev/null | jq '.items|length' 2>/dev/null || echo 0)
    jobs=$($K get jobs         -A -o json 2>/dev/null | jq '.items|length' 2>/dev/null || echo 0)
    cjs=$($K get cronjobs      -A -o json 2>/dev/null | jq '.items|length' 2>/dev/null || echo 0)
    echo " ⚠ All ServiceAccounts in the entire cluster are risky — RBAC risk: $risks (via subject: system:serviceaccounts)"
    echo "    ↳ backpointers: $bps"
    echo "    Affects workloads: pods=$pods, deployments=$dep, daemonsets=$ds, statefulsets=$sts, jobs=$jobs, cronjobs=$cjs"
    EXPOSE_FOUND=1
  }

  print_ns_summary() {
    local ns="$1" risks="$2" bps="$3"
    local pods dep ds sts jobs cjs
    pods=$($K get pods        -n "$ns" -o json 2>/dev/null | jq '.items|length' 2>/dev/null || echo 0)
    dep=$($K get deployments  -n "$ns" -o json 2>/dev/null | jq '.items|length' 2>/dev/null || echo 0)
    ds=$($K get daemonsets    -n "$ns" -o json 2>/dev/null | jq '.items|length' 2>/dev/null || echo 0)
    sts=$($K get statefulsets -n "$ns" -o json 2>/dev/null | jq '.items|length' 2>/dev/null || echo 0)
    jobs=$($K get jobs        -n "$ns" -o json 2>/dev/null | jq '.items|length' 2>/dev/null || echo 0)
    cjs=$($K get cronjobs     -n "$ns" -o json 2>/dev/null | jq '.items|length' 2>/dev/null || echo 0)
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
    [[ -z "$rs1_new" ]] && { check21_debug "skip Pod (no incremental risk vs cluster/ns-wide): $ns/$name SA=$sa rs1=$rs1 base_union=$base"; continue; }
    bps1="${AFFECTED_BINDINGS[$key]:-}"    # per-SA backpointers only
    [[ -z "$bps1" ]] && { check21_debug "skip Pod (no backpointers): $ns/$name SA=$sa"; continue; }
    if suppress_by_allowlist_bp "$bps1"; then
      check21_debug "skip Pod (quiet allowlist match on backpointers): $ns/$name SA=$sa"
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
    [[ -z "$rs1_new" ]] && { check21_debug "skip workload (no incremental risk vs cluster/ns-wide): $ns $kind/$name SA=$sa rs1=$rs1 base_union=$base"; continue; }
    bps1="${AFFECTED_BINDINGS[$key]:-}"
    [[ -z "$bps1" ]] && { check21_debug "skip workload (no backpointers): $ns $kind/$name SA=$sa"; continue; }
    if suppress_by_allowlist_bp "$bps1"; then
      check21_debug "skip workload (quiet allowlist match on backpointers): $ns $kind/$name SA=$sa"
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

# Compute and display total execution time in HH:MM:SS.mmm format
END_TIME_NS=$(date +%s%N)
DURATION_NS=$((END_TIME_NS - START_TIME_NS))

# Convert nanoseconds to human-readable format
DURATION_MS=$((DURATION_NS / 1000000))
MS=$((DURATION_MS % 1000))
SEC=$(( (DURATION_MS / 1000) % 60 ))
MIN=$(( (DURATION_MS / 60000) % 60 ))
HOUR=$(( DURATION_MS / 3600000 ))

printf "===== RBAC Audit Complete =====\n"
printf "Execution time: %02d:%02d:%02d.%03d (HH:MM:SS.mmm)\n" \
       "$HOUR" "$MIN" "$SEC" "$MS"
