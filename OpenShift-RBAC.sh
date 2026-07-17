#!/bin/bash
# ------------------------------------------------------------
# CLI: --checks --list/--list-checks --quiet --critical --help
#      --debug-check20 --debug-check21 (accepted for parity with GKE/EKS; no checks 20–21 here)
# Env: OC=/path/to/oc  DEBUG_CHECK20=1 DEBUG_CHECK21=1 (debug flags no-op on this script)
# ------------------------------------------------------------
CHECKS_SPEC=""
LIST_CHECKS=0
QUIET=0
CRITICAL_ONLY=0
SHOW_HELP=0
[[ "${DEBUG_CHECK20:-}" == "1" ]] && DEBUG_CHECK20=1 || DEBUG_CHECK20=0
[[ "${DEBUG_CHECK21:-}" == "1" ]] && DEBUG_CHECK21=1 || DEBUG_CHECK21=0

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
      shift
      ;;
  esac
done

if [[ $SHOW_HELP -eq 1 ]]; then
  cat <<'EOF'
OpenShift RBAC Security Audit (oc)

Usage:
  OpenShift-RBAC.sh [--checks LIST] [--critical] [--quiet] [--debug-check20] [--debug-check21]
                    [--list-checks | --list] [--help | -h]

Flags:
  --checks=LIST      Run only checks 1–14; comma-separated, ranges allowed (e.g. 1,3-5,14).
  --critical         Run only high-severity checks (1,2,4,6,7,9,10,13).
  --quiet            Suppress OK lines, empty results, <no subjects>, and
                     "skipped system/operator-managed" noise.
  --debug-check20    No-op here (compatibility with GKE-rbac.sh / EKS-rbac.sh).
  --debug-check21    No-op here (compatibility with GKE-rbac.sh / EKS-rbac.sh).
  --list, --list-checks   Print check catalogue and exit.
  -h, --help         Show this help and exit.

Env:
  OC=/path/to/oc     Override oc binary.

Examples:
  OpenShift-RBAC.sh --quiet
  OpenShift-RBAC.sh --checks=1,2,14
  OpenShift-RBAC.sh --critical
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

CRITICAL_CHECKS=(1 2 4 6 7 9 10 13)

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
  1  : System groups must not have cluster-admin
  2  : No custom (non-system) subjects with cluster-admin
  3  : No custom subjects creating workloads (pods, deployments, statefulsets)
  4  : No permission to exec into pods (pods/exec)
  5  : Only control plane should create persistentvolumes
  6  : No escalate on clusterroles; no bind on rolebindings; no impersonate
  7  : No custom subjects read secrets (get/list/watch)
  8  : No subject should patch namespaces
  9  : No subject should CRUD validating/mutating webhook configurations
  10 : Critical wildcard usage in roles and clusterroles
  11 : No subject should create tokenreviews
  12 : No subject should create subjectaccessreviews
  13 : Restricted access to nodes (get/list/watch/patch)
  14 : Read access to configmaps in system namespaces (CONFIGMAP_CHECK_NAMESPACES; OpenShift defaults)
EOF
  exit 0
fi

set -e
set -o pipefail

OC="${OC:-oc}"

if ! command -v "$OC" &> /dev/null; then
    echo "Error: oc CLI is required but not installed (OC=$OC)"
    exit 1
fi
if ! command -v jq &> /dev/null; then
    echo "Error: jq is required but not installed"
    exit 1
fi

if ! $OC whoami &>/dev/null; then
    echo "Error: Not logged into OpenShift cluster"
    exit 1
fi

# Print audit banner, current user context, and output legend
echo "===== OpenShift RBAC Security Audit (Critical Only) ====="
echo "Running as: $($OC whoami)"
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

##############################################
# Excluded namespaces
##############################################
# Static list of namespaces excluded from all checks; openshift-* is a glob pattern
EXCLUDED_NS=("kube-system" "kube-public" "kube-node-lease" "openshift-*")

# Add operator-managed namespaces dynamically
OP_NS=$($OC get ns -o json | jq -r '.items[] | select(.metadata.labels."olm.owner") | .metadata.name')
if [[ -n "$OP_NS" ]]; then
    EXCLUDED_NS+=("$OP_NS")
fi

echo "Excluding system/operator namespaces from checks: ${EXCLUDED_NS[*]}"
echo

# Wildcard-safe namespace exclusion
# Returns 0 (true) if the given namespace matches any entry in EXCLUDED_NS,
# supporting glob patterns (e.g. openshift-*) via regex conversion.
is_excluded_ns() {
    local ns="$1"
    for ex in "${EXCLUDED_NS[@]}"; do
        if [[ "$ex" == *"*" ]]; then
            local pattern="^${ex//\*/.*}$"
            [[ "$ns" =~ $pattern ]] && return 0
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

    local subjects
    if [[ "$ns" == "cluster" ]]; then
        # ClusterRoles can be bound via ClusterRoleBindings OR via RoleBindings in any namespace.
        # Both paths must be queried, otherwise subjects granted through RoleBinding→ClusterRole are missed.
        local crb_subjects rb_subjects
        crb_subjects=$($OC get clusterrolebinding -o json 2>/dev/null \
          | jq -r --arg ROLE "$name" '
              .items[]
              | select(.roleRef.name == $ROLE)
              | . as $binding
              | .subjects[]?
              | {kind:.kind,name:.name,namespace:(.namespace//"-"),binding:($binding.metadata.name)}
          ' | jq -s 'unique_by(.kind + .name + .namespace + .binding)' || echo '[]')
        rb_subjects=$($OC get rolebinding -A -o json 2>/dev/null \
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
        subjects=$($OC get rolebinding -n "$ns" -o json 2>/dev/null || echo '[]' \
          | jq -r --arg ROLE "$name" '
              .items[]
              | select(.roleRef.name == $ROLE)
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
    echo "Checking: $group does NOT have cluster-admin"

    hits=$($OC get clusterrolebinding -o json \
      | jq -r --arg GRP "$group" '
          .items[]
          | select(.subjects[]? | .kind=="Group" and .name==$GRP)
          | select(.roleRef.name=="cluster-admin")
          | select(.metadata.labels."olm.owner"? | not)   # skip operator bindings
          | .metadata.name')

    if [[ -z "$hits" ]]; then
        [[ $QUIET -eq 0 ]] && echo "  ✔ OK"
    else
        echo "  ⚠ VIOLATION: $group has cluster-admin:"
        echo "$hits" | sed 's/^/    - /'
    fi
    echo
}

if should_run 1; then
for grp in system:authenticated system:unauthenticated system:anonymous system:serviceaccounts; do
    check_system_group "$grp"
    echo
done
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
echo "Checking for non-system subjects with cluster-admin…"

found=0
while IFS= read -r line; do
    ns=$(echo "$line" | sed -n 's/.*(ns: \(.*\)).*/\1/p')
    binding_olm=$(echo "$line" | awk '{print $NF}')
    is_excluded_ns "$ns" && continue
    [[ "$binding_olm" != "-" ]] && continue
    echo "      * $line"
    found=1
done < <(
    $OC get clusterrolebinding -o json \
    | jq -r '
      .items[]
      | select(.roleRef.name=="cluster-admin")
      | . as $binding
      | .subjects[]?
      | select(.name | startswith("system:") | not)
      | "\(.kind) \(.name) (ns: \(.namespace // "-")) via ClusterRoleBinding: \($binding.metadata.name) \($binding.metadata.labels."olm.owner" // "-")"
    ' | sort -u
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
    local verbs_in="$1"    # single verb or comma-separated e.g. "get,list,watch"
    local resource="$2"
    local msg="$3"
    local empty_msg="${4:-✔ No matching roles found.}"
    local ap_key="${verbs_in}:${resource}"

    echo "Checking: $msg ($verbs_in $resource)"
    if [[ -n "${ATTACK_PATH[$ap_key]:-}" ]]; then
      echo "  Attack path: ${ATTACK_PATH[$ap_key]}"
    fi

    # Fetch all ClusterRoles and Roles
    matches=$($OC get clusterrole,role -A -o json \
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

    echo "  ⚠ Roles with this permission:"
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

        echo "    - $kind/$name (ns: $ns)"

        # Get subjects for this role
        subjects=$(get_subjects_for_role "$kind" "$name" "$ns")

        if [[ "$subjects" == "<no subjects>" ]]; then
            [[ $QUIET -eq 0 ]] && echo "      <no subjects>"
            continue
        fi

        # Filter out system/operator subjects
        filtered_subjects=$(echo "$subjects" | while read -r subj; do
            subj_ns=$(echo "$subj" | sed -n 's/.*(ns: \(.*\)).*/\1/p')
            subj_name=$(echo "$subj" | awk '{print $2}')
            is_excluded_ns "$subj_ns" && continue
            [[ "$subj_name" == system:* ]] && continue
            is_baseline_identity "$subj_name" && continue
            echo "$subj"
        done)

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
check_permission create pods/exec "No subjects should have permission to exec into pods"
echo
fi

# CHECK 5: No persistent volume creation
# Check 5: Verify only control-plane components can create PersistentVolumes.
# Unrestricted PV creation can expose host filesystem paths or cloud storage buckets.
if should_run 5; then
check_permission create persistentvolumes "Only control plane components should create persistentvolumes"
echo
fi

# CHECK 6: Escalate, Bind, Impersonate
# Check 6: Detect privilege-escalation verbs.
# 'escalate' on clusterroles allows granting permissions the subject doesn't hold themselves.
# 'bind' on role bindings allows attaching any role to any subject.
# 'impersonate' allows acting as another user, group, or serviceaccount, bypassing RBAC entirely.
if should_run 6; then
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
check_permission "get,list,watch" secrets "No custom subjects should read secrets (get/list/watch)"
echo
fi

# Check 8: Detect roles that can patch namespaces. Namespace labels control admission
# policies (e.g. PodSecurity, Kyverno), so patching them can disable security controls.
if should_run 8; then
check_permission patch namespaces "No subject should patch namespaces"
echo
fi

# Check 9: Detect roles that can create/update/patch/delete ValidatingWebhookConfigurations
# or MutatingWebhookConfigurations. Modifying these can intercept or silently mutate
# every API request cluster-wide, making them a high-value escalation target.
if should_run 9; then
for res in validatingwebhookconfigurations mutatingwebhookconfigurations; do
    for verb in create delete update patch; do
        check_permission "$verb" "$res" "No subject should $verb $res"
        echo
    done
done
fi

# Check 10: Find roles using wildcards (*) in verbs, resources, or apiGroups.
# Wildcards silently cover all current and future resource types and API additions,
# making them semantically equivalent to cluster-admin in many cases.
# System and OLM-managed roles are skipped; subjects are filtered as elsewhere.
if should_run 10; then
echo "Checking for critical wildcard usage in roles and clusterroles…"
wild_rules=$(
  $OC get clusterrole,role -A -o json \
  | jq -r '
      .items[]
      | . as $role
      | (.rules[]? // empty)
      | select(
          # detect ANY wildcard usage
          (.verbs[]? == "*")
          or (.resources[]? == "*")
          or (.apiGroups[]? == "*")
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
    '
)
if [[ -z "$wild_rules" ]]; then
    [[ $QUIET -eq 0 ]] && echo "  ✔ No critical wildcard usage detected."
    echo
else
    echo "$wild_rules" \
    | awk -F'\t' '!seen[$2,$3,$4,$5,$6]++' \
    | while IFS=$'\t' read -r kind name ns verbs resources apigroups olm; do

        if [[ "$kind" == "ClusterRole" && ( "$olm" != "-" || "$name" == system:* ) ]]; then
            [[ $QUIET -eq 0 ]] && echo "    - $kind/$name (ns: $ns) -> <skipped system/operator-managed>"
            continue
        fi

        echo "    - $kind/$name (ns: $ns) (rule: verbs=$verbs, resources=$resources, apiGroups=$apigroups)"

        # Determine correct scope for fetching bindings
        if [[ "$ns" == "cluster" ]]; then
            subjects=$(get_subjects_for_role "$kind" "$name" "cluster")
        else
            subjects=$(get_subjects_for_role "$kind" "$name" "$ns")
        fi

        if [[ "$subjects" == "<no subjects>" ]]; then
            [[ $QUIET -eq 0 ]] && echo "      <no subjects>"
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
            [[ $QUIET -eq 0 ]] && echo "      ✔ All subjects are system/operator accounts"
        else
            echo "$filtered_subjects" | while read -r subj; do
                echo "      * $subj"
            done
        fi
    done
    echo
fi
fi

# Check 11: Find roles that can create TokenReviews. This allows a subject to validate
# arbitrary bearer tokens and probe for valid credentials across the cluster.
if should_run 11; then
check_permission create tokenreviews "No subject should create tokenreviews"
echo
fi

# Check 12: Find roles that can create SubjectAccessReviews. This allows a subject to
# enumerate what permissions any other identity holds — useful for privilege mapping attacks.
if should_run 12; then
check_permission create subjectaccessreviews "No subject should create subjectaccessreviews"
echo
fi

# Check 13: Detect over-permissive node access. Read access (get/list/watch) exposes
# the full inventory of pods and tokens on each node; patch access can alter node
# taints, labels, and conditions to influence scheduling or disable health checks.
if should_run 13; then
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

# Default namespaces to inspect on OpenShift + core K8s
SYSTEM_CONFIGMAP_NAMESPACES=(
  kube-system
  openshift-kube-apiserver
  openshift-kube-controller-manager
  openshift-config
  openshift-config-managed
  openshift-etcd
  openshift-monitoring
)

# Optional override:
#   export CONFIGMAP_CHECK_NAMESPACES="ns1 ns2 ..."
if [[ -n "${CONFIGMAP_CHECK_NAMESPACES:-}" ]]; then
  read -r -a SYSTEM_CONFIGMAP_NAMESPACES <<< "${CONFIGMAP_CHECK_NAMESPACES}"
fi

if should_run 14; then
echo "Checking: subjects who can get/list/watch configmaps in system namespaces:"
echo "  Targets: ${SYSTEM_CONFIGMAP_NAMESPACES[*]}"
echo

for TARGET_NS in "${SYSTEM_CONFIGMAP_NAMESPACES[@]}"; do
  # Skip if namespace does not exist
  if ! $OC get ns "$TARGET_NS" >/dev/null 2>&1; then
    [[ $QUIET -eq 0 ]] && echo "  (skip: namespace $TARGET_NS not present)"
    continue
  fi

  echo "  Checking RoleBindings in $TARGET_NS…"
  $OC get rolebinding -n "$TARGET_NS" -o json \
  | jq -rc '
      .items[] | . as $rb
      | .roleRef as $ref
      | {binding:$rb.metadata.name, refKind:$ref.kind, refName:$ref.name, subjects:($rb.subjects // [])}
    ' \
  | while IFS= read -r json; do
      refKind=$(echo "$json" | jq -r '.refKind')
      refName=$(echo "$json" | jq -r '.refName')

      # Fetch referenced role/clusterrole rules
      if [[ "$refKind" == "Role" ]]; then
        rules=$($OC get role "$refName" -n "$TARGET_NS" -o json 2>/dev/null || echo "")
      else
        rules=$($OC get clusterrole "$refName" -o json 2>/dev/null || echo "")
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
  $OC get clusterrolebinding -o json \
  | jq -rc '
      .items[] | . as $crb
      | {binding:$crb.metadata.name, refName:$crb.roleRef.name, subjects:($crb.subjects // [])}
    ' \
  | while IFS= read -r json; do
      ref=$(echo "$json" | jq -r '.refName')
      rules=$($OC get clusterrole "$ref" -o json 2>/dev/null || echo "")
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

# All checks complete
echo "===== RBAC Critical Audit Complete ====="
