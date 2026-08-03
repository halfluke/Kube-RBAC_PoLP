#!/bin/bash

# -----------------------------
# Flags / argument parsing
# -----------------------------
ONLY_USER_NS=0
OUTPUT_MODE="text"   # text | csv | json
DEBUG=0
ARO_MODE=0
ROSA_MODE=0
# SCC candidate ranking when annotation is missing (after subject-review fails):
#   v1 — privileged + host namespaces only (scc_satisfies_pod)
#   v2 — v1 plus runAs*/fsGroup/supplementalGroups + allowed volumes (scc_satisfies_pod_enhanced)
SCC_MATCHING_VERSION="v2"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --only-user-ns) ONLY_USER_NS=1; shift ;;
    --output) OUTPUT_MODE="$2"; shift 2 ;;
    --debug) DEBUG=1; shift ;;
    --aro) ARO_MODE=1; shift ;;
    --rosa) ROSA_MODE=1; shift ;;
    --scc-matching)
      SCC_MATCHING_VERSION="$2"
      shift 2
      ;;
    -h|--help)
      cat <<'EOF'
OpenShift Container Capabilities / SCC audit

Usage:
  OpenShift-ContainerCapabilities.sh [--only-user-ns] [--output text|csv|json]
                                     [--scc-matching v1|v2] [--debug] [--aro|--rosa]

  --aro / --rosa   Surface Azure WI / AWS IRSA-style annotations (mutually exclusive).
                   Annotation/label read only (no az/aws API calls).
  --aro keys       azure.workload.identity/client-id
                   azure.workload.identity/service-account-client-id (SA fallback)
  --rosa keys      eks.amazonaws.com/role-arn ; iam.amazonaws.com/role
                   (pod annotation first, then SA fallback)
EOF
      exit 0
      ;;
    *) echo "[ERROR] Unknown argument: $1" >&2; exit 1 ;;
  esac
done

if [[ $ARO_MODE -eq 1 && $ROSA_MODE -eq 1 ]]; then
  echo "[ERROR] --aro and --rosa are mutually exclusive" >&2
  exit 1
fi

if [[ "$OUTPUT_MODE" != "text" && "$OUTPUT_MODE" != "csv" && "$OUTPUT_MODE" != "json" ]]; then
  echo "[ERROR] Invalid --output mode. Use: text | csv | json" >&2
  exit 1
fi

if [[ "$SCC_MATCHING_VERSION" != "v1" && "$SCC_MATCHING_VERSION" != "v2" ]]; then
  echo "[ERROR] Invalid --scc-matching \"$SCC_MATCHING_VERSION\". Use: v1 | v2" >&2
  exit 1
fi

START_TIME_NS=$(date +%s%N)

# Info banners: keep CSV/JSON stdout machine-clean
info() {
  if [[ "$OUTPUT_MODE" == "text" ]]; then
    echo "$@"
  else
    echo "$@" >&2
  fi
}

info "Performing SCC + capabilities check (oc + jq; '*' expanded)..."
info "[INFO] Escape-chain lines use the pod-spec effective-cap estimate and are listed separately from Status severity (not runtime verification)."
if [[ $ARO_MODE -eq 1 ]]; then
  info "[INFO] --aro: reporting azure.workload.identity/client-id (pod, then SA fallback)."
elif [[ $ROSA_MODE -eq 1 ]]; then
  info "[INFO] --rosa: reporting eks.amazonaws.com/role-arn or iam.amazonaws.com/role (pod, then SA fallback)."
fi

# -----------------------------
# Requirements check
# -----------------------------
if ! command -v oc &> /dev/null; then
    echo "[ERROR] oc not found." >&2
    exit 1
fi
if ! command -v jq &> /dev/null; then
    echo "[ERROR] jq not found." >&2
    exit 1
fi
if ! oc get ns >/dev/null 2>&1; then
    echo "[ERROR] Cannot list namespaces or reach the cluster (oc get namespaces failed). Check kubeconfig and RBAC." >&2
    exit 1
fi

# -----------------------------
# Capability definitions
# -----------------------------
PRIVILEGED_CAPS=("SYS_ADMIN" "NET_ADMIN" "SYS_TIME" "SYS_MODULE" "SYS_RAWIO")
BASELINE_PRIVILEGED_CAPS=("CHOWN" "DAC_OVERRIDE")
BASELINE_CAPS=("FSETID" "FOWNER" "MKNOD" "NET_RAW" "SETGID" "SETUID" "SETFCAP" "SETPCAP" "NET_BIND_SERVICE" "KILL" "AUDIT_WRITE")
ALL_LINUX_CAPS=("${BASELINE_CAPS[@]}" "${BASELINE_PRIVILEGED_CAPS[@]}" "${PRIVILEGED_CAPS[@]}")

# Add after capability definitions, before namespace iteration:
info "Pre-fetching all SCCs..."
if ! ALL_SCCS_JSON=$(oc get scc -o json 2>/dev/null) || [[ -z "$ALL_SCCS_JSON" ]]; then
  echo "[ERROR] Failed to list SecurityContextConstraints (oc get scc)." >&2
  exit 1
fi
declare -A SCC_BY_NAME ACCESSIBLE_SCC_CACHE SCC_REVIEW_CACHE
while IFS= read -r _scc_name; do
  [[ -z "$_scc_name" ]] && continue
  SCC_BY_NAME["$_scc_name"]=$(echo "$ALL_SCCS_JSON" | jq -c --arg n "$_scc_name" '.items[] | select(.metadata.name==$n)')
done < <(echo "$ALL_SCCS_JSON" | jq -r '.items[].metadata.name')
if ! NS_JSON=$(oc get ns -o json 2>/dev/null); then
  echo "[ERROR] Failed to list namespaces (oc get ns)." >&2
  exit 1
fi
info "SCC guess matcher (when annotation missing, after subject-review): $SCC_MATCHING_VERSION  [override: --scc-matching v1 | v2]"
info "If annotation + subject-review + matcher all fail, SCC is reported as unknown (no priority fallback)."

# -----------------------------
# Print capability arrays at start
# -----------------------------
info "-----------------------------"
info "Baseline capabilities:"
info "  ${BASELINE_CAPS[*]}"
info "Baseline privileged capabilities:"
info "  ${BASELINE_PRIVILEGED_CAPS[*]}"
info "Privileged capabilities:"
info "  ${PRIVILEGED_CAPS[*]}"
info "-----------------------------"
info ""

containsElement () {
  local match="$1"; shift
  for e in "$@"; do [[ "$e" == "$match" ]] && return 0; done
  return 1
}

# Align baseline union with Vanilla-ContainerCapabilities.sh / GKE-ContainerCapabilities.sh
cap_in_baseline_union () {
  local c="$1"
  containsElement "$c" "${BASELINE_CAPS[@]}" && return 0
  containsElement "$c" "${BASELINE_PRIVILEGED_CAPS[@]}"
}

escape_chain_push () {
  ESCAPE_CHAIN_MSGS+=("$1")
}

# Per-pod STATUS: rank 5=CRITICAL … 2=MEDIUM (same ladder as Vanilla); merge picks worst rank + " — also: " for ties.
status_push () {
  STATUS_RANKS+=("$1")
  STATUS_MSGS+=("$2")
}

# Escape-chain detection: estimated effective caps + co-conditions (separate from Status severity).
# Uses EFFECTIVE_CAPS, HOST_NETWORK_CHECK, SHARE_PROC_NS, HOSTPATH_WRITABLE_PATHS.
check_escape_chains () {
    local cap path has_sys_admin=0 has_sys_ptrace=0 has_sys_module=0 has_net=0 has_mknod=0
    local cg_hits=() dev_hits=()
    local host_net="${HOST_NETWORK_CHECK:-false}"

    for cap in "${EFFECTIVE_CAPS[@]}"; do
        [[ -z "$cap" ]] && continue
        case "$(printf '%s' "$cap" | tr '[:lower:]' '[:upper:]')" in
            SYS_ADMIN) has_sys_admin=1 ;;
            SYS_PTRACE) has_sys_ptrace=1 ;;
            SYS_MODULE) has_sys_module=1 ;;
            NET_RAW|NET_ADMIN) has_net=1 ;;
            MKNOD) has_mknod=1 ;;
        esac
    done

    for path in "${HOSTPATH_WRITABLE_PATHS[@]}"; do
        [[ -z "$path" ]] && continue
        if [[ "$path" == /sys/fs/cgroup || "$path" == /sys/fs/cgroup/* || "$path" == /sys/fs || "$path" == /sys/fs/* ]]; then
            cg_hits+=("$path")
        fi
        if [[ "$path" == /dev || "$path" == /dev/* ]]; then
            dev_hits+=("$path")
        fi
    done

    if [[ "$has_sys_admin" -eq 1 && ${#cg_hits[@]} -gt 0 ]]; then
        escape_chain_push "Escape chain: SYS_ADMIN + writable cgroup hostPath ($(IFS=,; echo "${cg_hits[*]}")) -> release_agent write -> host command execution"
    fi
    if [[ "$has_sys_ptrace" -eq 1 && "$SHARE_PROC_NS" == "true" ]]; then
        escape_chain_push "Escape chain: SYS_PTRACE + shareProcessNamespace -> attach to sibling container process -> credential/memory extraction"
    fi
    if [[ "$has_net" -eq 1 && "$host_net" == "true" ]]; then
        escape_chain_push "Escape chain: NET_RAW/NET_ADMIN + hostNetwork -> sniff/spoof node network -> reach metadata API"
    fi
    if [[ "$has_mknod" -eq 1 && ${#dev_hits[@]} -gt 0 ]]; then
        escape_chain_push "Escape chain: MKNOD + writable /dev hostPath ($(IFS=,; echo "${dev_hits[*]}")) -> create host device node -> raw disk read"
    fi
    if [[ "$has_sys_module" -eq 1 ]]; then
        escape_chain_push "Escape chain: SYS_MODULE -> load kernel module -> full host compromise"
    fi
}

if [[ "$OUTPUT_MODE" == "csv" ]]; then
  if [[ $ARO_MODE -eq 1 ]]; then
    echo "namespace,pod,scc,serviceAccount,privileged_container,status,scc_caps,defaultAddCapabilities,requiredDropCapabilities,requested_caps_from_pod,dropped_caps_from_pod,effective_caps,allowPrivilegeEscalation,hostPID,hostNetwork,hostIPC,runAsNonRoot,runAsUser,escape_chains,automountServiceAccountToken,workload_identity_client_id"
  elif [[ $ROSA_MODE -eq 1 ]]; then
    echo "namespace,pod,scc,serviceAccount,privileged_container,status,scc_caps,defaultAddCapabilities,requiredDropCapabilities,requested_caps_from_pod,dropped_caps_from_pod,effective_caps,allowPrivilegeEscalation,hostPID,hostNetwork,hostIPC,runAsNonRoot,runAsUser,escape_chains,automountServiceAccountToken,irsa_iam_role_arn"
  else
    echo "namespace,pod,scc,serviceAccount,privileged_container,status,scc_caps,defaultAddCapabilities,requiredDropCapabilities,requested_caps_from_pod,dropped_caps_from_pod,effective_caps,allowPrivilegeEscalation,hostPID,hostNetwork,hostIPC,runAsNonRoot,runAsUser,escape_chains,automountServiceAccountToken"
  fi
fi

JSON_ITEMS=()

# =============================================================================================
# HELPER FUNCTIONS FOR ENHANCED SCC DETERMINATION
# =============================================================================================

scc_satisfies_pod() {
    local SCC_JSON="$1"
    local POD_JSON="$2"
    local POD_NEEDS_PRIV SCC_ALLOWS_PRIV
    local POD_NEEDS_HOSTNET SCC_ALLOWS_HOSTNET
    local POD_NEEDS_HOSTPID SCC_ALLOWS_HOSTPID
    local POD_NEEDS_HOSTIPC SCC_ALLOWS_HOSTIPC

    # Check privileged
    POD_NEEDS_PRIV=$(echo "$POD_JSON" | jq -r '[(.spec.initContainers[]?.securityContext.privileged // false), (.spec.containers[]?.securityContext.privileged // false)] | any(. == true)')
    SCC_ALLOWS_PRIV=$(echo "$SCC_JSON" | jq -r '.allowPrivilegedContainer // false')
    [[ "$POD_NEEDS_PRIV" == "true" && "$SCC_ALLOWS_PRIV" != "true" ]] && return 1

    # Check hostNetwork
    POD_NEEDS_HOSTNET=$(echo "$POD_JSON" | jq -r '.spec.hostNetwork // false')
    SCC_ALLOWS_HOSTNET=$(echo "$SCC_JSON" | jq -r '.allowHostNetwork // false')
    [[ "$POD_NEEDS_HOSTNET" == "true" && "$SCC_ALLOWS_HOSTNET" != "true" ]] && return 1

    # Check hostPID
    POD_NEEDS_HOSTPID=$(echo "$POD_JSON" | jq -r '.spec.hostPID // false')
    SCC_ALLOWS_HOSTPID=$(echo "$SCC_JSON" | jq -r '.allowHostPID // false')
    [[ "$POD_NEEDS_HOSTPID" == "true" && "$SCC_ALLOWS_HOSTPID" != "true" ]] && return 1

    # Check hostIPC
    POD_NEEDS_HOSTIPC=$(echo "$POD_JSON" | jq -r '.spec.hostIPC // false')
    SCC_ALLOWS_HOSTIPC=$(echo "$SCC_JSON" | jq -r '.allowHostIPC // false')
    [[ "$POD_NEEDS_HOSTIPC" == "true" && "$SCC_ALLOWS_HOSTIPC" != "true" ]] && return 1

    return 0
}

# --- Stricter SCC vs pod checks (runAs*, volumes) used by try_enhanced_matching_v2 ---
value_in_ranges() {
    local value="$1"
    local ranges_json="$2"
    local range min max

    while IFS= read -r range; do
        [[ -z "$range" ]] && continue
        min=$(echo "$range" | jq -r '.min')
        max=$(echo "$range" | jq -r '.max')

        if [[ $value -ge $min && $value -le $max ]]; then
            return 0
        fi
    done < <(echo "$ranges_json" | jq -c '.[]')

    return 1
}

check_id_strategy() {
    local scc_strategy_json="$1"
    local -n pod_values="$2"
    local strategy_field="$3"
    local scc_name="$4"

    if [[ -z "$scc_strategy_json" || "$scc_strategy_json" == "null" ]]; then
        [[ "$DEBUG" -eq 1 ]] && echo "[DEBUG] $strategy_field strategy for SCC '$scc_name' is null/empty, assuming RunAsAny-like behavior." >&2
        return 0
    fi

    local strategy_type
    strategy_type=$(echo "$scc_strategy_json" | jq -r '.type // "RunAsAny"')

    case "$strategy_type" in
        "RunAsAny")
            return 0
            ;;
        "MustRunAsNonRoot")
            for val in "${pod_values[@]}"; do
                if [[ "$val" == "0" || "$val" == 0 ]]; then
                    [[ "$DEBUG" -eq 1 ]] && echo "[DEBUG] $strategy_field strategy 'MustRunAsNonRoot' failed for SCC '$scc_name': pod requested UID/GID 0." >&2
                    return 1
                fi
            done
            return 0
            ;;
        "MustRunAs")
            local strategy_uid strategy_gid strategy_ranges target_id
            strategy_uid=$(echo "$scc_strategy_json" | jq -r '.uid // empty')
            strategy_gid=$(echo "$scc_strategy_json" | jq -r '.gid // empty')
            strategy_ranges=$(echo "$scc_strategy_json" | jq -c '.ranges // []')

            target_id="$strategy_uid"
            if [[ -n "$strategy_gid" ]]; then target_id="$strategy_gid"; fi

            if [[ -n "$target_id" ]]; then
                for val in "${pod_values[@]}"; do
                    if [[ "$val" == "$target_id" ]]; then
                        return 0
                    fi
                done
                [[ "$DEBUG" -eq 1 ]] && echo "[DEBUG] $strategy_field strategy 'MustRunAs' (ID: $target_id) failed for SCC '$scc_name': pod did not request the required ID." >&2
                return 1
            elif [[ -n "$strategy_ranges" && "$strategy_ranges" != "[]" ]]; then
                local found_in_range=0
                for val in "${pod_values[@]}"; do
                    if [[ $val =~ ^[0-9]+$ ]] && value_in_ranges "$val" "$strategy_ranges"; then
                        found_in_range=1
                        break
                    fi
                done
                if [[ $found_in_range -eq 1 ]]; then
                    return 0
                else
                    [[ "$DEBUG" -eq 1 ]] && echo "[DEBUG] $strategy_field strategy 'MustRunAs' (ranges) failed for SCC '$scc_name': none of the pod's requested IDs matched the ranges." >&2
                    return 1
                fi
            else
                [[ "$DEBUG" -eq 1 ]] && echo "[DEBUG] $strategy_field strategy 'MustRunAs' for SCC '$scc_name' lacks uid/gid/ranges definition." >&2
                return 1
            fi
            ;;
        "MustRunAsRange")
            local scc_ranges
            scc_ranges=$(echo "$scc_strategy_json" | jq -c '.ranges // []')
            if [[ -z "$scc_ranges" || "$scc_ranges" == "[]" ]]; then
                [[ "$DEBUG" -eq 1 ]] && echo "[DEBUG] $strategy_field strategy 'MustRunAsRange' for SCC '$scc_name' has no defined ranges." >&2
                return 1
            fi

            for val in "${pod_values[@]}"; do
                if [[ $val =~ ^[0-9]+$ ]]; then
                    if ! value_in_ranges "$val" "$scc_ranges"; then
                        [[ "$DEBUG" -eq 1 ]] && echo "[DEBUG] $strategy_field strategy 'MustRunAsRange' failed for SCC '$scc_name': value '$val' is outside defined ranges." >&2
                        return 1
                    fi
                else
                    [[ "$DEBUG" -eq 1 ]] && echo "[DEBUG] $strategy_field strategy 'MustRunAsRange' failed for SCC '$scc_name': non-numeric value '$val' encountered." >&2
                    return 1
                fi
            done
            return 0
            ;;
        *)
            [[ "$DEBUG" -eq 1 ]] && echo "[DEBUG] Unknown $strategy_field strategy type '$strategy_type' for SCC '$scc_name'." >&2
            return 1
            ;;
    esac
}

check_volumes_allowed() {
    local scc_volumes_json="$1"
    local pod_spec_json="$2"
    local scc_name="$3"

    if echo "$scc_volumes_json" | jq -e 'index("*")' > /dev/null; then
        return 0
    fi

    local pod_volume_types
    pod_volume_types=$(echo "$pod_spec_json" | jq -r '
        .volumes // [] |
        .[] |
        to_entries |
        .[] |
        select(.value | type == "object") |
        .key
    ' | sort -u)

    while IFS= read -r vol_type; do
        if [[ -n "$vol_type" ]]; then
            if ! echo "$scc_volumes_json" | jq -e --arg vt "$vol_type" "map(ascii_downcase) | index(\$vt)" > /dev/null; then
                if ! echo "$scc_volumes_json" | jq -e --arg vt "$vol_type" "index(\$vt)" > /dev/null; then
                    [[ "$DEBUG" -eq 1 ]] && echo "[DEBUG] Volume check for SCC '$scc_name': Volume type '$vol_type' is not allowed by SCC." >&2
                    return 1
                fi
            fi
        fi
    done <<< "$pod_volume_types"

    return 0
}

scc_satisfies_pod_enhanced() {
    local SCC_JSON="$1"
    local POD_JSON="$2"
    local SCC_NAME_DEBUG
    SCC_NAME_DEBUG=$(echo "$SCC_JSON" | jq -r '.metadata.name // "unknown_scc"')

    local POD_NEEDS_PRIV SCC_ALLOWS_PRIV
    POD_NEEDS_PRIV=$(echo "$POD_JSON" | jq -r '[(.spec.initContainers[]?.securityContext.privileged // false), (.spec.containers[]?.securityContext.privileged // false)] | any(. == true)')
    SCC_ALLOWS_PRIV=$(echo "$SCC_JSON" | jq -r '.allowPrivilegedContainer // false')
    if [[ "$POD_NEEDS_PRIV" == "true" && "$SCC_ALLOWS_PRIV" != "true" ]]; then
        [[ "$DEBUG" -eq 1 ]] && echo "[DEBUG] SCC '$SCC_NAME_DEBUG' rejected: Pod needs privileged but SCC disallows it." >&2
        return 1
    fi

    local POD_NEEDS_HOSTNET SCC_ALLOWS_HOSTNET
    POD_NEEDS_HOSTNET=$(echo "$POD_JSON" | jq -r '.spec.hostNetwork // false')
    SCC_ALLOWS_HOSTNET=$(echo "$SCC_JSON" | jq -r '.allowHostNetwork // false')
    if [[ "$POD_NEEDS_HOSTNET" == "true" && "$SCC_ALLOWS_HOSTNET" != "true" ]]; then
        [[ "$DEBUG" -eq 1 ]] && echo "[DEBUG] SCC '$SCC_NAME_DEBUG' rejected: Pod needs hostNetwork but SCC disallows it." >&2
        return 1
    fi

    local POD_NEEDS_HOSTPID SCC_ALLOWS_HOSTPID
    POD_NEEDS_HOSTPID=$(echo "$POD_JSON" | jq -r '.spec.hostPID // false')
    SCC_ALLOWS_HOSTPID=$(echo "$SCC_JSON" | jq -r '.allowHostPID // false')
    if [[ "$POD_NEEDS_HOSTPID" == "true" && "$SCC_ALLOWS_HOSTPID" != "true" ]]; then
        [[ "$DEBUG" -eq 1 ]] && echo "[DEBUG] SCC '$SCC_NAME_DEBUG' rejected: Pod needs hostPID but SCC disallows it." >&2
        return 1
    fi

    local POD_NEEDS_HOSTIPC SCC_ALLOWS_HOSTIPC
    POD_NEEDS_HOSTIPC=$(echo "$POD_JSON" | jq -r '.spec.hostIPC // false')
    SCC_ALLOWS_HOSTIPC=$(echo "$SCC_JSON" | jq -r '.allowHostIPC // false')
    if [[ "$POD_NEEDS_HOSTIPC" == "true" && "$SCC_ALLOWS_HOSTIPC" != "true" ]]; then
        [[ "$DEBUG" -eq 1 ]] && echo "[DEBUG] SCC '$SCC_NAME_DEBUG' rejected: Pod needs hostIPC but SCC disallows it." >&2
        return 1
    fi

    local scc_runasuser_strategy pod_runasuser_values pod_level_uid
    scc_runasuser_strategy=$(echo "$SCC_JSON" | jq -c '.runAsUser // {}')
    pod_runasuser_values=()
    pod_level_uid=$(echo "$POD_JSON" | jq -r '.spec.securityContext.runAsUser // empty')
    if [[ -n "$pod_level_uid" ]]; then pod_runasuser_values+=("$pod_level_uid"); fi
    while IFS= read -r uid; do
        if [[ -n "$uid" && "$uid" != "null" ]]; then pod_runasuser_values+=("$uid"); fi
    done < <(echo "$POD_JSON" | jq -r '.spec.containers[]?.securityContext.runAsUser // empty' 2>/dev/null)
    while IFS= read -r uid; do
        if [[ -n "$uid" && "$uid" != "null" ]]; then pod_runasuser_values+=("$uid"); fi
    done < <(echo "$POD_JSON" | jq -r '.spec.initContainers[]?.securityContext.runAsUser // empty' 2>/dev/null)

    if ! check_id_strategy "$scc_runasuser_strategy" pod_runasuser_values "runAsUser" "$SCC_NAME_DEBUG"; then
        return 1
    fi

    local scc_runasgroup_strategy pod_runasgroup_values pod_level_gid
    scc_runasgroup_strategy=$(echo "$SCC_JSON" | jq -c '.runAsGroup // {}')
    pod_runasgroup_values=()
    pod_level_gid=$(echo "$POD_JSON" | jq -r '.spec.securityContext.runAsGroup // empty')
    if [[ -n "$pod_level_gid" ]]; then pod_runasgroup_values+=("$pod_level_gid"); fi
    while IFS= read -r gid; do
        if [[ -n "$gid" && "$gid" != "null" ]]; then pod_runasgroup_values+=("$gid"); fi
    done < <(echo "$POD_JSON" | jq -r '.spec.containers[]?.securityContext.runAsGroup // empty' 2>/dev/null)
    while IFS= read -r gid; do
        if [[ -n "$gid" && "$gid" != "null" ]]; then pod_runasgroup_values+=("$gid"); fi
    done < <(echo "$POD_JSON" | jq -r '.spec.initContainers[]?.securityContext.runAsGroup // empty' 2>/dev/null)

    if ! check_id_strategy "$scc_runasgroup_strategy" pod_runasgroup_values "runAsGroup" "$SCC_NAME_DEBUG"; then
        return 1
    fi

    local scc_fsgroup_strategy pod_fsgroup_values pod_level_fsgroup
    scc_fsgroup_strategy=$(echo "$SCC_JSON" | jq -c '.fsGroup // {}')
    pod_fsgroup_values=()
    pod_level_fsgroup=$(echo "$POD_JSON" | jq -r '.spec.securityContext.fsGroup // empty')
    if [[ -n "$pod_level_fsgroup" ]]; then pod_fsgroup_values+=("$pod_level_fsgroup"); fi

    if ! check_id_strategy "$scc_fsgroup_strategy" pod_fsgroup_values "fsGroup" "$SCC_NAME_DEBUG"; then
        return 1
    fi

    local scc_supplemental_groups_strategy pod_supplemental_groups_values supplemental_groups_json
    scc_supplemental_groups_strategy=$(echo "$SCC_JSON" | jq -c '.supplementalGroups // {}')
    pod_supplemental_groups_values=()
    supplemental_groups_json=$(echo "$POD_JSON" | jq -c '.spec.securityContext.supplementalGroups // []')
    while IFS= read -r gid; do
        if [[ -n "$gid" && "$gid" != "null" ]]; then pod_supplemental_groups_values+=("$gid"); fi
    done < <(echo "$supplemental_groups_json" | jq -r '.[]')

    if ! check_id_strategy "$scc_supplemental_groups_strategy" pod_supplemental_groups_values "supplementalGroups" "$SCC_NAME_DEBUG"; then
        return 1
    fi

    local scc_volumes_json
    scc_volumes_json=$(echo "$SCC_JSON" | jq -c '.volumes // []')
    if ! check_volumes_allowed "$scc_volumes_json" "$POD_JSON" "$SCC_NAME_DEBUG"; then
        return 1
    fi

    return 0
}

get_accessible_sccs() {
    local NS="$1"
    local SA_NAME="$2"
    local key="${NS}|${SA_NAME}"
    if [[ -n "${ACCESSIBLE_SCC_CACHE[$key]+x}" ]]; then
        echo "${ACCESSIBLE_SCC_CACHE[$key]}"
        return
    fi
    local out
    out=$(echo "$ALL_SCCS_JSON" | jq -r --arg sa "system:serviceaccount:$NS:$SA_NAME" --arg ns "$NS" "
        .items[] | select((.users[]? == \$sa) or (.groups[]? == \"system:authenticated\") or (.groups[]? == \"system:serviceaccounts\") or (.groups[]? == (\"system:serviceaccounts:\" + \$ns))) | .metadata.name")
    ACCESSIBLE_SCC_CACHE[$key]="$out"
    echo "$out"
}

try_scc_subject_review() {
    local NS="$1"
    local POD_JSON="$2"
    local TEMP_POD_FILE ACTUAL_SCC SA_NAME SIG KEY

    SA_NAME=$(echo "$POD_JSON" | jq -r '.spec.serviceAccountName // "default"')
    # Include initContainers so cache keys don't collide across pods that only differ there
    SIG=$(echo "$POD_JSON" | jq -c '{
      sa: (.spec.serviceAccountName // "default"),
      sc: (.spec.securityContext // {}),
      hostNetwork: (.spec.hostNetwork // false),
      hostPID: (.spec.hostPID // false),
      hostIPC: (.spec.hostIPC // false),
      vols: [(.spec.volumes // [])[] | {t: keys_unsorted[0], p: (.hostPath.path // null)}],
      containers: [((.spec.containers // [])[] | {
        privileged: (.securityContext.privileged // false),
        ape: .securityContext.allowPrivilegeEscalation,
        runAsUser: .securityContext.runAsUser,
        runAsGroup: .securityContext.runAsGroup,
        caps: (.securityContext.capabilities // {})
      })],
      initContainers: [((.spec.initContainers // [])[] | {
        privileged: (.securityContext.privileged // false),
        ape: .securityContext.allowPrivilegeEscalation,
        runAsUser: .securityContext.runAsUser,
        runAsGroup: .securityContext.runAsGroup,
        caps: (.securityContext.capabilities // {})
      })],
      ephemeralContainers: [((.spec.ephemeralContainers // [])[] | {
        privileged: (.securityContext.privileged // false),
        ape: .securityContext.allowPrivilegeEscalation,
        runAsUser: .securityContext.runAsUser,
        runAsGroup: .securityContext.runAsGroup,
        caps: (.securityContext.capabilities // {})
      })]
    }')
    KEY="${NS}|${SA_NAME}|${SIG}"
    if [[ -n "${SCC_REVIEW_CACHE[$KEY]+x}" ]]; then
        ACTUAL_SCC="${SCC_REVIEW_CACHE[$KEY]}"
        echo "$ACTUAL_SCC" && return 0
    fi

    TEMP_POD_FILE=$(mktemp)
    echo "$POD_JSON" | jq '{apiVersion: "v1", kind: "Pod", metadata: {name: (.metadata.name // "test"), namespace: "'"$NS"'"}, spec: .spec}' > "$TEMP_POD_FILE" 2>/dev/null

    ACTUAL_SCC=$(oc adm policy scc-subject-review -f "$TEMP_POD_FILE" -n "$NS" -o json 2>/dev/null | jq -r '.status.allowedBy.name // empty')
    rm -f "$TEMP_POD_FILE"
    # Cache positive hits only — empty/failure must not stick across transient API errors
    if [[ -n "$ACTUAL_SCC" ]]; then
      SCC_REVIEW_CACHE[$KEY]="$ACTUAL_SCC"
      echo "$ACTUAL_SCC"
      return 0
    fi
    return 1
}

try_enhanced_matching() {
    local NS="$1"
    local SA_NAME="$2"
    local POD_JSON="$3"

    local CANDIDATE_SCCS
    CANDIDATE_SCCS=$(get_accessible_sccs "$NS" "$SA_NAME")
    [[ -z "$CANDIDATE_SCCS" ]] && return 1

    local BEST_SCC=""
    local BEST_PRIORITY=-999999

    while IFS= read -r scc_name; do
        [[ -z "$scc_name" ]] && continue
        local SCC_JSON
        SCC_JSON="${SCC_BY_NAME[$scc_name]:-}"
        [[ -z "$SCC_JSON" ]] && continue

        if scc_satisfies_pod "$SCC_JSON" "$POD_JSON"; then
            local PRIORITY
            PRIORITY=$(echo "$SCC_JSON" | jq -r '.priority // 0')
            if [[ $PRIORITY -gt $BEST_PRIORITY ]]; then
                BEST_PRIORITY=$PRIORITY
                BEST_SCC="$scc_name"
            fi
        fi
    done <<< "$CANDIDATE_SCCS"

    [[ -n "$BEST_SCC" ]] && echo "$BEST_SCC" && return 0
    return 1
}

try_enhanced_matching_v2() {
    local NS="$1"
    local SA_NAME="$2"
    local POD_JSON="$3"

    local CANDIDATE_SCCS
    CANDIDATE_SCCS=$(get_accessible_sccs "$NS" "$SA_NAME")
    [[ -z "$CANDIDATE_SCCS" ]] && return 1

    local BEST_SCC=""
    local BEST_PRIORITY=-999999

    while IFS= read -r scc_name; do
        [[ -z "$scc_name" ]] && continue
        local SCC_JSON
        SCC_JSON="${SCC_BY_NAME[$scc_name]:-}"
        [[ -z "$SCC_JSON" ]] && continue

        if scc_satisfies_pod_enhanced "$SCC_JSON" "$POD_JSON"; then
            local PRIORITY
            PRIORITY=$(echo "$SCC_JSON" | jq -r '.priority // 0')
            if [[ $PRIORITY -gt $BEST_PRIORITY ]]; then
                BEST_PRIORITY=$PRIORITY
                BEST_SCC="$scc_name"
            fi
        fi
    done <<< "$CANDIDATE_SCCS"

    [[ -n "$BEST_SCC" ]] && echo "$BEST_SCC" && return 0
    return 1
}


# =============================================================================================
# BEGIN NAMESPACE ITERATION
# =============================================================================================

# -----------------------------
# Iterate namespaces (from prefetched NS_JSON)
# -----------------------------
NS_LIST=$(echo "$NS_JSON" | jq -r '.items[].metadata.name')

while read -r NS; do
    [ -z "$NS" ] && continue

    IS_SYSTEM_NS=0
    # Reserved kube names only — not kube-* prefix (lab fixtures may use kube-rbac-polp-*).
    # CRC / KubeVirt hostpath CSI namespaces are platform storage (privileged hostPath expected).
    if [[ "$NS" == "openshift" || "$NS" == openshift-* ]] \
        || [[ "$NS" == "kube-system" || "$NS" == "kube-public" || "$NS" == "kube-node-lease" ]] \
        || [[ "$NS" == "hostpath-provisioner" || "$NS" == "kubevirt-hostpath-provisioner" ]]; then
        IS_SYSTEM_NS=1
    fi
    [[ "$ONLY_USER_NS" -eq 1 && "$IS_SYSTEM_NS" -eq 1 ]] && continue

    # One list call per namespace; reuse full pod objects (no per-pod get)
    if ! PODS_JSON=$(oc get pods -n "$NS" -o json 2>/dev/null); then
            info "        --- Namespace: $NS ---"
            info "        [WARN] Failed to list pods in namespace: $NS"
            info ""
            continue
    fi
    POD_COUNT=$(echo "$PODS_JSON" | jq -r '.items | length')
    if [[ "$POD_COUNT" -eq 0 ]]; then
            [[ "$OUTPUT_MODE" == "text" ]] && echo "        --- Namespace: $NS ---" && echo "        [INFO] No pods found in namespace: $NS" && echo ""
            continue
    fi

    # Separator for each namespace output (text only — keep CSV/JSON clean)
    if [[ "$OUTPUT_MODE" == "text" ]]; then
      echo "---------------------------------------------------------"
      echo "--- Namespace: $NS ---"
      echo "---------------------------------------------------------"
      echo ""
    fi

    while IFS= read -r POD_JSON; do
        [ -z "$POD_JSON" ] && continue
        POD=$(echo "$POD_JSON" | jq -r '.metadata.name')
        [ -z "$POD" ] && continue
        SA_NAME=$(echo "$POD_JSON" | jq -r '.spec.serviceAccountName // "default"')
        CLOUD_ID="none"
        if [[ $ARO_MODE -eq 1 ]]; then
          CLOUD_ID=$(echo "$POD_JSON" | jq -r '.metadata.annotations["azure.workload.identity/client-id"] // empty')
          if [[ -z "$CLOUD_ID" ]]; then
            _sa_json=$(oc get serviceaccount "$SA_NAME" -n "$NS" -o json 2>/dev/null || true)
            if [[ -n "$_sa_json" ]]; then
              CLOUD_ID=$(echo "$_sa_json" | jq -r '.metadata.annotations["azure.workload.identity/client-id"] // .metadata.annotations["azure.workload.identity/service-account-client-id"] // empty')
            fi
          fi
          [[ -z "$CLOUD_ID" ]] && CLOUD_ID="none"
        elif [[ $ROSA_MODE -eq 1 ]]; then
          CLOUD_ID=$(echo "$POD_JSON" | jq -r '.metadata.annotations["eks.amazonaws.com/role-arn"] // .metadata.annotations["iam.amazonaws.com/role"] // empty')
          if [[ -z "$CLOUD_ID" ]]; then
            _sa_json=$(oc get serviceaccount "$SA_NAME" -n "$NS" -o json 2>/dev/null || true)
            if [[ -n "$_sa_json" ]]; then
              CLOUD_ID=$(echo "$_sa_json" | jq -r '.metadata.annotations["eks.amazonaws.com/role-arn"] // .metadata.annotations["iam.amazonaws.com/role"] // empty')
            fi
          fi
          [[ -z "$CLOUD_ID" ]] && CLOUD_ID="none"
        fi

        # Privileged container check
        # -----------------------------
        PRIV_CONTAINER=0

        # Debug output to show the steps involved
        [[ "$DEBUG" -eq 1 ]] && echo "DEBUG: Evaluating PrivilegedContainer for initContainers and containers"
		
		
        # Debugging the individual checks for privileged containers
        INIT_CONTAINER_PRIVILEGED=$(echo "$POD_JSON" | jq -r '{
            initContainers: (
                .spec.initContainers // []  # If initContainers is null, treat it as an empty array
            ) | [
                .[] | {
                    name: .name,
                    privileged: (.securityContext.privileged // false)
                }
            ]
        }')


        CONTAINER_PRIVILEGED=$(echo "$POD_JSON" | jq -r '{
            containers: (
                .spec.containers // []  # If containers is null, treat it as an empty array
            ) | [
                .[] | {
                    name: .name,
                    privileged: (.securityContext.privileged // false)
                }
            ]
        }')



        # Show the results of the individual checks with container names
        [[ "$DEBUG" -eq 1 ]] && echo "DEBUG: initContainers privileged values = $INIT_CONTAINER_PRIVILEGED"
        [[ "$DEBUG" -eq 1 ]] && echo "DEBUG: containers privileged values = $CONTAINER_PRIVILEGED"

		# Calculate PRIV_CHECK (init + containers + ephemeral; API default privileged=false)
		PRIV_CHECK=$(echo "$POD_JSON" | jq -r '
			[
				((.spec.initContainers // [])[] | .securityContext.privileged // false),
				((.spec.containers // [])[] | .securityContext.privileged // false),
				((.spec.ephemeralContainers // [])[] | .securityContext.privileged // false)
			] | any | tostring | ascii_downcase')

        # Show how PRIV_CHECK is calculated
        [[ "$DEBUG" -eq 1 ]] && echo "DEBUG: PRIV_CHECK result from jq = $PRIV_CHECK"


        # Determine if the pod has a privileged container
        if [[ "$PRIV_CHECK" == "true" ]]; then
            PRIV_CONTAINER=1
        else
            PRIV_CONTAINER=0
        fi

        # Set display output for PRIV_CONTAINER
        PRIV_CONTAINER_DISPLAY=$([[ $PRIV_CONTAINER -eq 1 ]] && echo "true (at least one container in the pod is privileged)" || echo "false")

        # Output the results
        [[ "$DEBUG" -eq 1 ]] && echo "DEBUG: PRIV_CONTAINER = $PRIV_CONTAINER"



        # AllowPrivilegeEscalation container check
        # -----------------------------
        ALLOW_PRIVILEGE_ESCALATION=0

        # Debug output to show the steps involved
        [[ "$DEBUG" -eq 1 ]] && echo "DEBUG: Evaluating AllowPrivilegeEscalation for initContainers and containers"
        
        # Debugging the individual checks for allowPrivilegeEscalation
        INIT_CONTAINER_ALLOW_PRIVILEGE_ESCALATION=$(echo "$POD_JSON" | jq -r '{
            initContainers: (
                .spec.initContainers // []  # If initContainers is null, treat it as an empty array
            ) | [
                .[] | {
                    name: .name,
                    allowPrivilegeEscalation: (.securityContext.allowPrivilegeEscalation // false)
                }
            ]
        }')

        CONTAINER_ALLOW_PRIVILEGE_ESCALATION=$(echo "$POD_JSON" | jq -r '{
            containers: (
                .spec.containers // []  # If containers is null, treat it as an empty array
            ) | [
                .[] | {
                    name: .name,
                    allowPrivilegeEscalation: (.securityContext.allowPrivilegeEscalation // false)
                }
            ]
        }')

        # Show the results of the individual checks with container names
        [[ "$DEBUG" -eq 1 ]] && echo "DEBUG: initContainers allowPrivilegeEscalation values = $INIT_CONTAINER_ALLOW_PRIVILEGE_ESCALATION"
        [[ "$DEBUG" -eq 1 ]] && echo "DEBUG: containers allowPrivilegeEscalation values = $CONTAINER_ALLOW_PRIVILEGE_ESCALATION"

        # API default allowPrivilegeEscalation=true when unset; include ephemeralContainers
        ALLOW_PRIVILEGE_ESCALATION_CHECK=$(echo "$POD_JSON" | jq -r '
            [
              ((.spec.initContainers // [])[] | ((.securityContext // {}) | .allowPrivilegeEscalation) != false),
              ((.spec.containers // [])[] | ((.securityContext // {}) | .allowPrivilegeEscalation) != false),
              ((.spec.ephemeralContainers // [])[] | ((.securityContext // {}) | .allowPrivilegeEscalation) != false)
            ] | any | tostring | ascii_downcase')

        # Show how ALLOW_PRIVILEGE_ESCALATION_CHECK is calculated
        [[ "$DEBUG" -eq 1 ]] && echo "DEBUG: ALLOW_PRIVILEGE_ESCALATION_CHECK result from jq = $ALLOW_PRIVILEGE_ESCALATION_CHECK"

        # Determine if the pod has allowPrivilegeEscalation enabled
        if [[ "$ALLOW_PRIVILEGE_ESCALATION_CHECK" == "true" ]]; then
            ALLOW_PRIVILEGE_ESCALATION=1
        else
            ALLOW_PRIVILEGE_ESCALATION=0
        fi

        # Set display output for ALLOW_PRIVILEGE_ESCALATION
        ALLOW_PRIV_ESC_DISPLAY=$([[ $ALLOW_PRIVILEGE_ESCALATION -eq 1 ]] && echo "true (at least one container in the pod has allowPrivilegeEscalation enabled)" || echo "false")

        # Output the results
        [[ "$DEBUG" -eq 1 ]] && echo "DEBUG: ALLOW_PRIVILEGE_ESCALATION = $ALLOW_PRIVILEGE_ESCALATION"


# -----------------------------
        # SCC for pod (Enhanced)
        # -----------------------------
        SCC_WAS_GUESSED=0
        SCC_CONFIDENCE="direct"
        SCC_GUESS_FROM_ENHANCED_V2=0
        SCC_UNRESOLVED=0

        # STEP 1: Check authoritative annotation
        SCC_NAME=$(echo "$POD_JSON" | jq -r '.metadata.annotations["openshift.io/scc"] // empty')

        if [[ -n "$SCC_NAME" ]]; then
            [[ "$DEBUG" -eq 1 ]] && echo "DEBUG: ✓ Found authoritative SCC annotation: $SCC_NAME"
        else
            # STEP 2: Apply enhanced guessing
            [[ "$DEBUG" -eq 1 ]] && echo "DEBUG: ✗ No SCC annotation, attempting to determine SCC..."
            SA_NAME=$(echo "$POD_JSON" | jq -r '.spec.serviceAccountName // "default"')
            SCC_WAS_GUESSED=1
            SCC_GUESS_FROM_ENHANCED_V2=0

            if SCC_NAME=$(try_scc_subject_review "$NS" "$POD_JSON"); then
                SCC_CONFIDENCE="high"
                [[ "$DEBUG" -eq 1 ]] && echo "DEBUG: ✓ scc-subject-review: $SCC_NAME"
            elif [[ "$SCC_MATCHING_VERSION" == "v2" ]] && SCC_NAME=$(try_enhanced_matching_v2 "$NS" "$SA_NAME" "$POD_JSON"); then
                SCC_CONFIDENCE="high (enhanced v2)"
                SCC_GUESS_FROM_ENHANCED_V2=1
                [[ "$DEBUG" -eq 1 ]] && echo "DEBUG: ✓ Enhanced matching v2: $SCC_NAME"
            elif [[ "$SCC_MATCHING_VERSION" == "v1" ]] && SCC_NAME=$(try_enhanced_matching "$NS" "$SA_NAME" "$POD_JSON"); then
                SCC_CONFIDENCE="high (enhanced v1)"
                [[ "$DEBUG" -eq 1 ]] && echo "DEBUG: ✓ Enhanced matching v1: $SCC_NAME"
            else
                SCC_UNRESOLVED=1
                SCC_NAME="unknown"
                SCC_CONFIDENCE="unknown"
                [[ "$DEBUG" -eq 1 ]] && echo "DEBUG: SCC could not be determined (no priority fallback)"
            fi
        fi

        # Fetch SCC JSON
        if [[ "$SCC_UNRESOLVED" -eq 1 ]]; then
            SCC_JSON=""
        else
            SCC_JSON="${SCC_BY_NAME[$SCC_NAME]:-}"
        fi

        # Validate guess and prepare display name (same bar as matcher when v2 picked the SCC)
        if [[ "$SCC_UNRESOLVED" -eq 1 ]]; then
            DISPLAY_SCC="unknown (SCC could not be determined — pod-only capability view)"
            [[ "$OUTPUT_MODE" == "text" ]] && echo "        ⚠ WARNING: SCC could not be determined (no openshift.io/scc annotation, scc-subject-review failed, and enhanced matching found no SCC). SCC-based fields are N/A; effective caps use pod spec only (baseline + requested adds, minus pod drops)."
        elif [[ "$SCC_WAS_GUESSED" -eq 1 ]]; then
            guess_ok=0
            if [[ -n "$SCC_JSON" ]]; then
                if [[ "$SCC_GUESS_FROM_ENHANCED_V2" -eq 1 ]]; then
                    scc_satisfies_pod_enhanced "$SCC_JSON" "$POD_JSON" && guess_ok=1
                else
                    scc_satisfies_pod "$SCC_JSON" "$POD_JSON" && guess_ok=1
                fi
            fi
            if [[ "$guess_ok" -eq 1 ]]; then
                DISPLAY_SCC="$SCC_NAME (guessed - $SCC_CONFIDENCE confidence)"
            else
                DISPLAY_SCC="$SCC_NAME (guessed - LOW confidence)"
                [[ "$OUTPUT_MODE" == "text" ]] && echo "        ⚠ WARNING: SCC guess may be incorrect"
            fi
        else
            DISPLAY_SCC="$SCC_NAME"
        fi


        # -----------------------------
        # Allowed caps
        # -----------------------------
        if [[ "$SCC_UNRESOLVED" -eq 1 ]]; then
            SCC_CAPS_DISPLAY="N/A (SCC unknown)"
            SCC_CAPS_ARRAY=()
        else
            SCC_CAPS=$(echo "$SCC_JSON" | jq -r '.allowedCapabilities // [] | .[]? | ascii_upcase' | grep -v '^$')
            if [[ "$SCC_CAPS" == "*" ]]; then
                    SCC_CAPS_ARRAY=("${ALL_LINUX_CAPS[@]}")
                    [[ "$DEBUG" -eq 1 ]] && echo "DEBUG: SCC Allowed Caps is '*', using ALL_LINUX_CAPS"
            elif [[ -z "$SCC_CAPS" || "$SCC_CAPS" == "null" ]]; then
                    SCC_CAPS_ARRAY=("${BASELINE_CAPS[@]}" "${BASELINE_PRIVILEGED_CAPS[@]}")
                    [[ "$DEBUG" -eq 1 ]] && echo "DEBUG: SCC Allowed Caps is 'null' or empty, using BASELINE_CAPS and BASELINE_PRIVILEGED_CAPS"
            else
                    mapfile -t TMP_SCC_CAPS_ARRAY <<< "$SCC_CAPS"
                    SCC_CAPS_ARRAY=("${TMP_SCC_CAPS_ARRAY[@]}")
                    [[ "$DEBUG" -eq 1 ]] && echo "DEBUG: SCC Allowed Caps populated from SCC: ${SCC_CAPS_ARRAY[*]}"
            fi
            SCC_CAPS_DISPLAY="${SCC_CAPS_ARRAY[*]}"
        fi

        # -----------------------------
        # Default add caps
        # -----------------------------
        if [[ "$SCC_UNRESOLVED" -eq 1 ]]; then
            SCC_DEFAULT_ADD_DISPLAY="N/A (SCC unknown)"
            SCC_DEFAULT_ADD_ARRAY=()
        else
            SCC_DEFAULT_ADD=$(echo "$SCC_JSON" | jq -r '.defaultAddCapabilities // [] | .[] | ascii_upcase' | grep -v '^$')
            if [[ -z "$SCC_DEFAULT_ADD" || "$SCC_DEFAULT_ADD" == "null" ]]; then
                    SCC_DEFAULT_ADD_DISPLAY="None"
                    SCC_DEFAULT_ADD_ARRAY=()
            elif [[ "$SCC_DEFAULT_ADD" == "*" ]]; then
                    SCC_DEFAULT_ADD_ARRAY=("${ALL_LINUX_CAPS[@]}")
                    SCC_DEFAULT_ADD_DISPLAY="${SCC_DEFAULT_ADD_ARRAY[*]}"
            else
                    mapfile -t SCC_DEFAULT_ADD_ARRAY <<< "$SCC_DEFAULT_ADD"
                    SCC_DEFAULT_ADD_DISPLAY="${SCC_DEFAULT_ADD_ARRAY[*]}"
            fi
        fi

        # -----------------------------
        # Required drop caps
        # -----------------------------
        if [[ "$SCC_UNRESOLVED" -eq 1 ]]; then
            SCC_REQUIRED_DROP_DISPLAY="N/A (SCC unknown)"
            SCC_REQUIRED_DROP_ARRAY=()
        else
            SCC_REQUIRED_DROP=$(echo "$SCC_JSON" | jq -r '.requiredDropCapabilities // [] | .[] | ascii_upcase' | grep -v '^$')
            if [[ -z "$SCC_REQUIRED_DROP" || "$SCC_REQUIRED_DROP" == "null" ]]; then
                    SCC_REQUIRED_DROP_DISPLAY="None"
                    SCC_REQUIRED_DROP_ARRAY=()
            elif [[ "$SCC_REQUIRED_DROP" == "*" ]]; then
                    SCC_REQUIRED_DROP_ARRAY=("ALL")
                    SCC_REQUIRED_DROP_DISPLAY="ALL"
            else
                    mapfile -t SCC_REQUIRED_DROP_ARRAY <<< "$SCC_REQUIRED_DROP"
                    SCC_REQUIRED_DROP_DISPLAY="${SCC_REQUIRED_DROP_ARRAY[*]}"
            fi
        fi

        # -----------------------------
        # Requested caps
        # -----------------------------
        REQUESTED_CAPS=$(echo "$POD_JSON" | jq -r '
          [(.spec.initContainers[]?.securityContext.capabilities.add // []),
           (.spec.containers[]?.securityContext.capabilities.add // [])] 
          | flatten | unique | .[]? | ascii_upcase' | grep -v '^$')

        if [[ -z "$REQUESTED_CAPS" || "$REQUESTED_CAPS" == "null" || "$REQUESTED_CAPS" == "*" ]]; then
            REQUESTED_CAPS_STR="None"
            REQUESTED_CAPS_ARRAY=()
        else
            mapfile -t REQUESTED_CAPS_ARRAY <<< "$REQUESTED_CAPS"
            REQUESTED_CAPS_STR="${REQUESTED_CAPS_ARRAY[*]}"
        fi

        # -----------------------------
        # Dropped caps from pod
        # -----------------------------
        DROPPED_CAPS=$(echo "$POD_JSON" | jq -r '
          [(.spec.initContainers[]?.securityContext.capabilities.drop // []),
           (.spec.containers[]?.securityContext.capabilities.drop // [])] 
          | flatten | unique | .[]? | ascii_upcase' | grep -v '^$')
        if [[ -z "$DROPPED_CAPS" ]]; then
            DROPPED_CAPS_STR="None"
            DROPPED_CAPS_ARRAY=()
        else
            mapfile -t DROPPED_CAPS_ARRAY <<< "$DROPPED_CAPS"
            DROPPED_CAPS_STR="${DROPPED_CAPS_ARRAY[*]}"
        fi

        # Pod & container securityContext fields
        # -----------------------------
        HOST_PID_CHECK=$(echo "$POD_JSON" | jq -r '
            [.spec.initContainers[]?.securityContext.hostPID,
             .spec.containers[]?.securityContext.hostPID,
             .spec.hostPID // false] | any(. == true) | tostring | ascii_downcase')
        [[ "$HOST_PID_CHECK" == "true" ]] && HOST_PID_DISPLAY="true (at least one container has HostPID set to True)" || HOST_PID_DISPLAY="false"
        [[ "$DEBUG" -eq 1 ]] && echo "DEBUG: HOST_PID_DISPLAY = $HOST_PID_DISPLAY"

        HOST_NETWORK_CHECK=$(echo "$POD_JSON" | jq -r '.spec.hostNetwork // false | tostring | ascii_downcase')
        [[ "$HOST_NETWORK_CHECK" == "true" ]] && HOST_NETWORK_DISPLAY="true" || HOST_NETWORK_DISPLAY="false"
        [[ "$DEBUG" -eq 1 ]] && echo "DEBUG: HOST_NETWORK_DISPLAY = $HOST_NETWORK_DISPLAY"

        HOST_IPC_CHECK=$(echo "$POD_JSON" | jq -r '
            [.spec.initContainers[]?.securityContext.hostIPC,
             .spec.containers[]?.securityContext.hostIPC,
             .spec.hostIPC // false] | any(. == true) | tostring | ascii_downcase')
        [[ "$HOST_IPC_CHECK" == "true" ]] && HOST_IPC_DISPLAY="true (at least one container has HostIPC set to True)" || HOST_IPC_DISPLAY="false"
        [[ "$DEBUG" -eq 1 ]] && echo "DEBUG: HOST_IPC_DISPLAY = $HOST_IPC_DISPLAY"

        SHARE_PROC_NS=$(echo "$POD_JSON" | jq -r '.spec.shareProcessNamespace // false | tostring | ascii_downcase')
        mapfile -t HOSTPATH_WRITABLE_PATHS < <(echo "$POD_JSON" | jq -r '
            ((.spec.volumes // []) | map(select(.hostPath != null) | {name, path: .hostPath.path})) as $hp |
            [
              (.spec.initContainers // [])[],
              (.spec.containers // [])[],
              (.spec.ephemeralContainers // [])[]
            ] as $ctrs |
            [
              $ctrs[]
              | (.volumeMounts // [])[] as $vm
              | select($vm.readOnly != true)
              | ($hp[] | select(.name == $vm.name) | .path)
            ]
            | map(select(. != null and . != ""))
            | unique[]?
        ' || true)

        # runAsNonRoot
        POD_RUNASNONROOT=$(echo "$POD_JSON" | jq -r '.spec.securityContext.runAsNonRoot // empty')
        [[ "$POD_RUNASNONROOT" == "" ]] && POD_RUNASNONROOT="unset"
        mapfile -t CONTAINER_RUNASNONROOT_VALUES < <(echo "$POD_JSON" | jq -r '
            [.spec.initContainers[]?.securityContext.runAsNonRoot,
             .spec.containers[]?.securityContext.runAsNonRoot] | map(select(. != null)) | .[]?')

        # Construct display value separating pod and container values
        RUN_AS_NONROOT_DISPLAY=""
        if [[ "$POD_RUNASNONROOT" != "unset" ]]; then
            RUN_AS_NONROOT_DISPLAY="pod:$POD_RUNASNONROOT"
        fi

        if [[ ${#CONTAINER_RUNASNONROOT_VALUES[@]} -gt 0 ]]; then
            CONTAINER_UNIQUE=$(printf "%s\n" "${CONTAINER_RUNASNONROOT_VALUES[@]}" | sort -u | paste -sd "," -)
            [[ -n "$RUN_AS_NONROOT_DISPLAY" ]] && RUN_AS_NONROOT_DISPLAY+=", "
            RUN_AS_NONROOT_DISPLAY+="containers:$CONTAINER_UNIQUE"
        fi

        [[ -z "$RUN_AS_NONROOT_DISPLAY" ]] && RUN_AS_NONROOT_DISPLAY="None"

        [[ "$DEBUG" -eq 1 ]] && echo "DEBUG: pod runAsNonRoot = $POD_RUNASNONROOT, container runAsNonRoot values = $(printf "%s," "${CONTAINER_RUNASNONROOT_VALUES[@]}" | sed 's/,$//')"
        [[ "$DEBUG" -eq 1 ]] && echo "DEBUG: RUN_AS_NONROOT_DISPLAY = $RUN_AS_NONROOT_DISPLAY"

        # runAsUser
        POD_RUNASUSER=$(echo "$POD_JSON" | jq -r '.spec.securityContext.runAsUser // empty')
        [[ "$POD_RUNASUSER" == "" ]] && POD_RUNASUSER="unset"
        mapfile -t CONTAINER_RUNASUSER_VALUES < <(echo "$POD_JSON" | jq -r '
            [.spec.initContainers[]?.securityContext.runAsUser,
             .spec.containers[]?.securityContext.runAsUser] | map(select(. != null)) | .[]?')

        # Construct display value separating pod and container values
        RUN_AS_USER_DISPLAY=""
        if [[ "$POD_RUNASUSER" != "unset" ]]; then
            RUN_AS_USER_DISPLAY="pod:$POD_RUNASUSER"
        fi

        if [[ ${#CONTAINER_RUNASUSER_VALUES[@]} -gt 0 ]]; then
            CONTAINER_UNIQUE=$(printf "%s\n" "${CONTAINER_RUNASUSER_VALUES[@]}" | sort -u | paste -sd "," -)
            [[ -n "$RUN_AS_USER_DISPLAY" ]] && RUN_AS_USER_DISPLAY+=", "
            RUN_AS_USER_DISPLAY+="containers:$CONTAINER_UNIQUE"
        fi

        [[ -z "$RUN_AS_USER_DISPLAY" ]] && RUN_AS_USER_DISPLAY="None"

        [[ "$DEBUG" -eq 1 ]] && echo "DEBUG: pod runAsUser = $POD_RUNASUSER, container runAsUser values = $(printf "%s," "${CONTAINER_RUNASUSER_VALUES[@]}" | sed 's/,$//')"
        [[ "$DEBUG" -eq 1 ]] && echo "DEBUG: RUN_AS_USER_DISPLAY = $RUN_AS_USER_DISPLAY"

        # --- automountServiceAccountToken + SA privileged caps check (optimized, full debug) ---

                AUTOMOUNT_WARNING=0
                RAW_POD_AUTOMOUNT=$(echo "$POD_JSON" | jq -r '.spec.automountServiceAccountToken')
        if [[ "$RAW_POD_AUTOMOUNT" == "false" ]]; then
                POD_AUTOMOUNT_LOGIC=0
                POD_AUTOMOUNT_REASON="pod-level false"
        else
                POD_AUTOMOUNT_LOGIC=1
                if [[ "$RAW_POD_AUTOMOUNT" == "true" ]]; then
                        POD_AUTOMOUNT_REASON="pod-level true"
                else
                        POD_AUTOMOUNT_REASON="default (true)"
                fi
        fi

        mapfile -t CONTAINER_AUTOMOUNT_VALUES < <(
                echo "$POD_JSON" | jq -r '
                  [.spec.initContainers[]?.automountServiceAccountToken,
                   .spec.containers[]?.automountServiceAccountToken]
                  | .[]?
                '
        )

        mapfile -t CONTAINER_NAMES < <(
                echo "$POD_JSON" | jq -r '
                  [.spec.initContainers[]?.name,
                   .spec.containers[]?.name]
                  | .[]?
                '
        )

        AUTOMOUNT_TRUE=$POD_AUTOMOUNT_LOGIC
        AUTOMOUNT_REASON="$POD_AUTOMOUNT_REASON"
        ALL_CONTAINERS_FALSE=1
        LAST_FALSE_CONTAINER=""

        for i in "${!CONTAINER_AUTOMOUNT_VALUES[@]}"; do
                val="${CONTAINER_AUTOMOUNT_VALUES[$i]}"
                cname="${CONTAINER_NAMES[$i]}"
                if [[ "$val" == "true" ]]; then
                        AUTOMOUNT_TRUE=1
                        AUTOMOUNT_REASON="container-level true ($cname)"
                        ALL_CONTAINERS_FALSE=0
                        break
                elif [[ "$val" == "false" ]]; then
                        LAST_FALSE_CONTAINER="$cname"
                else
                        ALL_CONTAINERS_FALSE=0
                fi
        done

        if [[ ${#CONTAINER_AUTOMOUNT_VALUES[@]} -gt 0 && $ALL_CONTAINERS_FALSE -eq 1 ]]; then
                AUTOMOUNT_TRUE=0
                AUTOMOUNT_REASON="all containers explicitly false"
        elif [[ $AUTOMOUNT_TRUE -eq 0 && -n "$LAST_FALSE_CONTAINER" ]]; then
                AUTOMOUNT_REASON="container-level false ($LAST_FALSE_CONTAINER)"
        fi

        # --- ServiceAccount and privileged SCCs (skipped when SCC unknown — SCC-derived) ---
        SA_NAME=$(echo "$POD_JSON" | jq -r '.spec.serviceAccountName // "default"')

        unset SCC_PRIV_CAPS
        declare -A SCC_PRIV_CAPS
        if [[ "$SCC_UNRESOLVED" -eq 0 ]]; then
                mapfile -t SA_PRIV_SCCS < <(
                        echo "$ALL_SCCS_JSON" | jq -r --arg sa "system:serviceaccount:$NS:$SA_NAME" --arg ns "$NS" '
                            .items[]
                            | select(
                                (.users[]? == $sa)
                                or (.groups[]? == "system:authenticated")
                                or (.groups[]? == "system:serviceaccounts")
                                or (.groups[]? == ("system:serviceaccounts:" + $ns))
                              )
                            | "\(.metadata.name):\((.allowedCapabilities // []) | join(","))"'
                )
                for scc_entry in "${SA_PRIV_SCCS[@]}"; do
                        scc_name="${scc_entry%%:*}"
                        caps="${scc_entry#*:}"
                        PRIV_FOUND=()
                        IFS=',' read -ra CAP_ARRAY <<< "$caps"
                        for c in "${CAP_ARRAY[@]}"; do
                                case "$(echo "$c" | awk '{print toupper($0)}')" in
                                        SYS_ADMIN|NET_ADMIN|SYS_TIME|SYS_MODULE|SYS_RAWIO)
                                                PRIV_FOUND+=("$c")
                                                ;;
                                esac
                        done
                        if [[ ${#PRIV_FOUND[@]} -gt 0 ]]; then
                                SCC_PRIV_CAPS["$scc_name"]=$(IFS=','; echo "${PRIV_FOUND[*]}")
                        fi
                done
        fi

        # --- Debug output ---
        if [[ "$DEBUG" -eq 1 ]]; then
                echo "DEBUG: privileged SCCs for SA $SA_NAME:"
                if [[ ${#SCC_PRIV_CAPS[@]} -eq 0 ]]; then
                        echo "None"
                else
                        for scc in "${!SCC_PRIV_CAPS[@]}"; do
                                echo "$scc: ${SCC_PRIV_CAPS[$scc]}"
                        done
                fi

                echo "DEBUG: RAW_POD_AUTOMOUNT=$RAW_POD_AUTOMOUNT"
                echo "DEBUG: POD_AUTOMOUNT_LOGIC=$POD_AUTOMOUNT_LOGIC ($POD_AUTOMOUNT_REASON)"
                echo "DEBUG: CONTAINER_AUTOMOUNT_VALUES=(${CONTAINER_AUTOMOUNT_VALUES[*]})"
                echo "DEBUG: CONTAINER_NAMES=(${CONTAINER_NAMES[*]})"
                echo "DEBUG: AUTOMOUNT_TRUE=$AUTOMOUNT_TRUE"
                echo "DEBUG: AUTOMOUNT_REASON=$AUTOMOUNT_REASON"
        fi

        if [[ $AUTOMOUNT_TRUE -eq 1 ]]; then
            AUTOMOUNT_DISPLAY="true ($AUTOMOUNT_REASON)"
        else
            AUTOMOUNT_DISPLAY="false ($AUTOMOUNT_REASON)"
        fi

        # -----------------------------
        # Effective capabilities calculation
        # -----------------------------

        [[ "$DEBUG" -eq 1 ]] && echo "DEBUG: PRIV_CONTAINER before effective caps calculation = $PRIV_CONTAINER"

        DROP_ALL=0
        if [[ "$SCC_UNRESOLVED" -eq 1 ]]; then
                containsElement "ALL" "${DROPPED_CAPS_ARRAY[@]}" && DROP_ALL=1
        elif containsElement "ALL" "${DROPPED_CAPS_ARRAY[@]}" || containsElement "ALL" "${SCC_REQUIRED_DROP_ARRAY[@]}"; then
                DROP_ALL=1
        fi
        [[ "$DEBUG" -eq 1 ]] && echo "DEBUG: DROP_ALL set to $DROP_ALL"

        if [[ "$PRIV_CONTAINER" -eq 1 ]]; then
                EFFECTIVE_CAPS=("${ALL_LINUX_CAPS[@]}")
                [[ "$DEBUG" -eq 1 ]] && echo "        Step 0 - Privileged container detected, all capabilities granted: ${EFFECTIVE_CAPS[*]}"
        elif [[ "$SCC_UNRESOLVED" -eq 1 ]]; then
                [[ "$DEBUG" -eq 1 ]] && echo "DEBUG: SCC unknown — pod-only effective caps (baseline + all requested adds, minus pod drops only)"
                EFFECTIVE_CAPS=()
                if [[ $DROP_ALL -eq 0 ]]; then
                        EFFECTIVE_CAPS+=("${BASELINE_CAPS[@]}" "${BASELINE_PRIVILEGED_CAPS[@]}")
                fi
                if [[ $DROP_ALL -eq 0 ]]; then
                        EFFECTIVE_CAPS+=("${REQUESTED_CAPS_ARRAY[@]}")
                fi
                ALL_SPECIFIC_DROPS=()
                for d in "${DROPPED_CAPS_ARRAY[@]}"; do
                        [[ "$d" != "ALL" ]] && ALL_SPECIFIC_DROPS+=("$d")
                done
                TMP_EFFECTIVE=()
                for cap in "${EFFECTIVE_CAPS[@]}"; do
                        skip=0
                        for drop in "${ALL_SPECIFIC_DROPS[@]}"; do
                                [[ "$cap" == "$drop" ]] && skip=1 && break
                        done
                        [[ $skip -eq 0 ]] && TMP_EFFECTIVE+=("$cap")
                        [[ "$DEBUG" -eq 1 && $skip -eq 1 ]] && echo "        Step 4 - Dropped specific cap: $cap"
                done
                # Empty array + printf "%s\n" emits a blank line; guard so DROP ALL stays truly empty.
                if [[ ${#TMP_EFFECTIVE[@]} -eq 0 ]]; then
                        EFFECTIVE_CAPS=()
                else
                        mapfile -t EFFECTIVE_CAPS < <(printf "%s\n" "${TMP_EFFECTIVE[@]}" | awk 'NF && !seen[$0]++')
                fi
                [[ "$DEBUG" -eq 1 ]] && echo "        Step 5 - Effective caps after dedup (pod-only): ${EFFECTIVE_CAPS[*]}"
        else
                [[ "$DEBUG" -eq 1 ]] && echo "DEBUG: Privileged container not detected, using normal effective caps logic"

                EFFECTIVE_CAPS=()
                if [[ $DROP_ALL -eq 0 ]]; then
                        EFFECTIVE_CAPS+=("${BASELINE_CAPS[@]}" "${BASELINE_PRIVILEGED_CAPS[@]}")
                        [[ "$DEBUG" -eq 1 ]] && echo "        Step 1 - baseline caps added: ${EFFECTIVE_CAPS[*]}"
                else
                        [[ "$DEBUG" -eq 1 ]] && echo "        Step 1 - DROP ALL detected, skipping baseline + defaultAddCaps"
                fi

                if [[ $DROP_ALL -eq 0 ]]; then
                        EFFECTIVE_CAPS+=("${SCC_DEFAULT_ADD_ARRAY[@]}")
                        [[ "$DEBUG" -eq 1 ]] && echo "        Step 2 - After defaultAddCapabilities: ${EFFECTIVE_CAPS[*]}"
                fi

                for cap in "${REQUESTED_CAPS_ARRAY[@]}"; do
                        if containsElement "$cap" "${SCC_CAPS_ARRAY[@]}" && [[ $DROP_ALL -eq 0 ]]; then
                                EFFECTIVE_CAPS+=("$cap")
                                [[ "$DEBUG" -eq 1 ]] && echo "        Step 3 - Added requested cap allowed by SCC: $cap"
                        elif [[ $DROP_ALL -eq 0 ]]; then
                                [[ "$DEBUG" -eq 1 ]] && echo "        Step 3 - Requested cap $cap NOT allowed by SCC"
                        fi
                done

                ALL_SPECIFIC_DROPS=()
                for d in "${DROPPED_CAPS_ARRAY[@]}" "${SCC_REQUIRED_DROP_ARRAY[@]}"; do
                        [[ "$d" != "ALL" ]] && ALL_SPECIFIC_DROPS+=("$d")
                done

                TMP_EFFECTIVE=()
                for cap in "${EFFECTIVE_CAPS[@]}"; do
                        skip=0
                        for drop in "${ALL_SPECIFIC_DROPS[@]}"; do
                                [[ "$cap" == "$drop" ]] && skip=1 && break
                        done
                        [[ $skip -eq 0 ]] && TMP_EFFECTIVE+=("$cap")
                        [[ "$DEBUG" -eq 1 && $skip -eq 1 ]] && echo "        Step 4 - Dropped specific cap: $cap"
                done

                if [[ ${#TMP_EFFECTIVE[@]} -eq 0 ]]; then
                        EFFECTIVE_CAPS=()
                else
                        mapfile -t EFFECTIVE_CAPS < <(printf "%s\n" "${TMP_EFFECTIVE[@]}" | awk 'NF && !seen[$0]++')
                fi
                [[ "$DEBUG" -eq 1 ]] && echo "        Step 5 - Effective caps after dedup: ${EFFECTIVE_CAPS[*]}"
        fi

        [[ "$DEBUG" -eq 1 ]] && echo "DEBUG: PRIV_CONTAINER after effective caps calculation = $PRIV_CONTAINER"

        # -----------------------------
        # Handle "DROP ALL" case BEFORE tagging
        # -----------------------------
        if [[ $DROP_ALL -eq 1 && ${#EFFECTIVE_CAPS[@]} -eq 0 ]]; then
                # No capabilities left after DROP ALL, so return a message
                EFFECTIVE_CAPS_STR="DROP ALL applied - No capabilities remaining"
                EFFECTIVE_CAPS_TAGGED=()
        else
                # Otherwise, prepare for tagging and final output string
                EFFECTIVE_CAPS_TAGGED=()
                for cap in "${EFFECTIVE_CAPS[@]}"; do
                        [[ -z "$cap" ]] && continue
                        if containsElement "$cap" "${BASELINE_CAPS[@]}"; then
                                EFFECTIVE_CAPS_TAGGED+=("$cap (baseline)")
                        elif containsElement "$cap" "${BASELINE_PRIVILEGED_CAPS[@]}"; then
                                EFFECTIVE_CAPS_TAGGED+=("$cap (baseline privileged)")
                        elif containsElement "$cap" "${PRIVILEGED_CAPS[@]}"; then
                                EFFECTIVE_CAPS_TAGGED+=("$cap (privileged)")
                        else
                                EFFECTIVE_CAPS_TAGGED+=("$cap")
                        fi
                done

                # Final string after tagging
                if [[ $DROP_ALL -eq 1 && ${#EFFECTIVE_CAPS_TAGGED[@]} -eq 0 ]]; then
                        EFFECTIVE_CAPS_STR="DROP ALL applied - No capabilities remaining"
                else
                        EFFECTIVE_CAPS_STR="${EFFECTIVE_CAPS_TAGGED[*]}"
                fi
        fi

        ESCAPE_CHAIN_MSGS=()
        check_escape_chains

        # -----------------------------
        # Status determination (ranked user-NS findings -> worst rank + " — also: " for ties; INFO_OK otherwise)
        STATUS_RANKS=()
        STATUS_MSGS=()
        ALERTS_INFO_OK=()

        # --- User namespace alerts ---
        if [[ "$IS_SYSTEM_NS" -eq 0 ]]; then
            [[ "$PRIV_CONTAINER" -eq 1 ]] && status_push 5 "CRITICAL: privileged container in user namespace - Please VERIFY!!"
            [[ "$ALLOW_PRIVILEGE_ESCALATION" -eq 1 ]] && status_push 4 "HIGH: at least a container allows privilege escalation in user namespace - Please VERIFY!!"
            if [[ "$HOST_NETWORK_CHECK" == "true" || "$HOST_PID_CHECK" == "true" || "$HOST_IPC_CHECK" == "true" ]]; then
                HOST_FLAG_PARTS_OSHIFT=()
                [[ "$HOST_NETWORK_CHECK" == "true" ]] && HOST_FLAG_PARTS_OSHIFT+=("hostNetwork")
                [[ "$HOST_PID_CHECK" == "true" ]] && HOST_FLAG_PARTS_OSHIFT+=("hostPID")
                [[ "$HOST_IPC_CHECK" == "true" ]] && HOST_FLAG_PARTS_OSHIFT+=("hostIPC")
                HOST_FLAG_JOIN_OSHIFT=$(IFS=,; echo "${HOST_FLAG_PARTS_OSHIFT[*]}")
                status_push 4 "HIGH: host access enabled ($HOST_FLAG_JOIN_OSHIFT) in user namespace - Please VERIFY!!"
            fi

            RUNASUSER_ZERO=0
            [[ "$POD_RUNASUSER" == "0" ]] && RUNASUSER_ZERO=1
            for val in "${CONTAINER_RUNASUSER_VALUES[@]}"; do [[ "$val" == "0" ]] && RUNASUSER_ZERO=1; done
            [[ $RUNASUSER_ZERO -eq 1 ]] && status_push 5 "CRITICAL: runAsUser=0 in pod or container - Please VERIFY!!"

            PRIV_CAP_PRESENT=0
            for cap in "${EFFECTIVE_CAPS[@]}"; do
                if containsElement "$cap" "${PRIVILEGED_CAPS[@]}"; then
                    PRIV_CAP_PRESENT=1
                    break
                fi
            done
            [[ $PRIV_CAP_PRESENT -eq 1 ]] && status_push 3 "WARNING: at least one privileged capability in user namespace - Please VERIFY!!"

            # --- AUTOMOUNT warning for user namespace ---
            AUTOMOUNT_PRIV_CAPS_BUILT=0

            if [[ ${#SCC_PRIV_CAPS[@]} -gt 0 && $AUTOMOUNT_TRUE -eq 1 && $AUTOMOUNT_PRIV_CAPS_BUILT -eq 0 ]]; then
                        AUTOMOUNT_WARNING=1
                        AUTOMOUNT_PRIV_CAPS=""
                        for scc in "${!SCC_PRIV_CAPS[@]}"; do
                                    [[ -n "$AUTOMOUNT_PRIV_CAPS" ]] && AUTOMOUNT_PRIV_CAPS+=", "
                                    AUTOMOUNT_PRIV_CAPS+="$scc: ${SCC_PRIV_CAPS[$scc]}"
                        done
                        AUTOMOUNT_PRIV_CAPS_BUILT=1

                        [[ "$DEBUG" -eq 1 ]] && echo "DEBUG: automount warning triggered, privileged caps = $AUTOMOUNT_PRIV_CAPS" && echo ""
            fi

            if [[ $AUTOMOUNT_WARNING -eq 1 ]]; then
                status_push 3 "WARNING: service account token with privileged capabilities automounted in user namespace - Please VERIFY!! (Privileged caps: $AUTOMOUNT_PRIV_CAPS; Reason: $AUTOMOUNT_REASON)"
            fi

            NONBASE_CAPS_OSHIFT=()
            for cap in "${EFFECTIVE_CAPS[@]}"; do
                [[ -z "$cap" ]] && continue
                if containsElement "$cap" "${PRIVILEGED_CAPS[@]}"; then
                    continue
                elif cap_in_baseline_union "$cap"; then
                    continue
                else
                    NONBASE_CAPS_OSHIFT+=("$cap")
                fi
            done
            if [[ ${#NONBASE_CAPS_OSHIFT[@]} -gt 0 ]]; then
                NONBASE_JOIN_OSHIFT=$(printf '%s\n' "${NONBASE_CAPS_OSHIFT[@]}" | sort -u | paste -sd "," -)
                status_push 2 "MEDIUM: non-baseline capability ($NONBASE_JOIN_OSHIFT) in user namespace - Please VERIFY!!"
            fi

            # --- INFO / OK if no ranked severity findings ---
            if [[ ${#STATUS_RANKS[@]} -eq 0 ]]; then
                BASELINE_PRIV_PRESENT=0
                for cap in "${EFFECTIVE_CAPS[@]}"; do
                    if containsElement "$cap" "${BASELINE_PRIVILEGED_CAPS[@]}"; then
                        BASELINE_PRIV_PRESENT=1
                        break
                    fi
                done
                [[ $BASELINE_PRIV_PRESENT -eq 1 ]] && ALERTS_INFO_OK+=("INFO: baseline privileged capabilities present in user namespace")

                ONLY_BASELINE_CAPS=1
                for cap in "${EFFECTIVE_CAPS[@]}"; do
                    if ! containsElement "$cap" "${BASELINE_CAPS[@]}"; then
                        ONLY_BASELINE_CAPS=0
                        break
                    fi
                done
                [[ $ONLY_BASELINE_CAPS -eq 1 && ${#EFFECTIVE_CAPS[@]} -gt 0 ]] && ALERTS_INFO_OK+=("OK: only baseline capabilities in user namespace")

                if [[ ${#EFFECTIVE_CAPS[@]} -eq 0 ]]; then
                    if [[ $DROP_ALL -eq 1 ]]; then
                        ALERTS_INFO_OK+=("OK: DROP ALL - no capabilities remaining")
                    else
                        ALERTS_INFO_OK+=("INFO: no capabilities detected")
                    fi
                fi
            fi

        # --- System namespace alerts ---
        else
            [[ "$PRIV_CONTAINER" -eq 1 ]] && ALERTS_INFO_OK+=("Privileged container - system namespace, probably expected")
            [[ "$ALLOW_PRIVILEGE_ESCALATION" -eq 1 ]] && ALERTS_INFO_OK+=("AllowPrivilegeEscalation - system namespace, probably expected")
            [[ "$HOST_NETWORK_CHECK" == "true" ]] && ALERTS_INFO_OK+=("hostNetwork=true - system namespace, probably expected")

            RUNASUSER_ZERO=0
            [[ "$POD_RUNASUSER" == "0" ]] && RUNASUSER_ZERO=1
            for val in "${CONTAINER_RUNASUSER_VALUES[@]}"; do [[ "$val" == "0" ]] && RUNASUSER_ZERO=1; done
            [[ $RUNASUSER_ZERO -eq 1 ]] && ALERTS_INFO_OK+=("runAsUser=0 - system namespace, probably expected")

            PRIV_CAP_PRESENT=0
            for cap in "${EFFECTIVE_CAPS[@]}"; do
                if containsElement "$cap" "${PRIVILEGED_CAPS[@]}"; then
                    PRIV_CAP_PRESENT=1
                    break
                fi
            done
            [[ $PRIV_CAP_PRESENT -eq 1 ]] && ALERTS_INFO_OK+=("Privileged capabilities present - system namespace, probably expected")

            # Use precomputed automount values accurately
            if [[ $AUTOMOUNT_TRUE -eq 1 ]]; then
                ALERTS_INFO_OK+=("service account token automounted in system namespace, probably expected (Reason: $AUTOMOUNT_REASON)")
            fi
        fi

        # -----------------------------
        # Merge alerts into STATUS (worst rank + same-rank "also:", like Vanilla/GKE)
        if [[ ${#STATUS_RANKS[@]} -gt 0 ]]; then
            max_r_os=0
            for r in "${STATUS_RANKS[@]}"; do
                [[ "$r" -gt "$max_r_os" ]] && max_r_os=$r
            done
            same_msgs_os=()
            for i in "${!STATUS_RANKS[@]}"; do
                [[ "${STATUS_RANKS[$i]}" -eq "$max_r_os" ]] && same_msgs_os+=("${STATUS_MSGS[$i]}")
            done
            primary_os="${same_msgs_os[0]}"
            if [[ ${#same_msgs_os[@]} -eq 1 ]]; then
                STATUS="$primary_os"
            else
                also_os=$(printf '%s\n' "${same_msgs_os[@]:1}" | paste -sd "; " -)
                STATUS="$primary_os — also: $also_os"
            fi
        else
            printf -v STATUS '%s; ' "${ALERTS_INFO_OK[@]}"
            STATUS="${STATUS%'; '}"
        fi

        # Ensure STATUS is never empty
        [[ -z "$STATUS" ]] && STATUS="OK: no issues detected"
        [[ "$SCC_UNRESOLVED" -eq 1 ]] && STATUS+="; INFO: SCC unknown — pod-only capability estimate (not admission-accurate)"

        if [[ ${#ESCAPE_CHAIN_MSGS[@]} -eq 0 ]]; then
            ESCAPE_CHAINS_CSV=""
            ESCAPE_CHAINS_JSON='[]'
        else
            ESCAPE_CHAINS_CSV=$(printf '%s; ' "${ESCAPE_CHAIN_MSGS[@]}" | sed 's/; $//')
            ESCAPE_CHAINS_JSON=$(printf '%s\n' "${ESCAPE_CHAIN_MSGS[@]}" | jq -R . | jq -s .)
        fi

        # -----------------------------
        # Output (8-space indentation)
        if [[ "$OUTPUT_MODE" == "text" ]]; then
                echo "        --- Pod: $POD ---"
                echo "        SCC: $DISPLAY_SCC"
				echo "        Service Account: $SA_NAME"
                if [[ $ARO_MODE -eq 1 ]]; then
                  echo "        workloadIdentityClientId: $CLOUD_ID"
                elif [[ $ROSA_MODE -eq 1 ]]; then
                  echo "        irsaIamRoleArn: $CLOUD_ID"
                fi
                echo "        Privileged Container: $PRIV_CONTAINER_DISPLAY"
                echo "        Allow Privilege Escalation: $ALLOW_PRIV_ESC_DISPLAY"
                echo "        hostPID: $HOST_PID_DISPLAY"
                echo "        hostNetwork: $HOST_NETWORK_DISPLAY"
                echo "        hostIPC: $HOST_IPC_DISPLAY"
                echo "        runAsNonRoot: $RUN_AS_NONROOT_DISPLAY"
                echo "        runAsUser: $RUN_AS_USER_DISPLAY"
                echo "        automountServiceAccountToken: $AUTOMOUNT_DISPLAY"
                echo "        SCC Allowed Caps: $SCC_CAPS_DISPLAY"
                echo "        SCC Default Add Caps: $SCC_DEFAULT_ADD_DISPLAY"
                echo "        SCC Required Drop Caps: $SCC_REQUIRED_DROP_DISPLAY"
                echo "        Requested Caps from Pod: $REQUESTED_CAPS_STR"
                if [[ "$SCC_UNRESOLVED" -eq 0 ]]; then
                        for cap in "${REQUESTED_CAPS_ARRAY[@]}"; do
                                if ! containsElement "$cap" "${SCC_CAPS_ARRAY[@]}"; then
                                        echo "        NOTE: requested cap $cap NOT allowed by SCC"
                                fi
                        done
                fi
                echo "        Dropped Caps from Pod: $DROPPED_CAPS_STR"
                echo "        Effective Caps: $EFFECTIVE_CAPS_STR"
                echo "        Status: $STATUS"
                for _ec in "${ESCAPE_CHAIN_MSGS[@]}"; do
                        echo "        $_ec"
                done
                echo ""

        elif [[ "$OUTPUT_MODE" == "csv" ]]; then
                NS_ESCAPED=${NS//\"/\"\"}
                POD_ESCAPED=${POD//\"/\"\"}
                SCC_NAME_ESCAPED=${SCC_NAME//\"/\"\"}
				SA_NAME_ESCAPED=${SA_NAME//\"/\"\"} 
                PRIV_TEXT_ESCAPED=${PRIV_CONTAINER_DISPLAY//\"/\"\"}
                STATUS_ESCAPED=${STATUS//\"/\"\"}
                SCC_CAPS_DISPLAY_ESCAPED=${SCC_CAPS_DISPLAY//\"/\"\"}
                SCC_DEFAULT_ADD_DISPLAY_ESCAPED=${SCC_DEFAULT_ADD_DISPLAY//\"/\"\"}
                SCC_REQUIRED_DROP_DISPLAY_ESCAPED=${SCC_REQUIRED_DROP_DISPLAY//\"/\"\"}
                REQUESTED_CAPS_STR_ESCAPED=${REQUESTED_CAPS_STR//\"/\"\"}
                DROPPED_CAPS_STR_ESCAPED=${DROPPED_CAPS_STR//\"/\"\"}
                EFFECTIVE_CAPS_STR_ESCAPED=${EFFECTIVE_CAPS_STR//\"/\"\"}
                ALLOW_PRIV_ESC_DISPLAY_ESCAPED=${ALLOW_PRIV_ESC_DISPLAY//\"/\"\"}
                HOST_PID_DISPLAY_ESCAPED=${HOST_PID_DISPLAY//\"/\"\"}
                HOST_NETWORK_DISPLAY_ESCAPED=${HOST_NETWORK_DISPLAY//\"/\"\"}
                HOST_IPC_DISPLAY_ESCAPED=${HOST_IPC_DISPLAY//\"/\"\"}
                RUN_AS_NONROOT_DISPLAY_ESCAPED=${RUN_AS_NONROOT_DISPLAY//\"/\"\"}
                RUN_AS_USER_DISPLAY_ESCAPED=${RUN_AS_USER_DISPLAY//\"/\"\"}
                ESCAPE_CHAINS_ESCAPED=${ESCAPE_CHAINS_CSV//\"/\"\"}

                # dynamic automount for CSV
                if [[ $AUTOMOUNT_TRUE -eq 1 ]]; then
                        AUTOMOUNT_DISPLAY_ESCAPED="true ($AUTOMOUNT_REASON)"
                else
                        AUTOMOUNT_DISPLAY_ESCAPED="false ($AUTOMOUNT_REASON)"
                fi
                AUTOMOUNT_DISPLAY_ESCAPED=${AUTOMOUNT_DISPLAY_ESCAPED//\"/\"\"}

                CLOUD_ID_ESCAPED=${CLOUD_ID//\"/\"\"} 
                if [[ $ARO_MODE -eq 1 || $ROSA_MODE -eq 1 ]]; then
                  echo "\"$NS_ESCAPED\",\"$POD_ESCAPED\",\"$SCC_NAME_ESCAPED\",\"$SA_NAME_ESCAPED\",\"$PRIV_TEXT_ESCAPED\",\"$STATUS_ESCAPED\",\"$SCC_CAPS_DISPLAY_ESCAPED\",\"$SCC_DEFAULT_ADD_DISPLAY_ESCAPED\",\"$SCC_REQUIRED_DROP_DISPLAY_ESCAPED\",\"$REQUESTED_CAPS_STR_ESCAPED\",\"$DROPPED_CAPS_STR_ESCAPED\",\"$EFFECTIVE_CAPS_STR_ESCAPED\",\"$ALLOW_PRIV_ESC_DISPLAY_ESCAPED\",\"$HOST_PID_DISPLAY_ESCAPED\",\"$HOST_NETWORK_DISPLAY_ESCAPED\",\"$HOST_IPC_DISPLAY_ESCAPED\",\"$RUN_AS_NONROOT_DISPLAY_ESCAPED\",\"$RUN_AS_USER_DISPLAY_ESCAPED\",\"$ESCAPE_CHAINS_ESCAPED\",\"$AUTOMOUNT_DISPLAY_ESCAPED\",\"$CLOUD_ID_ESCAPED\""
                else
                  echo "\"$NS_ESCAPED\",\"$POD_ESCAPED\",\"$SCC_NAME_ESCAPED\",\"$SA_NAME_ESCAPED\",\"$PRIV_TEXT_ESCAPED\",\"$STATUS_ESCAPED\",\"$SCC_CAPS_DISPLAY_ESCAPED\",\"$SCC_DEFAULT_ADD_DISPLAY_ESCAPED\",\"$SCC_REQUIRED_DROP_DISPLAY_ESCAPED\",\"$REQUESTED_CAPS_STR_ESCAPED\",\"$DROPPED_CAPS_STR_ESCAPED\",\"$EFFECTIVE_CAPS_STR_ESCAPED\",\"$ALLOW_PRIV_ESC_DISPLAY_ESCAPED\",\"$HOST_PID_DISPLAY_ESCAPED\",\"$HOST_NETWORK_DISPLAY_ESCAPED\",\"$HOST_IPC_DISPLAY_ESCAPED\",\"$RUN_AS_NONROOT_DISPLAY_ESCAPED\",\"$RUN_AS_USER_DISPLAY_ESCAPED\",\"$ESCAPE_CHAINS_ESCAPED\",\"$AUTOMOUNT_DISPLAY_ESCAPED\""
                fi

        elif [[ "$OUTPUT_MODE" == "json" ]]; then
                PRIV_TEXT_JSON=$PRIV_CONTAINER_DISPLAY
                if [[ ${#EFFECTIVE_CAPS_TAGGED[@]} -eq 0 ]]; then
                  EFFECTIVE_JSON='[]'
                else
                  EFFECTIVE_JSON=$(printf '%s\n' "${EFFECTIVE_CAPS_TAGGED[@]}" | jq -R . | jq -s .)
                fi

                # dynamic automount for JSON
                if [[ $AUTOMOUNT_TRUE -eq 1 ]]; then
                        AUTOMOUNT_JSON=true
                        AUTOMOUNT_REASON_JSON="$AUTOMOUNT_REASON"
                else
                        AUTOMOUNT_JSON=false
                        AUTOMOUNT_REASON_JSON="$AUTOMOUNT_REASON"
                fi

                JSON_ITEM=$(jq -c -n \
                        --arg ns "$NS" \
                        --arg pod "$POD" \
                        --arg scc "$SCC_NAME" \
						--arg sa "$SA_NAME" \
                        --arg priv "$PRIV_TEXT_JSON" \
                        --arg status "$STATUS" \
                        --arg scc_caps "$SCC_CAPS_DISPLAY" \
                        --arg default_add "$SCC_DEFAULT_ADD_DISPLAY" \
                        --arg required_drop "$SCC_REQUIRED_DROP_DISPLAY" \
                        --arg requested "$REQUESTED_CAPS_STR" \
                        --arg dropped "$DROPPED_CAPS_STR" \
                        --arg allow_priv "$ALLOW_PRIV_ESC_DISPLAY" \
                        --arg hostPID "$HOST_PID_DISPLAY" \
                        --arg hostNetwork "$HOST_NETWORK_DISPLAY" \
                        --arg hostIPC "$HOST_IPC_DISPLAY" \
                        --arg runAsNonRoot "$RUN_AS_NONROOT_DISPLAY" \
                        --arg runAsUser "$RUN_AS_USER_DISPLAY" \
                        --argjson automount "$AUTOMOUNT_JSON" \
                        --arg automount_reason "$AUTOMOUNT_REASON_JSON" \
                        --argjson effective "$EFFECTIVE_JSON" \
                        --argjson escape_chains "$ESCAPE_CHAINS_JSON" \
                        "{
                                namespace: \$ns,
                                pod: \$pod,
                                scc: \$scc,
                                serviceAccount: \$sa,
                                privileged: \$priv,
                                status: \$status,
                                scc_caps: \$scc_caps,
                                defaultAddCapabilities: \$default_add,
                                requiredDropCapabilities: \$required_drop,
                                requested_caps_from_pod: \$requested,
                                dropped_caps_from_pod: \$dropped,
                                effective_caps: \$effective,
                                escape_chains: \$escape_chains,
                                allowPrivilegeEscalation: \$allow_priv,
                                hostPID: \$hostPID,
                                hostNetwork: \$hostNetwork,
                                hostIPC: \$hostIPC,
                                runAsNonRoot: \$runAsNonRoot,
                                runAsUser: \$runAsUser,
                                automountServiceAccountToken: \$automount,
                                automount_reason: \$automount_reason
                        }")
                if [[ $ARO_MODE -eq 1 ]]; then
                  JSON_ITEM=$(echo "$JSON_ITEM" | jq -c --arg c "$CLOUD_ID" '. + {workload_identity_client_id: $c}')
                elif [[ $ROSA_MODE -eq 1 ]]; then
                  JSON_ITEM=$(echo "$JSON_ITEM" | jq -c --arg c "$CLOUD_ID" '. + {irsa_iam_role_arn: $c}')
                fi
                JSON_ITEMS+=("$JSON_ITEM")
        fi

    done < <(echo "$PODS_JSON" | jq -c '.items[]')

done <<< "$NS_LIST"

# Output JSON array if requested
if [[ "$OUTPUT_MODE" == "json" ]]; then
    printf '%s\n' "${JSON_ITEMS[@]}" | jq -s .
fi



# Duration footer (stderr for csv/json so machine output stays parseable)
END_TIME_NS=$(date +%s%N)
DURATION_NS=$((END_TIME_NS - START_TIME_NS))
DURATION_MS=$((DURATION_NS / 1000000))
MS=$((DURATION_MS % 1000))
SEC=$(( (DURATION_MS / 1000) % 60 ))
MIN=$(( (DURATION_MS / 60000) % 60 ))
HOUR=$(( DURATION_MS / 3600000 ))
if [[ "$OUTPUT_MODE" == "text" ]]; then
  printf "===== Caps/SCC Audit Complete =====\n"
  printf "Execution time: %02d:%02d:%02d.%03d (HH:MM:SS.mmm)\n" \
         "$HOUR" "$MIN" "$SEC" "$MS"
else
  printf "===== Caps/SCC Audit Complete =====\n" >&2
  printf "Execution time: %02d:%02d:%02d.%03d (HH:MM:SS.mmm)\n" \
         "$HOUR" "$MIN" "$SEC" "$MS" >&2
fi
