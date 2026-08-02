#!/bin/bash
# Azure Kubernetes Service (AKS): pod security audit (PSA labels + pod spec).
# Same intent as Vanilla / EKS / GKE *ContainerCapabilities.sh: namespace PSA labels, declared pod spec,
# and a cloud identity hint (here: Azure Workload Identity client-id on pod or ServiceAccount)—not Azure RBAC
# or admission-controller simulation. "Effective caps (pod estimate)" is NOT admission-accurate.
set -euo pipefail

# -----------------------------
# Flags / argument parsing
# -----------------------------
ONLY_USER_NS=0
OUTPUT_MODE="text"
DEBUG=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --only-user-ns) ONLY_USER_NS=1; shift ;;
    --output) OUTPUT_MODE="$2"; shift 2 ;;
    --debug) DEBUG=1; shift ;;
    *) echo "[ERROR] Unknown argument: $1"; exit 1 ;;
  esac
done

if [[ "$OUTPUT_MODE" != "text" && "$OUTPUT_MODE" != "csv" && "$OUTPUT_MODE" != "json" ]]; then
  echo "[ERROR] Invalid --output. Use: text | csv | json"
  exit 1
fi

# -----------------------------
# Requirements check
# -----------------------------
if ! command -v kubectl &> /dev/null; then
    echo "[ERROR] kubectl not found."
    exit 1
fi

if ! command -v jq &> /dev/null; then
    echo "[ERROR] jq not found."
    exit 1
fi

# Align with what the script actually needs (cluster reachability + list namespaces).
# Avoids false negatives from `auth can-i get pods` (namespace-scoped RBAC / wrong context NS).
if ! NS_JSON=$(kubectl get ns -o json 2>/dev/null); then
    echo "[ERROR] Cannot list namespaces or reach the cluster (kubectl get namespaces failed). Check kubeconfig and RBAC."
    exit 1
fi

# Informational: AKS-managed nodes typically carry kubernetes.azure.com/* labels.
if NODES_JSON=$(kubectl get nodes -o json 2>/dev/null); then
    if echo "$NODES_JSON" | jq -e '[.items[]?.metadata.labels["kubernetes.azure.com/cluster"]?] | any(. != null and . != "")' >/dev/null 2>&1; then
        echo "[INFO] AKS-style node labels detected (kubernetes.azure.com/cluster): cluster appears AKS-managed; admission may differ from this pod-spec-only estimate."
    fi
fi

echo "Running AKS security audit (PSA + pod-spec capabilities)..."
echo "[INFO] Pod-spec + PSA labels only (not live admission); Workload Identity column is an in-cluster hint, not full Azure IAM."
echo "[INFO] Escape-chain lines use the pod-spec effective-cap estimate and are listed separately from Status severity (not runtime verification)."
echo "[INFO] Known managed-plane pods (e.g. kube-proxy, azure-cni, cloud-node-manager) keep their severity but are tagged [known AKS platform component] — not suppressed."
[[ "$ONLY_USER_NS" -eq 1 ]] && echo "Filtering: only non-system namespaces (not openshift-* / kube-system|kube-public|kube-node-lease / gmp-* / calico-* / tigera-* / aks-command / azure-arc* / app-routing-system / ingress-appgw / kube-lineage / config-management-system / gatekeeper-system)."
echo ""

# -----------------------------
# Capability definitions (align BASELINE split with OpenShift-ContainerCapabilities.sh)
# -----------------------------
PRIVILEGED_CAPS=("SYS_ADMIN" "NET_ADMIN" "SYS_TIME" "SYS_MODULE" "SYS_RAWIO")
BASELINE_PRIVILEGED_CAPS=("CHOWN" "DAC_OVERRIDE")
BASELINE_CAPS=("FSETID" "FOWNER" "MKNOD" "NET_RAW" "SETGID" "SETUID" "SETFCAP" "SETPCAP" "NET_BIND_SERVICE" "KILL" "AUDIT_WRITE")
ALL_LINUX_CAPS=("${BASELINE_CAPS[@]}" "${BASELINE_PRIVILEGED_CAPS[@]}" "${PRIVILEGED_CAPS[@]}")

containsElement () {
  local match="$1"; shift
  for e in "$@"; do [[ "$e" == "$match" ]] && return 0; done
  return 1
}

cap_in_baseline_union () {
  local c="$1"
  containsElement "$c" "${BASELINE_CAPS[@]}" && return 0
  containsElement "$c" "${BASELINE_PRIVILEGED_CAPS[@]}"
}

# STATUS finding accumulator: parallel arrays, reset each pod. Rank 5=CRITICAL … 1=INFO.
escape_chain_push () {
    ESCAPE_CHAIN_MSGS+=("$1")
}

status_push () {
    STATUS_RANKS+=("$1")
    STATUS_MSGS+=("$2")
}

# Annotate known managed-plane workloads (CNI/proxy/node-manager). Never suppresses severity.
platform_workload_note () {
    local ns="$1" pod="$2" sa="$3"
    local note=""
    case "$sa" in
        kube-proxy|azure-cni|cloud-node-manager|csi-azuredisk-node-sa|csi-azurefile-node-sa|konnectivity-agent|azure-ip-masq-agent)
            note=" [known AKS platform component — expected on managed nodes]"
            ;;
    esac
    if [[ -z "$note" ]]; then
        case "$pod" in
            kube-proxy-*|azure-cni-*|cloud-node-manager-*|csi-azuredisk-node-*|csi-azurefile-node-*|konnectivity-agent-*|azure-ip-masq-agent-*)
                note=" [known AKS platform component — expected on managed nodes]"
                ;;
        esac
    fi
    if [[ -z "$note" ]] && { [[ "$ns" == "kube-system" || "$ns" == "kube-public" || "$ns" == "kube-node-lease" ]] || [[ "${IS_SYSTEM_NS:-0}" -eq 1 ]]; }; then
        note=" [platform namespace workload — vendor baseline unless unexpected]"
    fi
    printf '%s' "$note"
}

# Escape-chain detection: estimated effective caps + co-conditions (separate from Status severity).
# Uses EFFECTIVE_POD_ESTIMATE, HOST_NET, SHARE_PROC_NS, HOSTPATH_WRITABLE_PATHS.
check_escape_chains () {
    local cap path has_sys_admin=0 has_sys_ptrace=0 has_sys_module=0 has_net=0 has_mknod=0
    local cg_hits=() dev_hits=()

    for cap in "${EFFECTIVE_POD_ESTIMATE[@]}"; do
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
    if [[ "$has_net" -eq 1 && "$HOST_NET" == "true" ]]; then
        escape_chain_push "Escape chain: NET_RAW/NET_ADMIN + hostNetwork -> sniff/spoof node network -> reach metadata API"
    fi
    if [[ "$has_mknod" -eq 1 && ${#dev_hits[@]} -gt 0 ]]; then
        escape_chain_push "Escape chain: MKNOD + writable /dev hostPath ($(IFS=,; echo "${dev_hits[*]}")) -> create host device node -> raw disk read"
    fi
    if [[ "$has_sys_module" -eq 1 ]]; then
        escape_chain_push "Escape chain: SYS_MODULE -> load kernel module -> full host compromise"
    fi
}


# -----------------------------
# PSA labels on namespace
# -----------------------------
get_psa_labels() {
    local NS="$1"
    kubectl get ns "$NS" -o json | jq -r '
        [
            (.metadata.labels["pod-security.kubernetes.io/enforce"] // "none"),
            (.metadata.labels["pod-security.kubernetes.io/audit"] // "none"),
            (.metadata.labels["pod-security.kubernetes.io/warn"] // "none")
        ] | @tsv
    '
}

[[ "$OUTPUT_MODE" == "csv" ]] && echo "namespace,pod,serviceAccount,privileged_container,status,requested_caps_from_pod,dropped_caps_from_pod,effective_caps_pod_estimate,allowPrivilegeEscalation,hostPID,hostNetwork,hostIPC,runAsNonRoot,runAsUser,runAsGroup,fsGroup,supplementalGroups,volumeTypes,automountServiceAccountToken,escape_chains,workload_identity_client_id"

JSON_ITEMS=()

NS_LIST=$(echo "$NS_JSON" | jq -r '.items[].metadata.name')

while read -r NS; do
    [[ -z "$NS" ]] && continue

    IS_SYSTEM_NS=0
    # Use reserved kube-* names only — not kube-* prefix (lab fixtures use kube-rbac-polp-*).
    if [[ "$NS" == openshift-* ]] \
        || [[ "$NS" == "kube-system" || "$NS" == "kube-public" || "$NS" == "kube-node-lease" ]] \
        || [[ "$NS" == gmp-* ]] || [[ "$NS" == calico-* ]] || [[ "$NS" == tigera-* ]] \
        || [[ "$NS" == "aks-command" ]] || [[ "$NS" == azure-arc* ]] \
        || [[ "$NS" == "app-routing-system" ]] || [[ "$NS" == "ingress-appgw" ]] \
        || [[ "$NS" == "kube-lineage" ]] \
        || [[ "$NS" == "config-management-system" ]] || [[ "$NS" == "gatekeeper-system" ]]; then
        IS_SYSTEM_NS=1
    fi
    [[ "$ONLY_USER_NS" -eq 1 && "$IS_SYSTEM_NS" -eq 1 ]] && continue

    IFS=$'\t' read -r PSA_ENFORCE PSA_AUDIT PSA_WARN < <(get_psa_labels "$NS")

    if [[ "$OUTPUT_MODE" == "text" ]]; then
        echo "---------------------------------------------------------"
        echo "--- Namespace: $NS ---"
        echo "    PSA enforce=$PSA_ENFORCE  audit=$PSA_AUDIT  warn=$PSA_WARN"
        echo "---------------------------------------------------------"
        echo ""
    fi

    PODS=$(kubectl get pods -n "$NS" -o json | jq -r '.items[].metadata.name')

    if [[ -z "$PODS" ]]; then
        [[ "$OUTPUT_MODE" == "text" ]] && echo "  [INFO] No pods in namespace: $NS" && echo ""
        continue
    fi

    while read -r POD; do
        [[ -z "$POD" ]] && continue
        POD_JSON=$(kubectl get pod "$POD" -n "$NS" -o json)


        SHARE_PROC_NS=$(echo "$POD_JSON" | jq -r '.spec.shareProcessNamespace // false | tostring | ascii_downcase')

        # Writable hostPath mount paths (volume hostPath.path joined to container mounts with readOnly!=true)
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

        SA_NAME=$(echo "$POD_JSON" | jq -r '.spec.serviceAccountName // "default"')

        WI_CID=$(echo "$POD_JSON" | jq -r '.metadata.annotations["azure.workload.identity/client-id"] // empty')
        if [[ -z "$WI_CID" ]]; then
            _sa_json=""
            _sa_json=$(kubectl get serviceaccount "$SA_NAME" -n "$NS" -o json 2>/dev/null) || _sa_json=""
            if [[ -n "$_sa_json" ]]; then
                WI_CID=$(echo "$_sa_json" | jq -r '
                    .metadata.annotations["azure.workload.identity/client-id"]
                    // .metadata.annotations["azure.workload.identity/service-account-client-id"]
                    // empty
                ')
            fi
        fi
        [[ -z "$WI_CID" ]] && WI_CID="none"

        PRIV=$(echo "$POD_JSON" | jq -r '
            [(.spec.initContainers[]?.securityContext.privileged // false),
             (.spec.containers[]?.securityContext.privileged // false),
             (.spec.ephemeralContainers[]?.securityContext.privileged // false)]
            | any(. == true)
        ')

        # Parentheses required: jq binds | tighter than , (see Vanilla-ContainerCapabilities.sh).
        # API default when unset/null is true (only explicit false disables escalation).
        ESC=$(echo "$POD_JSON" | jq -r '
            [
                ((.spec.initContainers // [])[] | ((.securityContext // {}) | .allowPrivilegeEscalation) != false),
                ((.spec.containers // [])[] | ((.securityContext // {}) | .allowPrivilegeEscalation) != false),
                ((.spec.ephemeralContainers // [])[] | ((.securityContext // {}) | .allowPrivilegeEscalation) != false)
            ]
            | any(. == true)
        ')

        HOST_NET=$(echo "$POD_JSON" | jq -r '.spec.hostNetwork // false | tostring | ascii_downcase')

        HOST_PID=$(echo "$POD_JSON" | jq -r '
            [(.spec.initContainers[]?.securityContext.hostPID // false),
             (.spec.containers[]?.securityContext.hostPID // false),
             (.spec.ephemeralContainers[]?.securityContext.hostPID // false),
             (.spec.hostPID // false)]
            | map(if . == null then false else . end)
            | any(. == true)
            | tostring | ascii_downcase
        ')

        HOST_IPC=$(echo "$POD_JSON" | jq -r '
            [(.spec.initContainers[]?.securityContext.hostIPC // false),
             (.spec.containers[]?.securityContext.hostIPC // false),
             (.spec.ephemeralContainers[]?.securityContext.hostIPC // false),
             (.spec.hostIPC // false)]
            | map(if . == null then false else . end)
            | any(. == true)
            | tostring | ascii_downcase
        ')

        RUN_AS_USER=$(echo "$POD_JSON" | jq -r '
            [.spec.securityContext.runAsUser,
             (.spec.initContainers[]?.securityContext.runAsUser),
             (.spec.containers[]?.securityContext.runAsUser),
             (.spec.ephemeralContainers[]?.securityContext.runAsUser)]
            | map(select(. != null))
            | unique
            | join(",")
        ')
        [[ -z "$RUN_AS_USER" ]] && RUN_AS_USER="unset"

        HAS_ROOT_UID=$(echo "$POD_JSON" | jq -r '
            [
                .spec.securityContext.runAsUser,
                (.spec.initContainers[]?.securityContext.runAsUser),
                (.spec.containers[]?.securityContext.runAsUser),
                (.spec.ephemeralContainers[]?.securityContext.runAsUser)
            ]
            | map(select(. != null))
            | any(. == 0 or . == "0")
        ')

        POD_RUNASNONROOT=$(echo "$POD_JSON" | jq -r '.spec.securityContext.runAsNonRoot // empty')
        [[ "$POD_RUNASNONROOT" == "" ]] && POD_RUNASNONROOT="unset"
        mapfile -t CONTAINER_RUNASNONROOT_VALUES < <(echo "$POD_JSON" | jq -r '
            [.spec.initContainers[]?.securityContext.runAsNonRoot,
             .spec.containers[]?.securityContext.runAsNonRoot,
             .spec.ephemeralContainers[]?.securityContext.runAsNonRoot]
            | map(select(. != null))
            | .[]
        ')
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

        POD_RUNASGROUP=$(echo "$POD_JSON" | jq -r '.spec.securityContext.runAsGroup // empty')
        [[ -z "$POD_RUNASGROUP" ]] && POD_RUNASGROUP="unset"
        mapfile -t CONTAINER_RUNASGROUP_VALUES < <(echo "$POD_JSON" | jq -r '
            [.spec.initContainers[]?.securityContext.runAsGroup,
             .spec.containers[]?.securityContext.runAsGroup,
             .spec.ephemeralContainers[]?.securityContext.runAsGroup]
            | map(select(. != null))
            | .[]
        ')
        RUN_AS_GROUP_DISPLAY=""
        if [[ "$POD_RUNASGROUP" != "unset" ]]; then
            RUN_AS_GROUP_DISPLAY="pod:$POD_RUNASGROUP"
        fi
        if [[ ${#CONTAINER_RUNASGROUP_VALUES[@]} -gt 0 ]]; then
            CONTAINER_UNIQUE=$(printf "%s\n" "${CONTAINER_RUNASGROUP_VALUES[@]}" | sort -u | paste -sd "," -)
            [[ -n "$RUN_AS_GROUP_DISPLAY" ]] && RUN_AS_GROUP_DISPLAY+=", "
            RUN_AS_GROUP_DISPLAY+="containers:$CONTAINER_UNIQUE"
        fi
        [[ -z "$RUN_AS_GROUP_DISPLAY" ]] && RUN_AS_GROUP_DISPLAY="None"

        FSGROUP=$(echo "$POD_JSON" | jq -r '.spec.securityContext.fsGroup // empty')
        [[ -z "$FSGROUP" ]] && FSGROUP="unset"

        SUPP_GROUPS=$(echo "$POD_JSON" | jq -r '
            .spec.securityContext.supplementalGroups // [] | map(tostring) | join(",")
        ')
        [[ -z "$SUPP_GROUPS" ]] && SUPP_GROUPS="none"

        CAPS=$(echo "$POD_JSON" | jq -r '
            [(.spec.initContainers[]?.securityContext.capabilities.add // []),
             (.spec.containers[]?.securityContext.capabilities.add // []),
             (.spec.ephemeralContainers[]?.securityContext.capabilities.add // [])]
            | flatten | unique | .[]? | ascii_upcase
        ' | grep -v '^$' || true)

        DROPPED_CAPS=$(echo "$POD_JSON" | jq -r '
            [(.spec.initContainers[]?.securityContext.capabilities.drop // []),
             (.spec.containers[]?.securityContext.capabilities.drop // []),
             (.spec.ephemeralContainers[]?.securityContext.capabilities.drop // [])]
            | flatten | unique | .[]? | ascii_upcase
        ' | grep -v '^$' || true)

        if [[ -z "$DROPPED_CAPS" ]]; then
            DROPPED_CAPS_STR="None"
            DROPPED_CAPS_ARRAY=()
        else
            mapfile -t DROPPED_CAPS_ARRAY <<< "$DROPPED_CAPS"
            DROPPED_CAPS_STR="${DROPPED_CAPS_ARRAY[*]}"
        fi

        DROP_ALL=0
        for d in "${DROPPED_CAPS_ARRAY[@]}"; do
            ud=$(printf '%s' "$d" | tr '[:lower:]' '[:upper:]')
            [[ "$ud" == "ALL" ]] && DROP_ALL=1 && break
        done

        REQUESTED_CAPS_ARRAY=()
        if [[ -n "${CAPS:-}" ]]; then
            mapfile -t REQUESTED_CAPS_ARRAY <<< "$CAPS"
        fi
        if [[ ${#REQUESTED_CAPS_ARRAY[@]} -eq 0 ]]; then
            REQUESTED_CAPS_STR="None"
        else
            REQUESTED_CAPS_STR="${REQUESTED_CAPS_ARRAY[*]}"
        fi

        # Volume source types (audit only)
        VOL_TYPES=$(echo "$POD_JSON" | jq -r '
            .spec.volumes // [] |
            .[] |
            to_entries |
            .[] |
            select(.value | type == "object") |
            .key
        ' | sort -u | grep -v '^$' || true)
        if [[ -z "$VOL_TYPES" ]]; then
            VOLUME_TYPES_DISPLAY="None"
        else
            VOLUME_TYPES_DISPLAY=$(echo "$VOL_TYPES" | paste -sd "," -)
        fi

        # automountServiceAccountToken (display only; no SCC linkage)
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

        mapfile -t CONTAINER_AUTOMOUNT_VALUES < <(echo "$POD_JSON" | jq -r '
            ((.spec.initContainers // [])[] | .automountServiceAccountToken // empty),
            ((.spec.containers // [])[] | .automountServiceAccountToken // empty),
            ((.spec.ephemeralContainers // [])[] | .automountServiceAccountToken // empty)
        ')
        mapfile -t CONTAINER_NAMES < <(echo "$POD_JSON" | jq -r '
            ((.spec.initContainers // [])[] | .name),
            ((.spec.containers // [])[] | .name),
            ((.spec.ephemeralContainers // [])[] | .name)
        ')

        AUTOMOUNT_TRUE=$POD_AUTOMOUNT_LOGIC
        AUTOMOUNT_REASON="$POD_AUTOMOUNT_REASON"
        ALL_CONTAINERS_FALSE=1
        LAST_FALSE_CONTAINER=""
        for i in "${!CONTAINER_AUTOMOUNT_VALUES[@]}"; do
            val="${CONTAINER_AUTOMOUNT_VALUES[$i]}"
            cname="${CONTAINER_NAMES[$i]:-unknown}"
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
        if [[ $AUTOMOUNT_TRUE -eq 1 ]]; then
            AUTOMOUNT_DISPLAY="true ($AUTOMOUNT_REASON)"
        else
            AUTOMOUNT_DISPLAY="false ($AUTOMOUNT_REASON)"
        fi

        # Pod-only effective caps estimate (not admission-accurate)
        EFFECTIVE_CAPS_STR=""
        if [[ "$PRIV" == "true" ]]; then
            EFFECTIVE_POD_ESTIMATE=("${ALL_LINUX_CAPS[@]}")
            EFFECTIVE_CAPS_STR="(pod estimate) all caps if privileged — ${#EFFECTIVE_POD_ESTIMATE[@]} names; see PRIVILEGED_CAPS/BASELINE lists in script"
        elif [[ "$DROP_ALL" -eq 1 ]]; then
            # drop ALL clears baseline; only explicit .capabilities.add remain
            EFFECTIVE_POD_ESTIMATE=("${REQUESTED_CAPS_ARRAY[@]}")
            if [[ ${#EFFECTIVE_POD_ESTIMATE[@]} -eq 0 ]]; then
                EFFECTIVE_CAPS_STR="(pod estimate) DROP ALL in pod spec — no capabilities remaining from this estimate"
            else
                EFFECTIVE_CAPS_STR="(pod estimate, not admission-accurate) ${EFFECTIVE_POD_ESTIMATE[*]}"
            fi
        else
            EFFECTIVE_POD_ESTIMATE=("${BASELINE_CAPS[@]}" "${BASELINE_PRIVILEGED_CAPS[@]}")
            EFFECTIVE_POD_ESTIMATE+=("${REQUESTED_CAPS_ARRAY[@]}")
            ALL_SPECIFIC_DROPS=()
            for d in "${DROPPED_CAPS_ARRAY[@]}"; do
                ud=$(printf '%s' "$d" | tr '[:lower:]' '[:upper:]')
                [[ "$ud" != "ALL" ]] && ALL_SPECIFIC_DROPS+=("$d")
            done
            TMP_E=()
            for cap in "${EFFECTIVE_POD_ESTIMATE[@]}"; do
                skip=0
                for drop in "${ALL_SPECIFIC_DROPS[@]}"; do
                    [[ "$cap" == "$drop" ]] && skip=1 && break
                done
                [[ $skip -eq 0 ]] && TMP_E+=("$cap")
            done
            mapfile -t EFFECTIVE_POD_ESTIMATE < <(printf "%s\n" "${TMP_E[@]}" | awk '!seen[$0]++')
            EFFECTIVE_CAPS_STR="(pod estimate, not admission-accurate) ${EFFECTIVE_POD_ESTIMATE[*]}"
        fi

        ESCAPE_CHAIN_MSGS=()
        check_escape_chains

        # Status: worst severity headline + " — also: " for other findings at the same rank only.
        STATUS_RANKS=()
        STATUS_MSGS=()

        [[ "$PRIV" == "true" ]] && status_push 5 "CRITICAL: privileged container"
        [[ "$HAS_ROOT_UID" == "true" ]] && status_push 5 "CRITICAL: running as root (runAsUser 0 in pod spec)"
        [[ "$ESC" == "true" ]] && status_push 4 "HIGH: privilege escalation allowed"
        if [[ "$HOST_NET" == "true" || "$HOST_PID" == "true" || "$HOST_IPC" == "true" ]]; then
            HOST_FLAG_PARTS=()
            [[ "$HOST_NET" == "true" ]] && HOST_FLAG_PARTS+=("hostNetwork")
            [[ "$HOST_PID" == "true" ]] && HOST_FLAG_PARTS+=("hostPID")
            [[ "$HOST_IPC" == "true" ]] && HOST_FLAG_PARTS+=("hostIPC")
            HOST_FLAG_JOIN=$(IFS=,; echo "${HOST_FLAG_PARTS[*]}")
            status_push 4 "HIGH: host access enabled ($HOST_FLAG_JOIN)"
        fi
        [[ "$DROP_ALL" -eq 1 && "$PRIV" != "true" ]] && status_push 1 "INFO: capabilities.drop includes ALL (non-privileged pod spec)"

        PRIV_REQ_CAPS=()
        NONBASE_REQ_CAPS=()
        for cap in "${REQUESTED_CAPS_ARRAY[@]}"; do
            [[ -z "$cap" ]] && continue
            if containsElement "$cap" "${PRIVILEGED_CAPS[@]}"; then
                PRIV_REQ_CAPS+=("$cap")
            elif ! cap_in_baseline_union "$cap"; then
                NONBASE_REQ_CAPS+=("$cap")
            fi
        done
        if [[ ${#PRIV_REQ_CAPS[@]} -gt 0 ]]; then
            PRIV_CAPS_JOIN=$(printf '%s\n' "${PRIV_REQ_CAPS[@]}" | sort -u | paste -sd "," -)
            status_push 3 "WARNING: privileged capability ($PRIV_CAPS_JOIN)"
        fi
        if [[ ${#NONBASE_REQ_CAPS[@]} -gt 0 ]]; then
            NONBASE_JOIN=$(printf '%s\n' "${NONBASE_REQ_CAPS[@]}" | sort -u | paste -sd "," -)
            status_push 2 "MEDIUM: non-baseline capability ($NONBASE_JOIN)"
        fi

        FINDING_COUNT=${#STATUS_RANKS[@]}
        if [[ "$FINDING_COUNT" -eq 0 ]]; then
            STATUS="OK"
        else
            max_r=0
            for r in "${STATUS_RANKS[@]}"; do
                [[ "$r" -gt "$max_r" ]] && max_r=$r
            done
            same_msgs=()
            for i in "${!STATUS_RANKS[@]}"; do
                [[ "${STATUS_RANKS[$i]}" -eq "$max_r" ]] && same_msgs+=("${STATUS_MSGS[$i]}")
            done
            primary="${same_msgs[0]}"
            if [[ ${#same_msgs[@]} -eq 1 ]]; then
                STATUS="$primary"
            else
                also_s=$(printf '%s\n' "${same_msgs[@]:1}" | paste -sd "; " -)
                STATUS="$primary — also: $also_s"
            fi
        fi

        if [[ "$PSA_ENFORCE" == "restricted" && "$FINDING_COUNT" -gt 0 ]]; then
            STATUS="$STATUS (violates restricted PSA enforce profile)"
        fi

        PLATFORM_NOTE=$(platform_workload_note "$NS" "$POD" "$SA_NAME")
        if [[ -n "$PLATFORM_NOTE" && "$STATUS" != "OK" ]]; then
            STATUS="${STATUS}${PLATFORM_NOTE}"
            for _i in "${!ESCAPE_CHAIN_MSGS[@]}"; do
                ESCAPE_CHAIN_MSGS[_i]="${ESCAPE_CHAIN_MSGS[_i]}${PLATFORM_NOTE}"
            done
        fi

        [[ "$DEBUG" -eq 1 ]] && echo "DEBUG pod=$NS/$POD PRIV=$PRIV DROP_ALL=$DROP_ALL FINDINGS=$FINDING_COUNT STATUS=$STATUS"

        PRIV_DISPLAY=$([[ "$PRIV" == "true" ]] && echo "true" || echo "false")
        ESC_DISPLAY=$([[ "$ESC" == "true" ]] && echo "true" || echo "false")

        if [[ ${#ESCAPE_CHAIN_MSGS[@]} -eq 0 ]]; then
            ESCAPE_CHAINS_CSV=""
            ESCAPE_CHAINS_JSON='[]'
        else
            ESCAPE_CHAINS_CSV=$(printf '%s; ' "${ESCAPE_CHAIN_MSGS[@]}" | sed 's/; $//')
            ESCAPE_CHAINS_JSON=$(printf '%s\n' "${ESCAPE_CHAIN_MSGS[@]}" | jq -R . | jq -s .)
        fi

        if [[ "$OUTPUT_MODE" == "text" ]]; then
            echo "  Pod: $POD"
            echo "    serviceAccount: $SA_NAME"
            echo "    Privileged: $PRIV"
            echo "    AllowPrivilegeEscalation: $ESC"
            echo "    hostNetwork: $HOST_NET"
            echo "    hostPID: $HOST_PID"
            echo "    hostIPC: $HOST_IPC"
            echo "    runAsNonRoot: $RUN_AS_NONROOT_DISPLAY"
            echo "    runAsUser: $RUN_AS_USER"
            echo "    runAsGroup: $RUN_AS_GROUP_DISPLAY"
            echo "    fsGroup: $FSGROUP"
            echo "    supplementalGroups: $SUPP_GROUPS"
            echo "    volumeTypes: $VOLUME_TYPES_DISPLAY"
            echo "    automountServiceAccountToken: $AUTOMOUNT_DISPLAY"
            echo "    workloadIdentityClientId: $WI_CID"
            echo "    Capabilities (add): ${CAPS:-None}"
            echo "    Capabilities (drop): $DROPPED_CAPS_STR"
            echo "    Effective caps: $EFFECTIVE_CAPS_STR"
            echo "    Status: $STATUS"
            for _ec in "${ESCAPE_CHAIN_MSGS[@]}"; do
                echo "    $_ec"
            done
            echo ""
        elif [[ "$OUTPUT_MODE" == "csv" ]]; then
            EFFECTIVE_ESC=${EFFECTIVE_CAPS_STR//\"/\"\"}
            ESCAPE_ESC=${ESCAPE_CHAINS_CSV//\"/\"\"}
            echo "\"${NS//\"/\"\"}\",\"${POD//\"/\"\"}\",\"${SA_NAME//\"/\"\"}\",\"$PRIV_DISPLAY\",\"${STATUS//\"/\"\"}\",\"${REQUESTED_CAPS_STR//\"/\"\"}\",\"${DROPPED_CAPS_STR//\"/\"\"}\",\"${EFFECTIVE_ESC}\",\"$ESC_DISPLAY\",\"$HOST_PID\",\"$HOST_NET\",\"$HOST_IPC\",\"${RUN_AS_NONROOT_DISPLAY//\"/\"\"}\",\"${RUN_AS_USER//\"/\"\"}\",\"${RUN_AS_GROUP_DISPLAY//\"/\"\"}\",\"$FSGROUP\",\"${SUPP_GROUPS//\"/\"\"}\",\"${VOLUME_TYPES_DISPLAY//\"/\"\"}\",\"${AUTOMOUNT_DISPLAY//\"/\"\"}\",\"${ESCAPE_ESC}\",\"${WI_CID//\"/\"\"}\""
        elif [[ "$OUTPUT_MODE" == "json" ]]; then
            if [[ ${#EFFECTIVE_POD_ESTIMATE[@]} -eq 0 ]]; then
                EFFECTIVE_JSON='[]'
            else
                EFFECTIVE_JSON=$(printf '%s\n' "${EFFECTIVE_POD_ESTIMATE[@]}" | jq -R . | jq -s .)
            fi
            JSON_ITEM=$(jq -c -n \
                --arg ns "$NS" \
                --arg pod "$POD" \
                --arg sa "$SA_NAME" \
                --arg priv "$PRIV_DISPLAY" \
                --arg status "$STATUS" \
                --arg req "$REQUESTED_CAPS_STR" \
                --arg drop "$DROPPED_CAPS_STR" \
                --arg esc "$ESC_DISPLAY" \
                --arg hpid "$HOST_PID" \
                --arg hnet "$HOST_NET" \
                --arg hipc "$HOST_IPC" \
                --arg rarn "$RUN_AS_NONROOT_DISPLAY" \
                --arg rau "$RUN_AS_USER" \
                --arg rag "$RUN_AS_GROUP_DISPLAY" \
                --arg fsg "$FSGROUP" \
                --arg sg "$SUPP_GROUPS" \
                --arg vol "$VOLUME_TYPES_DISPLAY" \
                --arg am "$AUTOMOUNT_DISPLAY" \
                --arg wi "$WI_CID" \
                --arg psa_e "$PSA_ENFORCE" \
                --arg psa_a "$PSA_AUDIT" \
                --arg psa_w "$PSA_WARN" \
                --arg eff_note "pod spec only, not admission-accurate" \
                --argjson effective "$EFFECTIVE_JSON" \
                --argjson escape_chains "$ESCAPE_CHAINS_JSON" \
                "{
                    namespace: \$ns,
                    pod: \$pod,
                    serviceAccount: \$sa,
                    privileged: (\$priv == \"true\"),
                    status: \$status,
                    requested_caps_from_pod: \$req,
                    dropped_caps_from_pod: \$drop,
                    effective_caps_pod_estimate: \$effective,
                    effective_caps_note: \$eff_note,
                    escape_chains: \$escape_chains,
                    allowPrivilegeEscalation: (\$esc == \"true\"),
                    hostPID: \$hpid,
                    hostNetwork: \$hnet,
                    hostIPC: \$hipc,
                    runAsNonRoot: \$rarn,
                    runAsUser: \$rau,
                    runAsGroup: \$rag,
                    fsGroup: \$fsg,
                    supplementalGroups: \$sg,
                    volumeTypes: \$vol,
                    automountServiceAccountToken: \$am,
                    workload_identity_client_id: \$wi,
                    psa_enforce: \$psa_e,
                    psa_audit: \$psa_a,
                    psa_warn: \$psa_w
                }")
            JSON_ITEMS+=("$JSON_ITEM")
        fi

    done <<< "$PODS"

done <<< "$NS_LIST"

if [[ "$OUTPUT_MODE" == "json" ]]; then
    printf '%s\n' "${JSON_ITEMS[@]}" | jq -s .
fi
