#!/bin/bash
set -eu

# --- Configuration ---
HTTPS_CHECK_PORTS=("2379" "10250" "10257" "10259")
KUBELET_HTTP_RO_PORT="10255"
TIMEOUT=3
CONNECT_TIMEOUT=3
OUTPUT_MODE="human"
NAMESPACE_FILTER_RAW=""
MAX_PODS=0
TRUNCATE_LIMIT=120
CHECK_IMDS_CREDS=0
# --- End Configuration ---

usage() {
    cat <<'EOF'
Usage:
  ControlPlane_WorkerNodes_fromAllPods.sh [options]

Options:
  --namespaces ns1,ns2      Only test pods in listed namespaces
  --output human|jsonl      Output mode (default: human)
  --timeout N               Overall timeout seconds for probe commands (default: 3)
  --connect-timeout N       curl connect-timeout seconds (default: 3)
  --max-pods N              Max number of running pods to test (0 = all, default: 0)
  --check-imds-creds        Opt-in: from each probed pod, attempt cloud IMDS
                            credential retrieval (AWS/GCP/Azure). Secrets are
                            redacted; only masked identity prefixes are printed.
  -h, --help                Show this help
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --namespaces) NAMESPACE_FILTER_RAW="${2:-}"; shift 2 ;;
        --output) OUTPUT_MODE="${2:-}"; shift 2 ;;
        --timeout) TIMEOUT="${2:-}"; shift 2 ;;
        --connect-timeout) CONNECT_TIMEOUT="${2:-}"; shift 2 ;;
        --max-pods) MAX_PODS="${2:-}"; shift 2 ;;
        --check-imds-creds) CHECK_IMDS_CREDS=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Error: Unknown option '$1'"; usage; exit 2 ;;
    esac
done

if [[ ! "$OUTPUT_MODE" =~ ^(human|jsonl)$ ]]; then
    echo "Error: --output must be human or jsonl."
    exit 2
fi
if [[ ! "$TIMEOUT" =~ ^[0-9]+$ ]] || [[ ! "$CONNECT_TIMEOUT" =~ ^[0-9]+$ ]] || [[ ! "$MAX_PODS" =~ ^[0-9]+$ ]]; then
    echo "Error: --timeout, --connect-timeout, and --max-pods must be integers."
    exit 2
fi

if command -v oc >/dev/null 2>&1; then
    KCLI="oc"
elif command -v kubectl >/dev/null 2>&1; then
    KCLI="kubectl"
else
    echo "Error: Neither 'oc' nor 'kubectl' is available on PATH."
    exit 1
fi

if ! command -v timeout >/dev/null 2>&1; then
    echo "Error: 'timeout' is required on the host running this script."
    exit 1
fi
if ! command -v jq >/dev/null 2>&1; then
    echo "Error: 'jq' is required on the host running this script."
    exit 1
fi

declare -A STATUS_COUNTS
declare -A PORT_STATUS_COUNTS
TOTAL_PODS_CONSIDERED=0
TOTAL_PODS_TESTED=0
TOTAL_PODS_SKIPPED=0
TOTAL_PODS_SAMPLED_OUT=0

contains_exact_ip() {
    local needle="${1:-}"
    shift
    local item=""
    for item in "$@"; do
        if [[ "$item" == "$needle" ]]; then
            return 0
        fi
    done
    return 1
}

classify_connectivity_code() {
    local rc="${1:-}"
    case "$rc" in
        6|7|28|124)
            echo "BLOCKED_OR_UNREACHABLE"
            ;;
        51|58|60)
            echo "DENIED_WITHOUT_CREDS"
            ;;
        0)
            echo "REACHABLE"
            ;;
        *)
            echo "TEST_ERROR"
            ;;
    esac
}

run_exec_probe() {
    local src_namespace="${1:-}" src_name="${2:-}" cmd="${3:-}"
    set +e
    "$KCLI" exec -n "$src_namespace" "$src_name" -- sh -c "$cmd" >/dev/null 2>&1
    local rc=$?
    set -e
    echo "$rc"
}

resolve_node_role() {
    local ip="${1:-}"
    if contains_exact_ip "$ip" "${CP_IPS_ARR[@]}"; then
        echo "CP"
    else
        echo "Worker"
    fi
}

truncate_value() {
    local val="${1:-}"
    if [[ ${#val} -le $TRUNCATE_LIMIT ]]; then
        printf "%s" "$val"
    else
        printf "%s...(+truncated)" "${val:0:$TRUNCATE_LIMIT}"
    fi
}

emit_finding() {
    local src_namespace="${1:-}" src_name="${2:-}" host_network="${3:-}" service_account="${4:-}" netpol_count="${5:-}" netpol_match="${6:-}" policy_engine="${7:-}" plugin_policy_count="${8:-}" plugin_policy_refs="${9:-}" dest_role="${10:-}" ip="${11:-}" port="${12:-}" status="${13:-}" details="${14:-}"
    local risk="false"
    if [[ "$status" == "EXPOSED" || "$status" == "EXPOSED_CREDS" ]]; then
        risk="true"
    fi

    STATUS_COUNTS["$status"]=$(( ${STATUS_COUNTS["$status"]:-0} + 1 ))
    if [[ "$port" != "-" ]]; then
        PORT_STATUS_COUNTS["$port|$status"]=$(( ${PORT_STATUS_COUNTS["$port|$status"]:-0} + 1 ))
    fi

    if [[ "$OUTPUT_MODE" == "jsonl" ]]; then
        jq -cn \
          --arg src_namespace "$src_namespace" \
          --arg src_pod "$src_name" \
          --arg host_network "$host_network" \
          --arg service_account "$service_account" \
          --arg netpol_ns_count "$netpol_count" \
          --arg netpol_match "$netpol_match" \
          --arg policy_engine "$policy_engine" \
          --arg plugin_policy_count "$plugin_policy_count" \
          --arg plugin_policy_refs "$plugin_policy_refs" \
          --arg dest_role "$dest_role" \
          --arg dest_ip "$ip" \
          --arg port "$port" \
          --arg status "$status" \
          --arg details "$details" \
          --arg risk "$risk" \
          '{src_namespace:$src_namespace,src_pod:$src_pod,hostNetwork:$host_network,serviceAccount:$service_account,netpol_ns_count:$netpol_ns_count,netpol_match:$netpol_match,policy_engine:$policy_engine,plugin_policy_count:$plugin_policy_count,plugin_policy_refs:$plugin_policy_refs,dest_role:$dest_role,dest_ip:$dest_ip,port:$port,status:$status,details:$details,risk:($risk=="true")}'
    else
        if [[ "$status" == "EXPOSED" || "$status" == "EXPOSED_CREDS" ]]; then
            echo "=========ALERT========="
        fi
        printf "%s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s\n" \
            "$src_namespace" "$src_name" "$host_network" "$service_account" "$netpol_count" "$(truncate_value "$netpol_match")" \
            "$policy_engine" "$plugin_policy_count" "$(truncate_value "$plugin_policy_refs")" \
            "$dest_role" "$ip" "$port" "$status" "$details"
        if [[ "$status" == "EXPOSED" || "$status" == "EXPOSED_CREDS" ]]; then
            echo "=========ALERT========="
        fi
    fi
}

print_result() {
    local src_namespace="${1:-}" src_name="${2:-}" host_network="${3:-}" service_account="${4:-}" netpol_count="${5:-}" netpol_match="${6:-}" dest_role="${7:-}" ip="${8:-}" port="${9:-}" status="${10:-}" details="${11:-}"
    emit_finding "$src_namespace" "$src_name" "$host_network" "$service_account" "$netpol_count" "$netpol_match" "${POD_POLICY_ENGINE:-k8s-native}" "${POD_PLUGIN_POLICY_COUNT:-0}" "${POD_PLUGIN_POLICY_REFS:--}" "$dest_role" "$ip" "$port" "$status" "$details"
}

test_connection_simple() {
    local src_namespace="${1:-}" src_name="${2:-}" host_network="${3:-}" service_account="${4:-}" netpol_count="${5:-}" netpol_match="${6:-}" dest_role="${7:-}" ip="${8:-}" port="${9:-}"
    local probe_cmd="command -v curl >/dev/null 2>&1 || exit 127; timeout $TIMEOUT curl -s -o /dev/null --connect-timeout $CONNECT_TIMEOUT -m $TIMEOUT http://$ip:$port"
    local rc
    rc=$(run_exec_probe "$src_namespace" "$src_name" "$probe_cmd")

    case "$(classify_connectivity_code "$rc")" in
        REACHABLE)
            print_result "$src_namespace" "$src_name" "$host_network" "$service_account" "$netpol_count" "$netpol_match" "$dest_role" "$ip" "$port" "EXPOSED" "Port responded without auth (curl rc=$rc)."
            ;;
        BLOCKED_OR_UNREACHABLE)
            print_result "$src_namespace" "$src_name" "$host_network" "$service_account" "$netpol_count" "$netpol_match" "$dest_role" "$ip" "$port" "BLOCKED_OR_UNREACHABLE" "Connection blocked/unreachable (curl/timeout rc=$rc)."
            ;;
        *)
            print_result "$src_namespace" "$src_name" "$host_network" "$service_account" "$netpol_count" "$netpol_match" "$dest_role" "$ip" "$port" "TEST_ERROR" "Probe failed (curl/exec rc=$rc)."
            ;;
    esac
}

# Opt-in IMDS credential retrieval (secrets redacted). Port 80 on 169.254.169.254.
# Emits EXPOSED_CREDS / NOT_RETRIEVABLE / TEST_ERROR via emit_finding.
test_imds_creds() {
    local src_namespace="${1:-}" src_name="${2:-}" host_network="${3:-}" service_account="${4:-}" netpol_count="${5:-}" netpol_match="${6:-}"
    local imds_ip="169.254.169.254"
    local imds_port="80"
    local dest_role="IMDS"

    # Reachability first (TCP/HTTP to link-local metadata).
    local reach_cmd="command -v curl >/dev/null 2>&1 || exit 127; timeout $TIMEOUT curl -s -o /dev/null --connect-timeout $CONNECT_TIMEOUT -m $TIMEOUT http://${imds_ip}/"
    local reach_rc
    reach_rc=$(run_exec_probe "$src_namespace" "$src_name" "$reach_cmd")
    case "$(classify_connectivity_code "$reach_rc")" in
        BLOCKED_OR_UNREACHABLE)
            print_result "$src_namespace" "$src_name" "$host_network" "$service_account" "$netpol_count" "$netpol_match" "$dest_role" "$imds_ip" "$imds_port" "NOT_RETRIEVABLE" "IMDS endpoint blocked/unreachable (rc=$reach_rc)."
            return
            ;;
        TEST_ERROR)
            # Continue — some clouds return non-zero on bare / but still serve metadata paths.
            ;;
    esac

    # In-pod probe: confirm credential material is obtainable; redact secrets.
    # Markers: __AWS_OK__ role=... AccessKeyId=ASA****REDACTED
    #          __GCP_OK__ (token withheld)
    #          __AZ_OK__ (token withheld)
    local probe_script
    probe_script=$(cat <<'EOS'
URL_AWS_TOKEN="http://169.254.169.254/latest/api/token"
URL_AWS="http://169.254.169.254/latest/meta-data/iam/security-credentials/"
URL_GCP="http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token"
URL_AZ="http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
found=""
if ! command -v curl >/dev/null 2>&1; then
  echo "__NO_HTTP_TOOL__"
  exit 0
fi
T=$(curl -s -m 3 -X PUT "$URL_AWS_TOKEN" -H "X-aws-ec2-metadata-token-ttl-seconds: 60" 2>/dev/null || true)
if [ -n "$T" ]; then
  ROLE=$(curl -s -m 3 -H "X-aws-ec2-metadata-token: $T" "$URL_AWS" 2>/dev/null | head -n1 | tr -d '\r')
  if [ -n "$ROLE" ]; then
    CREDS=$(curl -s -m 3 -H "X-aws-ec2-metadata-token: $T" "${URL_AWS}${ROLE}" 2>/dev/null || true)
    AKID=$(printf '%s' "$CREDS" | sed -n 's/.*"AccessKeyId"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1)
    if [ -n "$AKID" ]; then
      PREFIX=$(printf '%s' "$AKID" | cut -c1-4)
      echo "__AWS_OK__ role=${ROLE} AccessKeyId=${PREFIX}****REDACTED"
      found=1
    elif printf '%s' "$CREDS" | grep -q AccessKeyId; then
      echo "__AWS_OK__ role=${ROLE} AccessKeyId=****REDACTED"
      found=1
    fi
  fi
fi
GCP=$(curl -s -m 3 -H "Metadata-Flavor: Google" "$URL_GCP" 2>/dev/null || true)
if printf '%s' "$GCP" | grep -q access_token; then
  echo "__GCP_OK__ (OAuth token withheld by design)"
  found=1
fi
AZ=$(curl -s -m 3 -H "Metadata:true" "$URL_AZ" 2>/dev/null || true)
if printf '%s' "$AZ" | grep -Eqi 'access_token|client_id'; then
  echo "__AZ_OK__ (MSI token withheld by design)"
  found=1
fi
if [ -z "$found" ]; then
  echo "__NOT_RETRIEVABLE__"
fi
EOS
)

    set +e
    local out
    out=$("$KCLI" exec -n "$src_namespace" "$src_name" -- sh -c "$probe_script" 2>/dev/null)
    local exec_rc=$?
    set -e

    if [[ "$exec_rc" -ne 0 ]]; then
        print_result "$src_namespace" "$src_name" "$host_network" "$service_account" "$netpol_count" "$netpol_match" "$dest_role" "$imds_ip" "$imds_port" "TEST_ERROR" "IMDS credential probe exec failed (rc=$exec_rc)."
        return
    fi
    if [[ "$out" == *"__NO_HTTP_TOOL__"* ]]; then
        print_result "$src_namespace" "$src_name" "$host_network" "$service_account" "$netpol_count" "$netpol_match" "$dest_role" "$imds_ip" "$imds_port" "TEST_ERROR" "Probe pod has no curl; IMDS credential check inconclusive."
        return
    fi

    local details_parts=()
    [[ "$out" == *"__AWS_OK__"* ]] && details_parts+=("$(printf '%s\n' "$out" | grep '__AWS_OK__' | head -n1 | sed 's/^__AWS_OK__ //')")
    [[ "$out" == *"__GCP_OK__"* ]] && details_parts+=("GCP metadata token retrievable")
    [[ "$out" == *"__AZ_OK__"* ]] && details_parts+=("Azure MSI token retrievable")

    if [[ ${#details_parts[@]} -gt 0 ]]; then
        local details
        printf -v details '%s; ' "${details_parts[@]}"
        details="${details%'; '}"
        print_result "$src_namespace" "$src_name" "$host_network" "$service_account" "$netpol_count" "$netpol_match" "$dest_role" "$imds_ip" "$imds_port" "EXPOSED_CREDS" "Cloud credentials retrievable via IMDS: $details. (SecretAccessKey/session/OAuth tokens withheld.)"
    else
        print_result "$src_namespace" "$src_name" "$host_network" "$service_account" "$netpol_count" "$netpol_match" "$dest_role" "$imds_ip" "$imds_port" "NOT_RETRIEVABLE" "IMDS reachable or not, but no cloud credentials retrieved from this pod."
    fi
}

test_auth_status_https() {
    local src_namespace="${1:-}" src_name="${2:-}" host_network="${3:-}" service_account="${4:-}" netpol_count="${5:-}" netpol_match="${6:-}" dest_role="${7:-}" ip="${8:-}" port="${9:-}"
    local endpoint="/metrics"
    local probe_cmd=""
    if [[ "$port" == "2379" ]]; then
        # etcd API auth behavior is better tested against v3 API than "/".
        probe_cmd="command -v curl >/dev/null 2>&1 || exit 127; timeout $TIMEOUT curl -sk --connect-timeout $CONNECT_TIMEOUT -m $TIMEOUT -o /dev/null -H 'Content-Type: application/json' -d '{}' https://$ip:$port/v3/maintenance/status"
    else
        probe_cmd="command -v curl >/dev/null 2>&1 || exit 127; timeout $TIMEOUT curl -sk --connect-timeout $CONNECT_TIMEOUT -m $TIMEOUT -o /dev/null https://$ip:$port$endpoint"
    fi
    local reach_rc
    reach_rc=$(run_exec_probe "$src_namespace" "$src_name" "$probe_cmd")

    local reach_class
    reach_class=$(classify_connectivity_code "$reach_rc")
    if [[ "$reach_class" == "BLOCKED_OR_UNREACHABLE" ]]; then
        print_result "$src_namespace" "$src_name" "$host_network" "$service_account" "$netpol_count" "$netpol_match" "$dest_role" "$ip" "$port" "BLOCKED_OR_UNREACHABLE" "Initial HTTPS probe blocked/unreachable (rc=$reach_rc)."
        return
    fi
    if [[ "$reach_class" == "DENIED_WITHOUT_CREDS" ]]; then
        print_result "$src_namespace" "$src_name" "$host_network" "$service_account" "$netpol_count" "$netpol_match" "$dest_role" "$ip" "$port" "DENIED_WITHOUT_CREDS" "TLS/client-credential denial (rc=$reach_rc)."
        return
    fi
    if [[ "$reach_class" == "TEST_ERROR" ]]; then
        print_result "$src_namespace" "$src_name" "$host_network" "$service_account" "$netpol_count" "$netpol_match" "$dest_role" "$ip" "$port" "TEST_ERROR" "Initial HTTPS probe failed (rc=$reach_rc)."
        return
    fi

    local code_cmd
    if [[ "$port" == "2379" ]]; then
        code_cmd="command -v curl >/dev/null 2>&1 || exit 127; timeout $TIMEOUT curl -sk --connect-timeout $CONNECT_TIMEOUT -m $TIMEOUT -o /dev/null -w '%{http_code}:%{exitcode}' -H 'Content-Type: application/json' -d '{}' https://$ip:$port/v3/maintenance/status"
    else
        code_cmd="command -v curl >/dev/null 2>&1 || exit 127; timeout $TIMEOUT curl -sk --connect-timeout $CONNECT_TIMEOUT -m $TIMEOUT -o /dev/null -w '%{http_code}:%{exitcode}' https://$ip:$port$endpoint"
    fi
    set +e
    local http_out
    http_out=$("$KCLI" exec -n "$src_namespace" "$src_name" -- sh -c "$code_cmd" 2>/dev/null)
    local http_cmd_rc=$?
    set -e

    if [[ "$http_cmd_rc" -ne 0 ]] || [[ "$http_out" != *:* ]]; then
        print_result "$src_namespace" "$src_name" "$host_network" "$service_account" "$netpol_count" "$netpol_match" "$dest_role" "$ip" "$port" "TEST_ERROR" "HTTP status probe failed (exec rc=$http_cmd_rc, out='${http_out:-none}')."
        return
    fi

    local http_code="${http_out%%:*}"
    local curl_rc="${http_out##*:}"

    if [[ "$http_code" == "200" ]]; then
        if [[ "$port" == "2379" ]]; then
            print_result "$src_namespace" "$src_name" "$host_network" "$service_account" "$netpol_count" "$netpol_match" "$dest_role" "$ip" "$port" "EXPOSED" "Unauthenticated HTTP 200 from etcd v3 endpoint '/v3/maintenance/status'."
        else
            print_result "$src_namespace" "$src_name" "$host_network" "$service_account" "$netpol_count" "$netpol_match" "$dest_role" "$ip" "$port" "EXPOSED" "Unauthenticated HTTP 200 from endpoint '$endpoint'."
        fi
    elif [[ "$http_code" == "401" ]] || [[ "$http_code" == "403" ]]; then
        print_result "$src_namespace" "$src_name" "$host_network" "$service_account" "$netpol_count" "$netpol_match" "$dest_role" "$ip" "$port" "AUTH_REQUIRED" "Endpoint requires authentication/authorization (HTTP $http_code)."
    elif [[ "$http_code" == "400" ]] || [[ "$http_code" == "404" ]]; then
        print_result "$src_namespace" "$src_name" "$host_network" "$service_account" "$netpol_count" "$netpol_match" "$dest_role" "$ip" "$port" "DENIED_WITHOUT_CREDS" "Endpoint denied request without credentials/path (HTTP $http_code)."
    elif [[ "$http_code" == "000" ]]; then
        case "$(classify_connectivity_code "$curl_rc")" in
            BLOCKED_OR_UNREACHABLE)
                print_result "$src_namespace" "$src_name" "$host_network" "$service_account" "$netpol_count" "$netpol_match" "$dest_role" "$ip" "$port" "BLOCKED_OR_UNREACHABLE" "No HTTP response and transport failure (curl rc=$curl_rc)."
                ;;
            DENIED_WITHOUT_CREDS)
                print_result "$src_namespace" "$src_name" "$host_network" "$service_account" "$netpol_count" "$netpol_match" "$dest_role" "$ip" "$port" "DENIED_WITHOUT_CREDS" "No HTTP response due to TLS/client auth denial (curl rc=$curl_rc)."
                ;;
            *)
                print_result "$src_namespace" "$src_name" "$host_network" "$service_account" "$netpol_count" "$netpol_match" "$dest_role" "$ip" "$port" "TEST_ERROR" "No HTTP response and ambiguous probe failure (curl rc=$curl_rc)."
                ;;
        esac
    else
        print_result "$src_namespace" "$src_name" "$host_network" "$service_account" "$netpol_count" "$netpol_match" "$dest_role" "$ip" "$port" "TEST_ERROR" "Unhandled HTTP response (http=$http_code, curl rc=$curl_rc)."
    fi
}

echo "Using Kubernetes CLI: $KCLI"
echo "Identifying Node IPs by Role..."
CP_IPS_RAW=$("$KCLI" get nodes -l node-role.kubernetes.io/control-plane= -o jsonpath='{.items[*].status.addresses[?(@.type=="InternalIP")].address}')
ALL_NODE_IPS_RAW=$("$KCLI" get nodes -o jsonpath='{.items[*].status.addresses[?(@.type=="InternalIP")].address}')
if [ -z "$ALL_NODE_IPS_RAW" ]; then
    echo "Error: Could not find any node InternalIPs."
    exit 1
fi

MODE="full"
if [ -n "$CP_IPS_RAW" ]; then
    read -r -a CP_IPS_ARR <<< "$CP_IPS_RAW"
else
    MODE="worker_only"
    CP_IPS_ARR=()
fi

read -r -a ALL_NODE_IPS_ARR <<< "$ALL_NODE_IPS_RAW"
WORKER_IPS_RAW=$("$KCLI" get nodes -l node-role.kubernetes.io/worker= -o jsonpath='{.items[*].status.addresses[?(@.type=="InternalIP")].address}')
WORKER_IPS_ARR=()

if [ -n "$WORKER_IPS_RAW" ]; then
    read -r -a WORKER_IPS_ARR <<< "$WORKER_IPS_RAW"
elif [ "$MODE" == "full" ]; then
    for ip in "${ALL_NODE_IPS_ARR[@]}"; do
        if ! contains_exact_ip "$ip" "${CP_IPS_ARR[@]}"; then
            WORKER_IPS_ARR+=("$ip")
        fi
    done
else
    WORKER_IPS_ARR=("${ALL_NODE_IPS_ARR[@]}")
fi

WORKER_IPS_RAW="${WORKER_IPS_ARR[*]}"
if [ "$MODE" == "full" ]; then
    ALL_NODES_IPS=("${CP_IPS_ARR[@]}" "${WORKER_IPS_ARR[@]}")
else
    ALL_NODES_IPS=("${WORKER_IPS_ARR[@]}")
fi

if [ -n "$CP_IPS_RAW" ]; then
    echo "Control Plane IPs found: $CP_IPS_RAW"
else
    echo "Control Plane IPs found: none"
fi
if [ -n "$WORKER_IPS_RAW" ]; then
    echo "Worker IPs found: $WORKER_IPS_RAW"
else
    echo "Worker IPs found: none"
fi

if [ "$MODE" == "worker_only" ]; then
    echo "Mode: worker_only"
    echo "Info: Control-plane nodes are not visible. Skipping CP-only checks (2379, 10257, 10259)."
else
    echo "Mode: full"
    if [ -z "$WORKER_IPS_RAW" ]; then
        echo "Info: No worker-labeled nodes were detected. Running control-plane-only checks."
    fi
fi
PRE_NODE_COUNT=$("$KCLI" get nodes --no-headers 2>/dev/null | wc -l | tr -d ' ')
if "$KCLI" cluster-info >/dev/null 2>&1; then PRE_API_HEALTH="ok"; else PRE_API_HEALTH="unreachable"; fi

if [[ "$OUTPUT_MODE" == "human" ]]; then
    echo "---------------------------------------------------------------------"
    echo "Testing connectivity from all running pods..."
    echo "Status legend:"
    echo "- EXPOSED: unauthenticated access succeeded."
    echo "- EXPOSED_CREDS: cloud IMDS credentials retrievable from pod (opt-in --check-imds-creds)."
    echo "- NOT_RETRIEVABLE: IMDS credential check did not obtain cloud credentials."
    echo "- AUTH_REQUIRED: endpoint reachable but requires auth."
    echo "- DENIED_WITHOUT_CREDS: reachable but denied by TLS/auth/path constraints."
    echo "- BLOCKED_OR_UNREACHABLE: network path blocked, timed out, or no route."
    echo "- TEST_ERROR: probe could not be completed reliably."
    echo "- SKIPPED: source pod missing required probe tools (curl/timeout)."
    echo "- NETPOL_* fields are based on Kubernetes native NetworkPolicy objects only (networking.k8s.io/v1)."
    echo "  They do not include CNI-specific policy engines (for example Calico GlobalNetworkPolicy)."
    echo "Connectivity/transport code mapping:"
    echo "- BLOCKED_OR_UNREACHABLE: curl/timeout rc in {6,7,28,124}"
    echo "- DENIED_WITHOUT_CREDS: curl rc in {51,58,60} or HTTP 400/404 in auth probe stage"
    echo "- TEST_ERROR: any other probe/exec failure or ambiguous rc"
    echo "- EXPOSED / EXPOSED_CREDS findings are wrapped with =========ALERT========= lines."
    if [[ "$CHECK_IMDS_CREDS" -eq 1 ]]; then
        echo "IMDS credential probe: ENABLED (--check-imds-creds). Secrets redacted by design."
    else
        echo "IMDS credential probe: disabled (pass --check-imds-creds to enable)."
    fi
    echo "Format: SRC_NS | SRC_POD | HOSTNETWORK | SERVICEACCOUNT | NETPOL_NS_COUNT | NETPOL_MATCH | POLICY_ENGINE | PLUGIN_POLICY_COUNT | PLUGIN_POLICY_REFS | DEST_ROLE | DEST_IP | PORT | STATUS | DETAILS"
    echo "Pre-check: API=$PRE_API_HEALTH | NODE_COUNT=$PRE_NODE_COUNT"
    echo "---------------------------------------------------------------------"
else
    jq -cn --arg type "meta" --arg stage "precheck" --arg api "$PRE_API_HEALTH" --arg node_count "$PRE_NODE_COUNT" '{type:$type,stage:$stage,api:$api,node_count:($node_count|tonumber)}'
fi
PODS_JSON=$("$KCLI" get pods -A -o json)
set +e
NETPOL_JSON=$("$KCLI" get networkpolicy -A -o json 2>/dev/null)
NETPOL_RC=$?

CALICO_NS_JSON=$("$KCLI" get networkpolicies.crd.projectcalico.org -A -o json 2>/dev/null)
CALICO_NS_RC=$?
CALICO_GLOBAL_JSON=$("$KCLI" get globalnetworkpolicies.crd.projectcalico.org -o json 2>/dev/null)
CALICO_GLOBAL_RC=$?

CILIUM_NS_JSON=$("$KCLI" get ciliumnetworkpolicies.cilium.io -A -o json 2>/dev/null)
CILIUM_NS_RC=$?
CILIUM_CLUSTER_JSON=$("$KCLI" get ciliumclusterwidenetworkpolicies.cilium.io -o json 2>/dev/null)
CILIUM_CLUSTER_RC=$?
CRD_JSON=$("$KCLI" get crd -o json 2>/dev/null)
CRD_RC=$?
set -e
if [[ $NETPOL_RC -ne 0 ]]; then
    NETPOL_JSON='{"items":[]}'
    echo "Warning: Could not read NetworkPolicies with $KCLI. NETPOL context will be n/a."
fi
if [[ $CALICO_NS_RC -ne 0 ]]; then CALICO_NS_JSON='{"items":[]}'; fi
if [[ $CALICO_GLOBAL_RC -ne 0 ]]; then CALICO_GLOBAL_JSON='{"items":[]}'; fi
if [[ $CILIUM_NS_RC -ne 0 ]]; then CILIUM_NS_JSON='{"items":[]}'; fi
if [[ $CILIUM_CLUSTER_RC -ne 0 ]]; then CILIUM_CLUSTER_JSON='{"items":[]}'; fi
if [[ $CRD_RC -ne 0 ]]; then CRD_JSON='{"items":[]}'; fi

NAMESPACE_FILTER_JSON=$(printf "%s" "$NAMESPACE_FILTER_RAW" | tr ',' '\n' | sed '/^$/d' | jq -R . | jq -s .)
if [[ "$NAMESPACE_FILTER_RAW" == "" ]]; then
    NAMESPACE_FILTER_JSON='[]'
fi

mapfile -t RUNNING_PODS < <(echo "$PODS_JSON" | jq -rc --argjson ns_filter "$NAMESPACE_FILTER_JSON" '
  .items[]
  | select(.status.phase=="Running")
  | select(($ns_filter|length)==0 or (.metadata.namespace as $n | any($ns_filter[]; . == $n)))
  | [.metadata.namespace, .metadata.name, (.spec.hostNetwork // false), (.spec.serviceAccountName // "default"), (.metadata.labels // {})]
  | @base64
')

TOTAL_PODS_CONSIDERED=${#RUNNING_PODS[@]}
if [[ "$MAX_PODS" -gt 0 ]] && [[ ${#RUNNING_PODS[@]} -gt "$MAX_PODS" ]]; then
    TOTAL_PODS_SAMPLED_OUT=$(( ${#RUNNING_PODS[@]} - MAX_PODS ))
    RUNNING_PODS=("${RUNNING_PODS[@]:0:$MAX_PODS}")
fi

for pod_rec in "${RUNNING_PODS[@]}"; do
    pod_data=$(printf "%s" "$pod_rec" | base64 -d)
    src_namespace=$(printf "%s" "$pod_data" | jq -r '.[0]')
    src_name=$(printf "%s" "$pod_data" | jq -r '.[1]')
    host_network=$(printf "%s" "$pod_data" | jq -r '.[2]')
    service_account=$(printf "%s" "$pod_data" | jq -r '.[3]')
    pod_labels=$(printf "%s" "$pod_data" | jq -c '.[4]')
    if [[ "$service_account" == "null" ]] || [[ -z "$service_account" ]]; then
        service_account="default"
    fi

    if [[ $NETPOL_RC -eq 0 ]]; then
        netpol_count=$(printf "%s" "$NETPOL_JSON" | jq --arg ns "$src_namespace" '[.items[] | select(.metadata.namespace == $ns)] | length')
        netpol_match=$(printf "%s" "$NETPOL_JSON" | jq -r --arg ns "$src_namespace" --argjson labels "$pod_labels" '
          def label_match($sel; $labels):
            (($sel.matchLabels // {}) | to_entries | all($labels[.key] == .value)) and
            (($sel.matchExpressions // []) | all(
              if .operator == "In" then (($labels[.key] // null) as $v | ($v != null and ((.values // []) | index($v) != null)))
              elif .operator == "NotIn" then (($labels[.key] // null) as $v | ($v == null or ((.values // []) | index($v) == null)))
              elif .operator == "Exists" then ($labels[.key] != null)
              elif .operator == "DoesNotExist" then ($labels[.key] == null)
              else false
              end
            ));
          [ .items[]
            | select(.metadata.namespace == $ns)
            | select(label_match((.spec.podSelector // {}); $labels))
            | "\(.metadata.namespace)/\(.metadata.name)"
          ] | if length == 0 then "-" else join(",") end
        ')
    else
        netpol_count="n/a"
        netpol_match="n/a"
    fi

    # Plugin policy context is additive to native NetworkPolicy context.
    plugin_engine_parts=("k8s-native")
    plugin_refs=()
    plugin_count=0

    if [[ $CALICO_NS_RC -eq 0 ]] || [[ $CALICO_GLOBAL_RC -eq 0 ]]; then
        plugin_engine_parts+=("calico")
        calico_ns_count=$(printf "%s" "$CALICO_NS_JSON" | jq --arg ns "$src_namespace" '[.items[] | select(.metadata.namespace == $ns)] | length')
        calico_global_count=$(printf "%s" "$CALICO_GLOBAL_JSON" | jq '[.items[]] | length')
        plugin_count=$((plugin_count + calico_ns_count + calico_global_count))
        if [[ "$calico_ns_count" -gt 0 ]]; then
            calico_ns_refs=$(printf "%s" "$CALICO_NS_JSON" | jq -r --arg ns "$src_namespace" '[.items[] | select(.metadata.namespace == $ns) | "calico-np/\(.metadata.namespace)/\(.metadata.name)"] | join(",")')
            [[ -n "$calico_ns_refs" ]] && plugin_refs+=("$calico_ns_refs")
        fi
        if [[ "$calico_global_count" -gt 0 ]]; then
            calico_global_refs=$(printf "%s" "$CALICO_GLOBAL_JSON" | jq -r '[.items[] | "calico-gnp/\(.metadata.name)"] | join(",")')
            [[ -n "$calico_global_refs" ]] && plugin_refs+=("$calico_global_refs")
        fi
    fi

    if [[ $CILIUM_NS_RC -eq 0 ]] || [[ $CILIUM_CLUSTER_RC -eq 0 ]]; then
        plugin_engine_parts+=("cilium")
        cilium_ns_count=$(printf "%s" "$CILIUM_NS_JSON" | jq --arg ns "$src_namespace" '[.items[] | select(.metadata.namespace == $ns)] | length')
        cilium_cluster_count=$(printf "%s" "$CILIUM_CLUSTER_JSON" | jq '[.items[]] | length')
        plugin_count=$((plugin_count + cilium_ns_count + cilium_cluster_count))
        if [[ "$cilium_ns_count" -gt 0 ]]; then
            cilium_ns_refs=$(printf "%s" "$CILIUM_NS_JSON" | jq -r --arg ns "$src_namespace" '[.items[] | select(.metadata.namespace == $ns) | "cilium-np/\(.metadata.namespace)/\(.metadata.name)"] | join(",")')
            [[ -n "$cilium_ns_refs" ]] && plugin_refs+=("$cilium_ns_refs")
        fi
        if [[ "$cilium_cluster_count" -gt 0 ]]; then
            cilium_cluster_refs=$(printf "%s" "$CILIUM_CLUSTER_JSON" | jq -r '[.items[] | "cilium-ccnp/\(.metadata.name)"] | join(",")')
            [[ -n "$cilium_cluster_refs" ]] && plugin_refs+=("$cilium_cluster_refs")
        fi
    fi

    if [[ $CRD_RC -eq 0 ]]; then
        heuristic_engine_parts=()
        while IFS= read -r grp; do
            [[ -z "$grp" ]] && continue
            # Avoid duplicating known engine groups already represented.
            if [[ "$grp" == "networking.k8s.io" ]] || [[ "$grp" == "policy.networking.k8s.io" ]] || [[ "$grp" == "projectcalico.org" ]] || [[ "$grp" == "cilium.io" ]] || [[ "$grp" == *.projectcalico.org ]] || [[ "$grp" == *.cilium.io ]]; then
                continue
            fi
            heuristic_engine_parts+=("heuristic:$grp")
        done < <(printf "%s" "$CRD_JSON" | jq -r '
          [
            .items[]
            | {
                n: (.metadata.name // ""),
                g: (.spec.group // "")
              }
            | select(
                (.n | test("networkpolic|policy|egress|ingress"; "i")) or
                (.g | test("policy|network"; "i"))
              )
            | .g
          ] | unique[]?
        ')
        if [[ ${#heuristic_engine_parts[@]} -gt 0 ]]; then
            plugin_engine_parts+=("${heuristic_engine_parts[@]}")
        fi
    fi

    POD_POLICY_ENGINE=$(printf "%s\n" "${plugin_engine_parts[@]}" | jq -R . | jq -s -r 'unique | join(",")')
    POD_PLUGIN_POLICY_COUNT="$plugin_count"
    if [[ ${#plugin_refs[@]} -eq 0 ]]; then
        POD_PLUGIN_POLICY_REFS="-"
    else
        POD_PLUGIN_POLICY_REFS=$(printf "%s," "${plugin_refs[@]}" | sed 's/,$//')
    fi

    preflight_rc=$(run_exec_probe "$src_namespace" "$src_name" "command -v curl >/dev/null 2>&1 && command -v timeout >/dev/null 2>&1")
    if [[ "$preflight_rc" -ne 0 ]]; then
        TOTAL_PODS_SKIPPED=$((TOTAL_PODS_SKIPPED + 1))
        print_result "$src_namespace" "$src_name" "$host_network" "$service_account" "$netpol_count" "$netpol_match" "-" "-" "-" "SKIPPED" "Missing required tools in source pod (need curl + timeout; rc=$preflight_rc)."
        continue
    fi
    TOTAL_PODS_TESTED=$((TOTAL_PODS_TESTED + 1))

    for ip in "${ALL_NODES_IPS[@]}"; do
        NODE_ROLE=$(resolve_node_role "$ip")

        for port in "${HTTPS_CHECK_PORTS[@]}"; do
            if [[ "$NODE_ROLE" == "CP" ]]; then
                test_auth_status_https "$src_namespace" "$src_name" "$host_network" "$service_account" "$netpol_count" "$netpol_match" "$NODE_ROLE" "$ip" "$port"
            elif [[ "$NODE_ROLE" == "Worker" ]] && [[ "$port" == "10250" ]]; then
                test_auth_status_https "$src_namespace" "$src_name" "$host_network" "$service_account" "$netpol_count" "$netpol_match" "$NODE_ROLE" "$ip" "$port"
            fi
        done
    done

    for ip in "${ALL_NODES_IPS[@]}"; do
        NODE_ROLE=$(resolve_node_role "$ip")
        test_connection_simple "$src_namespace" "$src_name" "$host_network" "$service_account" "$netpol_count" "$netpol_match" "$NODE_ROLE" "$ip" "$KUBELET_HTTP_RO_PORT"
    done

    if [[ "$CHECK_IMDS_CREDS" -eq 1 ]]; then
        test_imds_creds "$src_namespace" "$src_name" "$host_network" "$service_account" "$netpol_count" "$netpol_match"
    fi
done

POST_NODE_COUNT=$("$KCLI" get nodes --no-headers 2>/dev/null | wc -l | tr -d ' ')
if "$KCLI" cluster-info >/dev/null 2>&1; then POST_API_HEALTH="ok"; else POST_API_HEALTH="unreachable"; fi

if [[ "$OUTPUT_MODE" == "human" ]]; then
    echo "---------------------------------------------------------------------"
    echo "Coverage summary:"
    echo "  Pods considered:   $TOTAL_PODS_CONSIDERED"
    echo "  Pods tested:       $TOTAL_PODS_TESTED"
    echo "  Pods skipped:      $TOTAL_PODS_SKIPPED"
    echo "  Pods sampled out:  $TOTAL_PODS_SAMPLED_OUT"
    echo "Status summary:"
    for key in "${!STATUS_COUNTS[@]}"; do
        echo "  $key: ${STATUS_COUNTS[$key]}"
    done
    echo "Per-port status summary:"
    for key in "${!PORT_STATUS_COUNTS[@]}"; do
        echo "  $key: ${PORT_STATUS_COUNTS[$key]}"
    done
    echo "Post-check: API=$POST_API_HEALTH | NODE_COUNT=$POST_NODE_COUNT"
    echo "Cluster port connectivity test complete."
else
    jq -cn \
      --arg type "summary" \
      --argjson pods_considered "$TOTAL_PODS_CONSIDERED" \
      --argjson pods_tested "$TOTAL_PODS_TESTED" \
      --argjson pods_skipped "$TOTAL_PODS_SKIPPED" \
      --argjson pods_sampled_out "$TOTAL_PODS_SAMPLED_OUT" \
      --arg pre_api "$PRE_API_HEALTH" \
      --arg post_api "$POST_API_HEALTH" \
      --argjson pre_nodes "${PRE_NODE_COUNT:-0}" \
      --argjson post_nodes "${POST_NODE_COUNT:-0}" \
      '{type:$type,pods_considered:$pods_considered,pods_tested:$pods_tested,pods_skipped:$pods_skipped,pods_sampled_out:$pods_sampled_out,pre_api:$pre_api,post_api:$post_api,pre_node_count:$pre_nodes,post_node_count:$post_nodes}'
fi
