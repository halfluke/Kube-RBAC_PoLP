# Future work: cloud Caps / RBAC performance and correctness

**Handoff for a new agent.** This is the source of truth for remaining Vanilla/cloud cleanups after the OpenShift CRC lab work. Implement the fixes below; do not re-open completed OpenShift items unless parity drift appears.

## Context for the new agent

| | |
|--|--|
| **Repo** | [https://github.com/halfluke/Kube-RBAC_PoLP](https://github.com/halfluke/Kube-RBAC_PoLP) (git remote may still show old `Kube-fluff` URL; same repo) |
| **Branch** | `main` |
| **Baseline** | After OpenShift CRC lab + RBAC/Caps parity (README testing status lists Vanilla / AKS / GKE / EKS / OpenShift CRC as validated; ARO/ROSA not yet tested) |
| **OpenShift plan** | **Done** — treat [`OpenShift-RBAC.sh`](../OpenShift-RBAC.sh) and [`OpenShift-ContainerCapabilities.sh`](../OpenShift-ContainerCapabilities.sh) as reference implementations for the patterns below |
| **This file** | Remaining Vanilla / AKS / EKS / GKE performance + correctness backlog |

### Rules

- Do **not** re-implement these items on OpenShift scripts (already fixed there).
- Do **not** expand ARO/ROSA Check 20 / cloud-flag IAM semantics here.
- Prefer matching existing script style; keep AKS / EKS / GKE in sync when changing shared patterns.
- Commit messages: short, why-focused (match recent `main` history).

### How to start

```text
Clone/pull Kube-RBAC_PoLP main.
Open docs/FUTURE_CLOUD_CAPS_RBAC_FIXES.md.
Implement the remaining fixes in order (Fix 1 → 2 → 3; Fix 4 optional).
```

---

## Already done on OpenShift (copy from these)

| Item | Reference |
|------|-----------|
| RBAC prefetch + `check_permission` reading cache | [`OpenShift-RBAC.sh`](../OpenShift-RBAC.sh), [`Vanilla-RBAC.sh`](../Vanilla-RBAC.sh) |
| Caps: `NS_JSON` + per-NS `PODS_JSON`, no per-pod get | [`OpenShift-ContainerCapabilities.sh`](../OpenShift-ContainerCapabilities.sh) |
| `get_subjects_for_role` filters `roleRef.kind` | [`OpenShift-RBAC.sh`](../OpenShift-RBAC.sh) |
| Check 14 indexed algorithm + mawk-safe awk in checks 16/17 | [`OpenShift-RBAC.sh`](../OpenShift-RBAC.sh) |
| Quiet Check 10 `set -e` / `pipefail` abort | OpenShift + Vanilla Check 10 already fixed |

---

## Fix 1 — Cloud RBAC: use `ALL_ROLES_AND_CR` in `check_permission`

**Status:** pending

**Files:** [`AKS-rbac.sh`](../AKS-rbac.sh), [`EKS-rbac.sh`](../EKS-rbac.sh), [`GKE-rbac.sh`](../GKE-rbac.sh)

**Problem:** Startup already loads `ALL_ROLES_AND_CR` (and bindings), but `check_permission` still runs `$K get clusterrole,role -A -o json` on every call (~30× per full run). Prefetch is unused for role scanning. On AKS this is around the live get near line ~787; EKS/GKE share the same pattern.

**Same class as:** Caps double-fetch (redundant API), but shape is “ignore cache and re-query N times,” not “get the same object twice in a row.”

**Change (keep cloud scripts in sync):**

- In `check_permission`, replace the live `$K get clusterrole,role -A -o json` with `echo "$ALL_ROLES_AND_CR" | jq …` (same pattern as [`Vanilla-RBAC.sh`](../Vanilla-RBAC.sh)).
- Ensure prefetch / `ensure_rbac_cache` has run before any `check_permission` (already true on full runs; for narrow `--checks`, call ensure/cache inside `check_permission` or fall back only when cache empty — match Vanilla).
- Optionally align any other leftover live `get clusterrole,role -A` in wildcard / similar checks the same way.
- Do **not** change check semantics, SUBJECT_CACHE, or cloud Check 2 IAM logic.

**Verify:**

```bash
./AKS-rbac.sh --checks=4,6 --quiet   # same findings, fewer kubectl calls / faster
# repeat for EKS-rbac.sh, GKE-rbac.sh
```

---

## Fix 2 — Caps: eliminate list-then-get-pod double-fetch

**Status:** pending

**Files:** [`Vanilla-ContainerCapabilities.sh`](../Vanilla-ContainerCapabilities.sh), [`AKS-ContainerCapabilities.sh`](../AKS-ContainerCapabilities.sh), [`EKS-ContainerCapabilities.sh`](../EKS-ContainerCapabilities.sh), [`GKE-ContainerCapabilities.sh`](../GKE-ContainerCapabilities.sh)

**Problem:**

1. `kubectl get pods -n $NS -o json` returns full pod objects.
2. Script extracts names only, then `kubectl get pod $POD -n $NS -o json` per pod.

Every pod is fetched twice. On Vanilla this is around lines ~170–179.

**Change (each Caps script):**

- Keep one `PODS_JSON=$(kubectl get pods -n "$NS" -o json)`.
- Iterate `.items[]` from that JSON (name + body); delete the per-pod `get pod`.
- Mirror the loop shape in [`OpenShift-ContainerCapabilities.sh`](../OpenShift-ContainerCapabilities.sh).
- Leave PSA labels, escape chains, platform tags, output formats unchanged.
- Optional follow-up: derive PSA labels from cached `NS_JSON` instead of `kubectl get ns $NS` per namespace.

**Out of this fix:** OpenShift Caps (already done). Duration footers on Vanilla/cloud Caps only if you want parity later.

**Verify:**

```bash
./Vanilla-ContainerCapabilities.sh --only-user-ns --output text
# AKS/EKS/GKE Caps the same against a lab cluster if available
```

Same findings; roughly half the pod-related kubectl GETs.

---

## Fix 3 — `get_subjects_for_role`: filter `roleRef.kind`

**Status:** pending

**Files:** [`Vanilla-RBAC.sh`](../Vanilla-RBAC.sh) first, then [`AKS-rbac.sh`](../AKS-rbac.sh), [`EKS-rbac.sh`](../EKS-rbac.sh), [`GKE-rbac.sh`](../GKE-rbac.sh)

**Problem:** Namespaced Role subject resolution matches RoleBindings by **name only**:

```bash
select(.metadata.namespace == $NS and .roleRef.name == $ROLE)
```

If a RoleBinding in that namespace references a **ClusterRole** with the same name as a namespaced **Role**, subjects of the ClusterRole binding are incorrectly attributed to the Role (and the CRB path may omit `roleRef.kind == "ClusterRole"` on some scripts).

**Already fixed on:** [`OpenShift-RBAC.sh`](../OpenShift-RBAC.sh) — CRB/RB paths require `roleRef.kind`, and namespaced Role lookups use `roleRef.kind == "Role"`.

**Change:**

- ClusterRole path: `select(.roleRef.kind == "ClusterRole" and .roleRef.name == $ROLE)` on both CRB and namespaced RoleBinding→ClusterRole queries.
- Role path: `select(.metadata.namespace == $NS and .roleRef.kind == "Role" and .roleRef.name == $ROLE)`.
- Keep OpenShift as the reference; do not change OpenShift again unless parity drift appears.

**Verify:** Lab fixture (or mental case) with Role `foo` and RoleBinding to ClusterRole `foo` in the same ns — Vanilla/cloud must not list ClusterRole-binding subjects under Role/`foo`.

---

## Fix 4 (optional, after 1–3) — Check 14 algorithmic speedup + mawk

**Status:** pending (optional)

**Problem:** Vanilla Check 14 (same shape as pre-fix OpenShift) rescans **all** ClusterRoleBindings × each target namespace, with per-binding `jq` over `ALL_ROLES_AND_CR`. Prefetch exists; the nested loops do not use it efficiently.

**Already fixed on:** OpenShift-RBAC — index configmap-read roles once; RoleBindings per target ns; CRBs once; mawk-safe subject dedupe in checks 16/17.

**Change later:**

- Port that Check 14 shape to Vanilla (and AKS/EKS/GKE if they share it).
- Replace GNU-awk-only `match(..., m)` in Vanilla checks 16/17 with mawk-portable `substr`/`RSTART` (Kali default awk is mawk).

---

## Suggested order

1. Fix 1 on AKS, then copy the same `check_permission` cache use to EKS and GKE.
2. Fix 2 on Vanilla Caps first, then mirror to AKS/EKS/GKE Caps.
3. Fix 3 on Vanilla-RBAC, then mirror `get_subjects_for_role` filters to AKS/EKS/GKE.
4. Fix 4 optional.

---

## Out of scope

- OpenShift-RBAC / OpenShift-ContainerCapabilities (except as reference).
- Cloud IAM / WI / IRSA / ARO / ROSA check logic changes.
- Expanding check catalogues.
- Full line-by-line semantic re-diff of OpenShift checks 15–19 vs Vanilla.
- CRC/cluster ops (stop, cache, delete).

---

## Acceptance

- Each fix: findings unchanged vs before on a lab cluster.
- Fix 1 / Fix 2: measurable fewer kubectl list/get calls (or clearly faster equivalent smoke runs).
- AKS / EKS / GKE stay behaviorally aligned for shared helpers.
