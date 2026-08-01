"""Governed E1 draft-plane maintenance for CloudMold workflow definitions."""

from __future__ import annotations

import asyncio
import copy
import hashlib
import hmac
import json
import os
import re
import tempfile
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from secrets import token_hex
from typing import Any, Literal
from weakref import WeakValueDictionary

from langchain.tools import tool

from deerflow.config.paths import get_paths
from deerflow.runtime.user_context import resolve_runtime_user_id
from deerflow.tools.types import Runtime

_WORKFLOW_ID_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_WORKFLOW_STEWARD_AGENT_NAME = "workflow-steward"
_ATTESTATION_ISSUER = "cloudmold-workflow-registry"
_ATTESTATION_SECRET_ENV = "CLOUDMOLD_WORKFLOW_ATTESTATION_SECRET"
_ATTESTATION_MAX_AGE_SECONDS = 15 * 60
_ATTESTATION_MAX_FUTURE_SKEW_SECONDS = 5 * 60
_LOCK_ACQUIRE_TIMEOUT_SECONDS = 10.0
_LOCK_STALE_AFTER_SECONDS = 60.0
_LOCK_HEARTBEAT_SECONDS = 10.0
_RISK_ORDER = {"R0": 0, "R1": 1, "R2": 2, "R3": 3}
_EVOLUTION_RISK_ORDER = {"E0": 0, "E1": 1, "E2": 2, "E3": 3}
_locks: WeakValueDictionary[tuple[str, str, str], asyncio.Lock] = WeakValueDictionary()


def _canonical_bytes(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _sha256(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _verify_active_attestation(
    *,
    workflow_id: str,
    owner_user_id: str,
    definition: dict[str, Any],
    attestation: dict[str, Any] | None,
    current_pointer: dict[str, Any] | None,
) -> dict[str, Any]:
    secret = os.environ.get(_ATTESTATION_SECRET_ENV)
    if not secret:
        raise ValueError(f"{_ATTESTATION_SECRET_ENV} is required to import an authoritative active definition")
    if not isinstance(attestation, dict):
        raise ValueError("A CloudMold registry attestation is required for import_active")

    digest = _sha256(definition)
    issued_at = attestation.get("issued_at")
    material = {
        "issuer": attestation.get("issuer"),
        "workflow_id": attestation.get("workflow_id"),
        "owner_user_id": attestation.get("owner_user_id"),
        "version_id": attestation.get("version_id"),
        "definition_sha256": attestation.get("definition_sha256"),
        "issued_at": issued_at,
    }
    if material["issuer"] != _ATTESTATION_ISSUER:
        raise ValueError("Active definition attestation has an untrusted issuer")
    if material["workflow_id"] != workflow_id or material["owner_user_id"] != owner_user_id:
        raise ValueError("Active definition attestation is not bound to this workflow owner")
    if not isinstance(material["version_id"], str) or not material["version_id"]:
        raise ValueError("Active definition attestation requires version_id")
    if material["definition_sha256"] != digest:
        raise ValueError("Active definition does not match its registry attestation")
    if not isinstance(issued_at, int):
        raise ValueError("Active definition attestation issued_at must be an integer Unix timestamp")

    now = int(time.time())
    if issued_at > now + _ATTESTATION_MAX_FUTURE_SKEW_SECONDS:
        raise ValueError("Active definition attestation is dated too far in the future")
    if issued_at < now - _ATTESTATION_MAX_AGE_SECONDS:
        raise ValueError("Active definition attestation is stale; retrieve the definition again")

    signature = attestation.get("signature")
    expected_signature = hmac.new(secret.encode(), _canonical_bytes(material), hashlib.sha256).hexdigest()
    if not isinstance(signature, str) or not hmac.compare_digest(signature, expected_signature):
        raise ValueError("Active definition attestation signature is invalid")

    if current_pointer:
        current_attestation = current_pointer.get("attestation")
        if isinstance(current_attestation, dict):
            current_issued_at = current_attestation.get("issued_at")
            if isinstance(current_issued_at, int) and issued_at < current_issued_at:
                raise ValueError("Active definition attestation is older than the current imported pointer")
            if isinstance(current_issued_at, int) and issued_at == current_issued_at and current_pointer.get("sha256") != digest:
                raise ValueError("Conflicting active definitions share the same attestation timestamp")

    return {**material, "signature": signature, "algorithm": "hmac-sha256"}


def _atomic_write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, path)
    finally:
        if os.path.exists(temp_name):
            os.unlink(temp_name)


@contextmanager
def _interprocess_lock(root: Path):
    """Serialize one workflow across API and scheduler worker processes."""
    root.mkdir(parents=True, exist_ok=True)
    lock_path = root / ".workflow-manage.lock"
    token = token_hex(16)
    deadline = time.monotonic() + _LOCK_ACQUIRE_TIMEOUT_SECONDS
    acquired = False
    heartbeat_stop = threading.Event()
    heartbeat_thread: threading.Thread | None = None

    while not acquired:
        try:
            fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            try:
                stale_stat = lock_path.stat()
                if time.time() - stale_stat.st_mtime > _LOCK_STALE_AFTER_SECONDS:
                    current_stat = lock_path.stat()
                    if (current_stat.st_ino, current_stat.st_mtime_ns) == (stale_stat.st_ino, stale_stat.st_mtime_ns):
                        lock_path.unlink()
                        continue
            except FileNotFoundError:
                continue
            if time.monotonic() >= deadline:
                raise TimeoutError("Another worker is updating this workflow; retry shortly")
            time.sleep(0.05)
        else:
            try:
                os.write(fd, token.encode())
                os.fsync(fd)
            finally:
                os.close(fd)
            acquired = True

    def _refresh_lease() -> None:
        while not heartbeat_stop.wait(_LOCK_HEARTBEAT_SECONDS):
            try:
                if lock_path.read_text(encoding="utf-8") != token:
                    return
                os.utime(lock_path, None)
            except FileNotFoundError:
                return

    heartbeat_thread = threading.Thread(
        target=_refresh_lease,
        name="workflow-manage-lock-heartbeat",
        daemon=True,
    )
    heartbeat_thread.start()
    try:
        yield
    finally:
        heartbeat_stop.set()
        heartbeat_thread.join(timeout=max(_LOCK_HEARTBEAT_SECONDS * 2, 0.1))
        try:
            if lock_path.read_text(encoding="utf-8") == token:
                lock_path.unlink()
        except FileNotFoundError:
            pass


def _read_json(path: Path) -> Any:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def _read_active_snapshot(root: Path, digest: str) -> dict[str, Any]:
    if not isinstance(digest, str) or not _SHA256_RE.fullmatch(digest):
        raise ValueError("Active snapshot pointer has an invalid SHA-256 digest")
    snapshot = _read_json(root / "active" / digest / "skill-task.json")
    if not isinstance(snapshot, dict) or _sha256(snapshot) != digest:
        raise ValueError("Immutable active snapshot hash mismatch")
    return snapshot


def _thread_id(runtime: Runtime) -> str:
    context = runtime.context if isinstance(runtime.context, dict) else {}
    thread_id = context.get("thread_id")
    if not isinstance(thread_id, str) or not thread_id:
        thread_id = runtime.config.get("configurable", {}).get("thread_id")
    if not isinstance(thread_id, str) or not thread_id:
        raise ValueError("workflow_manage requires a persisted thread_id")
    return thread_id


def _workflow_root(runtime: Runtime, workflow_id: str) -> tuple[Path, str]:
    context = runtime.context if isinstance(runtime.context, dict) else {}
    if context.get("agent_name") != _WORKFLOW_STEWARD_AGENT_NAME:
        raise ValueError("workflow_manage is restricted to the managed workflow-steward agent")
    if not _WORKFLOW_ID_RE.fullmatch(workflow_id):
        raise ValueError("workflow_id may contain only letters, digits, dots, underscores, and hyphens")
    user_id = resolve_runtime_user_id(runtime)
    thread_id = _thread_id(runtime)
    root = get_paths().sandbox_outputs_dir(thread_id, user_id=user_id) / "workflow-steward" / workflow_id
    return root, user_id


def _decode_pointer(path: str) -> list[str]:
    if not path.startswith("/"):
        raise ValueError(f"JSON Patch path must be an absolute JSON Pointer: {path!r}")
    if path == "/":
        return [""]
    return [part.replace("~1", "/").replace("~0", "~") for part in path[1:].split("/")]


def _list_index(token: str, length: int, *, allow_end: bool) -> int:
    if token == "-" and allow_end:
        return length
    if not token.isdigit():
        raise ValueError(f"Invalid list index {token!r}")
    index = int(token)
    upper = length if allow_end else length - 1
    if index < 0 or index > upper:
        raise ValueError(f"List index {index} is out of range")
    return index


def _apply_json_patch(document: dict[str, Any], operations: list[dict[str, Any]]) -> dict[str, Any]:
    candidate: Any = copy.deepcopy(document)
    for position, operation in enumerate(operations):
        op = operation.get("op")
        path = operation.get("path")
        if op not in {"add", "replace", "remove"}:
            raise ValueError(f"Patch operation {position} uses unsupported op {op!r}")
        if not isinstance(path, str) or path in {"", "/"}:
            raise ValueError("Root-document replacement/removal is forbidden; submit field-level patches")
        tokens = _decode_pointer(path)
        parent = candidate
        for token in tokens[:-1]:
            if isinstance(parent, dict):
                if token not in parent:
                    raise ValueError(f"Patch path does not exist: {path!r}")
                parent = parent[token]
            elif isinstance(parent, list):
                parent = parent[_list_index(token, len(parent), allow_end=False)]
            else:
                raise ValueError(f"Patch path traverses a scalar: {path!r}")

        leaf = tokens[-1]
        if isinstance(parent, dict):
            if op in {"replace", "remove"} and leaf not in parent:
                raise ValueError(f"Patch path does not exist: {path!r}")
            if op == "remove":
                del parent[leaf]
            else:
                if "value" not in operation:
                    raise ValueError(f"Patch operation {position} requires value")
                parent[leaf] = copy.deepcopy(operation["value"])
        elif isinstance(parent, list):
            index = _list_index(leaf, len(parent), allow_end=op == "add")
            if op == "add":
                if "value" not in operation:
                    raise ValueError(f"Patch operation {position} requires value")
                parent.insert(index, copy.deepcopy(operation["value"]))
            elif op == "replace":
                if "value" not in operation:
                    raise ValueError(f"Patch operation {position} requires value")
                parent[index] = copy.deepcopy(operation["value"])
            else:
                del parent[index]
        else:
            raise ValueError(f"Patch path targets a scalar parent: {path!r}")

    if not isinstance(candidate, dict):
        raise ValueError("Workflow definition must remain a JSON object")
    return candidate


def _validate_candidate(base: dict[str, Any], candidate: dict[str, Any]) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    for field in ("schema_version", "skill_id", "skill_version", "risk_level", "steps"):
        if field not in candidate:
            findings.append({"severity": "error", "code": "required-field", "message": f"Missing required field: {field}"})
    steps = candidate.get("steps")
    if not isinstance(steps, list) or not steps:
        findings.append({"severity": "error", "code": "steps-empty", "message": "steps must be a non-empty array"})
        return findings

    seen_codes: set[str] = set()
    seen_orders: set[int] = set()
    base_capabilities = {step.get("capability_id") for step in base.get("steps", []) if isinstance(step, dict) and isinstance(step.get("capability_id"), str)}
    for index, step in enumerate(steps):
        if not isinstance(step, dict):
            findings.append({"severity": "error", "code": "step-shape", "message": f"Step {index} must be an object"})
            continue
        code = step.get("step_code")
        order = step.get("step_order")
        if not isinstance(code, str) or not code:
            findings.append({"severity": "error", "code": "step-code", "message": f"Step {index} has no step_code"})
        elif code in seen_codes:
            findings.append({"severity": "error", "code": "step-code-duplicate", "message": f"Duplicate step_code: {code}"})
        else:
            seen_codes.add(code)
        if not isinstance(order, int) or order < 1:
            findings.append({"severity": "error", "code": "step-order", "message": f"Step {code or index} has invalid step_order"})
        elif order in seen_orders:
            findings.append({"severity": "error", "code": "step-order-duplicate", "message": f"Duplicate step_order: {order}"})
        else:
            seen_orders.add(order)

        capability = step.get("capability_id")
        operation_type = step.get("operation_type")
        if operation_type == "WRITE":
            if capability not in base_capabilities:
                findings.append({"severity": "error", "code": "new-write-capability", "message": f"E1 draft introduced write capability {capability!r}; escalate through CloudMold E3 governance"})
            if step.get("approval_required") is not True:
                findings.append({"severity": "error", "code": "write-approval", "message": f"Write step {code!r} must keep approval_required=true"})
            if not isinstance(step.get("idempotency_binding"), dict):
                findings.append({"severity": "error", "code": "write-idempotency", "message": f"Write step {code!r} must keep idempotency_binding"})

    base_risk = _RISK_ORDER.get(str(base.get("risk_level")))
    candidate_risk = _RISK_ORDER.get(str(candidate.get("risk_level")))
    if candidate_risk is None:
        findings.append({"severity": "error", "code": "risk-level", "message": "risk_level must be one of R0, R1, R2, R3"})
    elif base_risk is not None and candidate_risk < base_risk:
        findings.append({"severity": "error", "code": "risk-downgrade", "message": "A draft cannot lower the imported active risk level"})
    return findings


def _minimum_evolution_risk(base: dict[str, Any], candidate: dict[str, Any]) -> str:
    if _sha256(base) == _sha256(candidate):
        return "E0"
    candidate_risk = str(candidate.get("risk_level"))
    if candidate_risk == "R3":
        return "E3"
    if candidate_risk == "R2":
        return "E2"

    base_steps = {step.get("step_code"): step for step in base.get("steps", []) if isinstance(step, dict) and isinstance(step.get("step_code"), str)}
    for step in candidate.get("steps", []):
        if not isinstance(step, dict) or step.get("operation_type") != "WRITE":
            continue
        if base_steps.get(step.get("step_code")) != step:
            return "E2"
    return "E1"


def _summary(root: Path) -> dict[str, Any]:
    pointer_path = root / "active" / "current.json"
    state_path = root / "draft" / "state.json"
    return {
        "active_import": _read_json(pointer_path) if pointer_path.exists() else None,
        "draft": _read_json(state_path) if state_path.exists() else None,
        "artifact_root": f"/mnt/user-data/outputs/workflow-steward/{root.name}",
    }


def load_proposal_for_submission(runtime: Runtime, workflow_id: str, proposal_id: str) -> dict[str, Any]:
    """Load an immutable local review bundle and re-verify every hash boundary."""
    root, owner_user_id = _workflow_root(runtime, workflow_id)
    if not isinstance(proposal_id, str) or not re.fullmatch(r"proposal-[0-9a-f]{16}", proposal_id):
        raise ValueError("proposal_id must use the managed proposal hash identifier")
    proposal_root = root / "proposals" / proposal_id
    proposal_path = proposal_root / "proposal.json"
    candidate_path = proposal_root / "skill-task.json"
    validation_path = proposal_root / "validation.json"
    if not proposal_path.exists() or not candidate_path.exists() or not validation_path.exists():
        raise ValueError("Managed proposal bundle is incomplete or does not exist")

    proposal = _read_json(proposal_path)
    candidate = _read_json(candidate_path)
    validation = _read_json(validation_path)
    base_sha = proposal.get("base_sha256")
    candidate_sha = proposal.get("candidate_sha256")
    if proposal.get("proposal_id") != proposal_id or proposal.get("workflow_id") != workflow_id:
        raise ValueError("Managed proposal identity does not match its artifact namespace")
    if proposal.get("status") != "READY_FOR_EXTERNAL_VALIDATION":
        raise ValueError("Managed proposal is not ready for external validation")
    if not isinstance(base_sha, str) or not re.fullmatch(r"[0-9a-f]{64}", base_sha):
        raise ValueError("Managed proposal base hash is invalid")
    if _sha256(candidate) != candidate_sha or proposal_id != f"proposal-{str(candidate_sha)[:16]}":
        raise ValueError("Managed proposal candidate hash does not match its immutable artifact")
    base = _read_active_snapshot(root, base_sha)
    attestation_path = root / "active" / base_sha / "attestation.json"
    if not attestation_path.exists():
        raise ValueError("Managed proposal base attestation is missing")
    base_attestation = _read_json(attestation_path)
    current_pointer_path = root / "active" / "current.json"
    current_pointer = _read_json(current_pointer_path) if current_pointer_path.exists() else None
    base_attestation = _verify_active_attestation(
        workflow_id=workflow_id,
        owner_user_id=owner_user_id,
        definition=base,
        attestation=base_attestation,
        current_pointer=current_pointer,
    )
    if validation.get("passed") is not True or validation.get("base_sha256") != base_sha or validation.get("draft_sha256") != candidate_sha:
        raise ValueError("Managed proposal validation does not match the immutable definitions")
    return {
        "proposal": proposal,
        "base_definition": base,
        "base_attestation": base_attestation,
        "candidate_definition": candidate,
        "validation": validation,
    }


def _manage_locked_sync(
    runtime: Runtime,
    action: str,
    workflow_id: str,
    definition: dict[str, Any] | None,
    attestation: dict[str, Any] | None,
    base_sha256: str | None,
    patch: list[dict[str, Any]] | None,
    expected_draft_sha256: str | None,
    proposal: dict[str, Any] | None,
) -> dict[str, Any]:
    root, owner_user_id = _workflow_root(runtime, workflow_id)
    pointer_path = root / "active" / "current.json"
    draft_path = root / "draft" / "skill-task.json"
    state_path = root / "draft" / "state.json"

    if action == "status":
        return _summary(root)

    if action == "import_active":
        if not isinstance(definition, dict):
            raise ValueError("definition is required for import_active")
        digest = _sha256(definition)
        current_pointer = _read_json(pointer_path) if pointer_path.exists() else None
        verified_attestation = _verify_active_attestation(
            workflow_id=workflow_id,
            owner_user_id=owner_user_id,
            definition=definition,
            attestation=attestation,
            current_pointer=current_pointer,
        )
        snapshot_path = root / "active" / digest / "skill-task.json"
        if snapshot_path.exists() and _sha256(_read_json(snapshot_path)) != digest:
            raise ValueError("Immutable active snapshot hash mismatch")
        if not snapshot_path.exists():
            _atomic_write_json(snapshot_path, definition)
            _atomic_write_json(snapshot_path.with_name("attestation.json"), verified_attestation)
        _atomic_write_json(pointer_path, {"sha256": digest, "attestation": verified_attestation})
        if state_path.exists():
            state = _read_json(state_path)
            if state.get("base_sha256") != digest and state.get("status") not in {"SUPERSEDED", "APPLIED_EXTERNALLY"}:
                state["status"] = "SUPERSEDED"
                state["superseded_by_sha256"] = digest
                _atomic_write_json(state_path, state)
        return _summary(root)

    if not pointer_path.exists():
        raise ValueError("Import an active definition before creating or changing a draft")
    active_pointer = _read_json(pointer_path)
    active_sha = active_pointer.get("sha256")

    if action == "create_draft":
        requested_base = base_sha256 or active_sha
        if requested_base != active_sha:
            raise ValueError("base_sha256 is stale; import/retrieve the current active definition and rebase")
        base = _read_active_snapshot(root, requested_base)
        _atomic_write_json(draft_path, base)
        for stale_path in ("last-patch.json", "patches.json", "validation.json"):
            (root / "draft" / stale_path).unlink(missing_ok=True)
        _atomic_write_json(
            state_path,
            {
                "status": "DRAFT",
                "base_sha256": requested_base,
                "draft_sha256": _sha256(base),
            },
        )
        return _summary(root)

    if not draft_path.exists() or not state_path.exists():
        raise ValueError("Create a draft before applying patches or validation")
    state = _read_json(state_path)
    if state.get("status") == "SUPERSEDED":
        raise ValueError("Draft is superseded by a newer active import; create a new draft")
    if state.get("base_sha256") != active_sha:
        raise ValueError("Draft base no longer matches the current active import")
    current = _read_json(draft_path)
    current_sha = _sha256(current)
    if state.get("draft_sha256") != current_sha:
        raise ValueError("Draft content changed outside workflow_manage; recreate the draft and use JSON Patch")
    if expected_draft_sha256 and expected_draft_sha256 != current_sha:
        raise ValueError("expected_draft_sha256 does not match the current draft")

    if action == "apply_patch":
        if not isinstance(patch, list) or not patch:
            raise ValueError("patch must be a non-empty JSON Patch array")
        candidate = _apply_json_patch(current, patch)
        candidate_sha = _sha256(candidate)
        _atomic_write_json(draft_path, candidate)
        _atomic_write_json(root / "draft" / "last-patch.json", patch)
        patch_history_path = root / "draft" / "patches.json"
        patch_history = _read_json(patch_history_path) if patch_history_path.exists() else []
        patch_history.append({"from_sha256": current_sha, "to_sha256": candidate_sha, "operations": patch})
        _atomic_write_json(patch_history_path, patch_history)
        state.update({"status": "DRAFT", "draft_sha256": candidate_sha})
        _atomic_write_json(state_path, state)
        return _summary(root)

    if action == "validate":
        state["status"] = "VALIDATING"
        _atomic_write_json(state_path, state)
        base = _read_active_snapshot(root, active_sha)
        findings = _validate_candidate(base, current)
        passed = not any(finding["severity"] == "error" for finding in findings)
        validation = {
            "validator": "deerflow-e1-static-preflight/v1",
            "base_sha256": active_sha,
            "draft_sha256": current_sha,
            "passed": passed,
            "minimum_risk_level": _minimum_evolution_risk(base, current),
            "findings": findings,
            "limitations": [
                "CloudMold remains authoritative for schema, capability catalog, composition closure, replay, shadow, approval, release, and rollback.",
            ],
        }
        _atomic_write_json(root / "draft" / "validation.json", validation)
        state.update({"status": "READY_FOR_REVIEW" if passed else "REJECTED", "draft_sha256": current_sha})
        _atomic_write_json(state_path, state)
        return {**_summary(root), "validation": validation}

    if action == "create_proposal":
        if state.get("status") != "READY_FOR_REVIEW":
            raise ValueError("Draft must pass local validation before proposal packaging")
        if not isinstance(proposal, dict):
            raise ValueError("proposal is required for create_proposal")
        required = (
            "problem",
            "evidence_refs",
            "hypothesis",
            "primary_objective",
            "expected_benefit",
            "business_guardrails",
            "technical_guardrails",
            "minimum_sample",
            "observation_window",
            "rollback_conditions",
            "risk_level",
        )
        missing = [field for field in required if not proposal.get(field)]
        if missing:
            raise ValueError(f"Proposal is missing required fields: {', '.join(missing)}")
        if proposal.get("risk_level") not in {"E0", "E1", "E2", "E3"}:
            raise ValueError("Proposal risk_level must be one of E0, E1, E2, E3")
        base = _read_active_snapshot(root, active_sha)
        findings = _validate_candidate(base, current)
        if any(finding["severity"] == "error" for finding in findings):
            raise ValueError("Draft no longer passes local validation")
        validation = _read_json(root / "draft" / "validation.json")
        minimum_risk = _minimum_evolution_risk(base, current)
        if validation.get("passed") is not True or validation.get("base_sha256") != active_sha or validation.get("draft_sha256") != current_sha or validation.get("minimum_risk_level") != minimum_risk:
            raise ValueError("Stored validation does not match the current server-derived draft verdict")
        if _EVOLUTION_RISK_ORDER[proposal["risk_level"]] < _EVOLUTION_RISK_ORDER.get(str(minimum_risk), 3):
            raise ValueError(f"Proposal risk_level cannot be lower than the server-derived minimum {minimum_risk}")
        proposal_id = f"proposal-{current_sha[:16]}"
        proposal_root = root / "proposals" / proposal_id
        bundle = {
            **proposal,
            "proposal_id": proposal_id,
            "workflow_id": workflow_id,
            "base_sha256": active_sha,
            "candidate_sha256": current_sha,
            "status": "READY_FOR_EXTERNAL_VALIDATION",
        }
        if proposal_root.exists():
            existing = _read_json(proposal_root / "proposal.json")
            if existing != bundle:
                raise ValueError("An immutable proposal already exists for this candidate hash")
            return {
                **_summary(root),
                "proposal": existing,
                "proposal_path": f"/mnt/user-data/outputs/workflow-steward/{workflow_id}/proposals/{proposal_id}/proposal.json",
            }
        _atomic_write_json(proposal_root / "proposal.json", bundle)
        _atomic_write_json(proposal_root / "skill-task.json", current)
        if (root / "draft" / "patches.json").exists():
            _atomic_write_json(proposal_root / "patches.json", _read_json(root / "draft" / "patches.json"))
        _atomic_write_json(proposal_root / "validation.json", validation)
        return {
            **_summary(root),
            "proposal": bundle,
            "proposal_path": f"/mnt/user-data/outputs/workflow-steward/{workflow_id}/proposals/{proposal_id}/proposal.json",
        }

    raise ValueError(f"Unsupported action: {action}")


def _manage_sync(
    runtime: Runtime,
    action: str,
    workflow_id: str,
    definition: dict[str, Any] | None,
    attestation: dict[str, Any] | None,
    base_sha256: str | None,
    patch: list[dict[str, Any]] | None,
    expected_draft_sha256: str | None,
    proposal: dict[str, Any] | None,
) -> dict[str, Any]:
    root, _ = _workflow_root(runtime, workflow_id)
    with _interprocess_lock(root):
        return _manage_locked_sync(
            runtime,
            action,
            workflow_id,
            definition,
            attestation,
            base_sha256,
            patch,
            expected_draft_sha256,
            proposal,
        )


@tool(parse_docstring=True)
async def workflow_manage(
    runtime: Runtime,
    action: Literal["status", "import_active", "create_draft", "apply_patch", "validate", "create_proposal"],
    workflow_id: str,
    definition: dict[str, Any] | None = None,
    attestation: dict[str, Any] | None = None,
    base_sha256: str | None = None,
    patch: list[dict[str, Any]] | None = None,
    expected_draft_sha256: str | None = None,
    proposal: dict[str, Any] | None = None,
) -> str:
    """Maintain a thread-scoped workflow draft and review bundle without changing the active registry.

    Args:
        action: Draft-plane action to perform.
        workflow_id: Stable workflow identifier used for the isolated artifact namespace.
        definition: Server-returned active definition, required only for import_active.
        attestation: CloudMold registry HMAC attestation bound to the definition, workflow, owner, version, and issue time.
        base_sha256: Expected imported active hash when creating a draft.
        patch: Field-level JSON Patch operations for apply_patch (add, replace, remove).
        expected_draft_sha256: Optional optimistic-concurrency hash for apply/validate/package.
        proposal: Problem, objective, guardrails, samples, window, rollback, and risk fields for packaging.

    Returns:
        JSON status and artifact paths. External CloudMold validation/release remains required.
    """
    _, user_id = _workflow_root(runtime, workflow_id)
    key = (user_id, _thread_id(runtime), workflow_id)
    lock = _locks.get(key)
    if lock is None:
        lock = asyncio.Lock()
        _locks[key] = lock
    async with lock:
        result = await asyncio.to_thread(
            _manage_sync,
            runtime,
            action,
            workflow_id,
            definition,
            attestation,
            base_sha256,
            patch,
            expected_draft_sha256,
            proposal,
        )
    return json.dumps(result, ensure_ascii=False, sort_keys=True)
