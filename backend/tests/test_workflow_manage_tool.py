from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from langchain.tools import ToolRuntime

from deerflow.tools import workflow_manage_tool as module
from deerflow.tools.workflow_manage_tool import workflow_manage


def _runtime() -> ToolRuntime:
    return ToolRuntime(
        state={"sandbox": {"sandbox_id": "local"}, "thread_data": {}},
        context={"thread_id": "steward-thread", "user_id": "alice", "agent_name": "workflow-steward"},
        config={"configurable": {"thread_id": "steward-thread"}},
        stream_writer=lambda _: None,
        tools=[],
        tool_call_id="call-1",
        store=None,
    )


def _definition(*, risk_level: str = "R1") -> dict:
    return {
        "schema_version": "cloudmold.skill-task-definition/v1",
        "skill_id": "skill.cloudmold.inventory.stockout-diagnosis.v1",
        "skill_version": "1.0.0",
        "risk_level": risk_level,
        "steps": [
            {
                "step_code": "diagnose",
                "step_order": 1,
                "capability_id": "capability.cloudmold.inventory.query.v1",
                "operation_type": "READ",
                "arguments": ["$input.skuId"],
            }
        ],
    }


def _attestation(definition: dict, *, version_id: str = "1.0.0", issued_at: int | None = None) -> dict:
    material = {
        "issuer": "cloudmold-workflow-registry",
        "workflow_id": "stockout-diagnosis",
        "owner_user_id": "alice",
        "version_id": version_id,
        "definition_sha256": module._sha256(definition),
        "issued_at": issued_at or int(time.time()),
    }
    signature = hmac.new(
        b"test-attestation-secret",
        module._canonical_bytes(material),
        hashlib.sha256,
    ).hexdigest()
    return {**material, "signature": signature}


def _proposal(*, risk_level: str = "E1") -> dict:
    return {
        "problem": "Read-only diagnosis repeatedly times out",
        "evidence_refs": ["observation://stockout/2026-07-25..2026-07-31"],
        "hypothesis": "A bounded query change reduces timeouts without changing results",
        "primary_objective": "Reduce diagnosis latency",
        "expected_benefit": "Lower P95 latency by 20%",
        "business_guardrails": ["Inventory result completeness remains 100%"],
        "technical_guardrails": ["Failure rate does not increase"],
        "minimum_sample": 100,
        "observation_window": "7d",
        "rollback_conditions": ["P95 latency regresses by 10%"],
        "risk_level": risk_level,
    }


@pytest.fixture(autouse=True)
def _paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    paths = MagicMock()
    paths.sandbox_outputs_dir.return_value = tmp_path / "outputs"
    monkeypatch.setattr(module, "get_paths", lambda: paths)
    monkeypatch.setenv("CLOUDMOLD_WORKFLOW_ATTESTATION_SECRET", "test-attestation-secret")


async def _call(action: str, **kwargs) -> dict:
    if action == "import_active" and "attestation" not in kwargs:
        kwargs["attestation"] = _attestation(kwargs["definition"])
    result = await workflow_manage.coroutine(
        runtime=_runtime(),
        action=action,
        workflow_id="stockout-diagnosis",
        **kwargs,
    )
    return json.loads(result)


@pytest.mark.asyncio
async def test_workflow_manage_builds_hash_pinned_review_bundle(tmp_path: Path):
    imported = await _call(
        "import_active",
        definition=_definition(),
    )
    active_sha = imported["active_import"]["sha256"]

    draft = await _call("create_draft", base_sha256=active_sha)
    original_draft_sha = draft["draft"]["draft_sha256"]
    patched = await _call(
        "apply_patch",
        expected_draft_sha256=original_draft_sha,
        patch=[{"op": "replace", "path": "/skill_version", "value": "1.0.1"}],
    )
    assert patched["draft"]["draft_sha256"] != original_draft_sha

    validation = await _call(
        "validate",
        expected_draft_sha256=patched["draft"]["draft_sha256"],
    )
    assert validation["validation"]["passed"] is True
    assert validation["draft"]["status"] == "READY_FOR_REVIEW"

    packaged = await _call(
        "create_proposal",
        expected_draft_sha256=patched["draft"]["draft_sha256"],
        proposal=_proposal(),
    )
    assert packaged["proposal"]["base_sha256"] == active_sha
    assert packaged["proposal"]["status"] == "READY_FOR_EXTERNAL_VALIDATION"
    assert packaged["proposal_path"].startswith("/mnt/user-data/outputs/workflow-steward/")
    proposal_root = packaged["proposal_path"].removeprefix("/mnt/user-data/outputs/").removesuffix("/proposal.json")
    patches_file = tmp_path / "outputs" / proposal_root / "patches.json"
    assert json.loads(patches_file.read_text())[0]["operations"][0]["path"] == "/skill_version"

    active_file = tmp_path / "outputs" / "workflow-steward" / "stockout-diagnosis" / "active" / active_sha / "skill-task.json"
    assert json.loads(active_file.read_text())["skill_version"] == "1.0.0"


@pytest.mark.asyncio
async def test_workflow_manage_rejects_root_replacement_and_stale_hash():
    imported = await _call("import_active", definition=_definition())
    await _call("create_draft", base_sha256=imported["active_import"]["sha256"])

    with pytest.raises(ValueError, match="Root-document"):
        await _call("apply_patch", patch=[{"op": "replace", "path": "", "value": {}}])
    with pytest.raises(ValueError, match="expected_draft_sha256"):
        await _call(
            "apply_patch",
            expected_draft_sha256="0" * 64,
            patch=[{"op": "replace", "path": "/skill_version", "value": "1.0.1"}],
        )


@pytest.mark.asyncio
async def test_workflow_manage_rejects_out_of_band_draft_change(tmp_path: Path):
    imported = await _call("import_active", definition=_definition())
    await _call("create_draft", base_sha256=imported["active_import"]["sha256"])
    draft_path = tmp_path / "outputs" / "workflow-steward" / "stockout-diagnosis" / "draft" / "skill-task.json"
    changed = json.loads(draft_path.read_text())
    changed["skill_version"] = "9.9.9"
    draft_path.write_text(json.dumps(changed))

    with pytest.raises(ValueError, match="changed outside workflow_manage"):
        await _call("validate")


@pytest.mark.asyncio
async def test_workflow_manage_rejects_tampered_active_snapshot(tmp_path: Path):
    imported = await _call("import_active", definition=_definition())
    active_sha = imported["active_import"]["sha256"]
    active_path = tmp_path / "outputs" / "workflow-steward" / "stockout-diagnosis" / "active" / active_sha / "skill-task.json"
    active_path.write_text("{}")

    with pytest.raises(ValueError, match="Immutable active snapshot hash mismatch"):
        await _call("create_draft", base_sha256=active_sha)


@pytest.mark.asyncio
async def test_import_active_rejects_invalid_registry_attestation():
    definition = _definition()
    attestation = _attestation(definition)
    attestation["signature"] = "0" * 64
    with pytest.raises(ValueError, match="signature is invalid"):
        await _call(
            "import_active",
            definition=definition,
            attestation=attestation,
        )


@pytest.mark.asyncio
async def test_import_active_fails_closed_without_verifier_secret(monkeypatch: pytest.MonkeyPatch):
    definition = _definition()
    monkeypatch.delenv("CLOUDMOLD_WORKFLOW_ATTESTATION_SECRET")

    with pytest.raises(ValueError, match="CLOUDMOLD_WORKFLOW_ATTESTATION_SECRET is required"):
        await _call("import_active", definition=definition, attestation=_attestation(definition))


@pytest.mark.asyncio
async def test_workflow_manage_rejects_non_steward_agent():
    runtime = _runtime()
    runtime.context["agent_name"] = "other-agent"

    with pytest.raises(ValueError, match="restricted to the managed workflow-steward"):
        await workflow_manage.coroutine(
            runtime=runtime,
            action="status",
            workflow_id="stockout-diagnosis",
        )


@pytest.mark.asyncio
async def test_workflow_manage_recovers_stale_cross_process_lock(tmp_path: Path):
    root = tmp_path / "outputs" / "workflow-steward" / "stockout-diagnosis"
    root.mkdir(parents=True)
    lock_path = root / ".workflow-manage.lock"
    lock_path.write_text("abandoned-worker")
    stale_time = time.time() - module._LOCK_STALE_AFTER_SECONDS - 1
    os.utime(lock_path, (stale_time, stale_time))

    result = await _call("status")

    assert result["active_import"] is None
    assert not lock_path.exists()


def test_cross_process_lock_heartbeat_prevents_live_lease_theft(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    root = tmp_path / "workflow"
    holder_started = threading.Event()

    monkeypatch.setattr(module, "_LOCK_HEARTBEAT_SECONDS", 0.01)
    monkeypatch.setattr(module, "_LOCK_STALE_AFTER_SECONDS", 0.04)
    monkeypatch.setattr(module, "_LOCK_ACQUIRE_TIMEOUT_SECONDS", 0.12)

    def _hold_lock() -> None:
        with module._interprocess_lock(root):
            holder_started.set()
            time.sleep(0.2)

    holder = threading.Thread(target=_hold_lock)
    holder.start()
    assert holder_started.wait(timeout=1)

    with pytest.raises(TimeoutError, match="Another worker is updating"):
        with module._interprocess_lock(root):
            pytest.fail("A live workflow lock must not be stolen")

    holder.join(timeout=1)
    assert not holder.is_alive()


@pytest.mark.asyncio
async def test_workflow_manage_fails_closed_on_risk_downgrade_and_new_write_capability():
    imported = await _call("import_active", definition=_definition(risk_level="R2"))
    await _call("create_draft", base_sha256=imported["active_import"]["sha256"])
    await _call(
        "apply_patch",
        patch=[
            {"op": "replace", "path": "/risk_level", "value": "R1"},
            {
                "op": "add",
                "path": "/steps/-",
                "value": {
                    "step_code": "write",
                    "step_order": 2,
                    "capability_id": "capability.cloudmold.inventory.write.v1",
                    "operation_type": "WRITE",
                    "approval_required": False,
                },
            },
        ],
    )

    result = await _call("validate")

    assert result["validation"]["passed"] is False
    codes = {finding["code"] for finding in result["validation"]["findings"]}
    assert {"risk-downgrade", "new-write-capability", "write-approval", "write-idempotency"} <= codes
    assert result["draft"]["status"] == "REJECTED"


@pytest.mark.asyncio
async def test_new_active_import_supersedes_existing_draft():
    first = await _call("import_active", definition=_definition())
    await _call("create_draft", base_sha256=first["active_import"]["sha256"])
    next_definition = _definition()
    next_definition["skill_version"] = "1.1.0"

    result = await _call(
        "import_active",
        definition=next_definition,
        attestation=_attestation(next_definition, version_id="1.1.0", issued_at=int(time.time()) + 1),
    )

    assert result["draft"]["status"] == "SUPERSEDED"
    assert result["draft"]["superseded_by_sha256"] == result["active_import"]["sha256"]


@pytest.mark.asyncio
async def test_proposal_cannot_understate_server_derived_risk():
    imported = await _call("import_active", definition=_definition())
    draft = await _call("create_draft", base_sha256=imported["active_import"]["sha256"])
    patched = await _call(
        "apply_patch",
        expected_draft_sha256=draft["draft"]["draft_sha256"],
        patch=[{"op": "replace", "path": "/skill_version", "value": "1.0.1"}],
    )
    validated = await _call("validate", expected_draft_sha256=patched["draft"]["draft_sha256"])
    assert validated["validation"]["minimum_risk_level"] == "E1"

    with pytest.raises(ValueError, match="server-derived minimum E1"):
        await _call(
            "create_proposal",
            expected_draft_sha256=patched["draft"]["draft_sha256"],
            proposal=_proposal(risk_level="E0"),
        )
