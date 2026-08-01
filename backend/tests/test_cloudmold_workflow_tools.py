from __future__ import annotations

import hashlib
import hmac
import json
import time
from pathlib import Path
from unittest.mock import MagicMock

import httpx
import pytest
from langchain.tools import ToolRuntime

from deerflow.tools import cloudmold_workflow_tools as module
from deerflow.tools import workflow_manage_tool as manage_module
from deerflow.tools.workflow_manage_tool import workflow_manage


def _runtime(*, agent_name: str = "workflow-steward") -> ToolRuntime:
    return ToolRuntime(
        state={"sandbox": {"sandbox_id": "local"}, "thread_data": {}},
        context={"thread_id": "steward-thread", "user_id": "alice", "agent_name": agent_name},
        config={"configurable": {"thread_id": "steward-thread"}},
        stream_writer=lambda _: None,
        tools=[],
        tool_call_id="call-1",
        store=None,
    )


def _definition() -> dict:
    return {
        "schema_version": "cloudmold.skill-task-definition/v1",
        "skill_id": "skill.cloudmold.inventory.stockout-diagnosis.v1",
        "skill_version": "1.0.0",
        "risk_level": "R1",
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


def _managed_bundle(
    *,
    workflow_id: str = "skill.cloudmold.inventory.stockout-diagnosis.v1",
    proposal_id: str = "proposal-aabbccddeeff0011",
    base_version: str = "1.0.0",
    candidate_version: str = "1.0.1",
) -> dict:
    return {
        "proposal": {
            "proposal_id": proposal_id,
            "workflow_id": workflow_id,
            "risk_level": "E1",
        },
        "base_definition": {"skill_id": workflow_id, "skill_version": base_version},
        "candidate_definition": {
            "skill_id": workflow_id,
            "skill_version": candidate_version,
        },
        "validation": {"passed": True},
    }


def _attestation(definition: dict, *, owner_user_id: str = "227") -> dict:
    material = {
        "issuer": "cloudmold-workflow-registry",
        "workflow_id": "skill.cloudmold.inventory.stockout-diagnosis.v1",
        "owner_user_id": owner_user_id,
        "version_id": "1.0.0",
        "definition_sha256": module._sha256(definition),
        "issued_at": int(time.time()),
    }
    signature = hmac.new(
        b"registry-secret",
        module._canonical_bytes(material),
        hashlib.sha256,
    ).hexdigest()
    return {**material, "signature": signature}


def test_cloudmold_java_signer_canonical_vector_matches_deerflow_verifier():
    definition = _definition()
    material = {
        "issuer": "cloudmold-workflow-registry",
        "workflow_id": "skill.cloudmold.inventory.stockout-diagnosis.v1",
        "owner_user_id": "42",
        "version_id": "1.0.0",
        "definition_sha256": module._sha256(definition),
        "issued_at": 1780000000,
    }

    assert material["definition_sha256"] == "aa887b233076243c8b10990fb247f2e5ea21e71ce53b1472b4936e3dc1a6808a"
    assert hmac.new(b"registry-secret", module._canonical_bytes(material), hashlib.sha256).hexdigest() == ("14cdf8650a0bec47a2db93111d40a78ea7441970f00718e956d74748feeab850")


@pytest.fixture(autouse=True)
def _config(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("CLOUDMOLD_WORKFLOW_REGISTRY_BASE_URL", "https://cloudmold.test/admin-api")
    monkeypatch.setenv("CLOUDMOLD_WORKFLOW_REGISTRY_TOKEN", "secret-token")
    monkeypatch.setenv("CLOUDMOLD_WORKFLOW_REGISTRY_DEERFLOW_USER_ID", "alice")
    monkeypatch.setenv("CLOUDMOLD_WORKFLOW_REGISTRY_TOKEN_SUBJECT", "227")
    monkeypatch.setenv("CLOUDMOLD_WORKFLOW_ATTESTATION_SECRET", "registry-secret")


@pytest.fixture
def _workflow_artifacts(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    paths = MagicMock()
    paths.sandbox_outputs_dir.return_value = tmp_path / "outputs"
    monkeypatch.setattr(manage_module, "get_paths", lambda: paths)
    return tmp_path


def _authenticated_transport(
    handler,
    *,
    cloudmold_subject: str = "227",
) -> httpx.MockTransport:
    def authenticated_handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/admin-api/cloudmold/workflow-registry/subject":
            return httpx.Response(
                200,
                json={"code": 0, "data": {"owner_user_id": cloudmold_subject, "tenant_id": 162}},
            )
        return handler(request)

    return httpx.MockTransport(authenticated_handler)


@pytest.mark.asyncio
async def test_definition_get_verifies_attestation_and_never_returns_token():
    definition = _definition()

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == ("/admin-api/cloudmold/workflow-registry/definitions/skill.cloudmold.inventory.stockout-diagnosis.v1/1.0.0")
        assert request.headers["authorization"] == "Bearer secret-token"
        return httpx.Response(
            200,
            json={"code": 0, "data": {"definition": definition, "attestation": _attestation(definition)}},
        )

    result = await module._get_definition(
        runtime=_runtime(),
        workflow_id="skill.cloudmold.inventory.stockout-diagnosis.v1",
        workflow_version="1.0.0",
        transport=_authenticated_transport(handler),
    )

    assert result["definition"] == definition
    assert result["attestation"]["owner_user_id"] == "227"
    assert "secret-token" not in json.dumps(result)


@pytest.mark.asyncio
async def test_definition_get_rejects_cross_owner_attestation():
    definition = _definition()

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "code": 0,
                "data": {"definition": definition, "attestation": _attestation(definition, owner_user_id="bob")},
            },
        )

    with pytest.raises(ValueError, match="not bound to this workflow owner"):
        await module._get_definition(
            runtime=_runtime(),
            workflow_id="skill.cloudmold.inventory.stockout-diagnosis.v1",
            workflow_version="1.0.0",
            transport=_authenticated_transport(handler),
        )


@pytest.mark.asyncio
async def test_definition_get_fails_closed_when_registry_configuration_is_missing(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("CLOUDMOLD_WORKFLOW_REGISTRY_TOKEN")

    with pytest.raises(ValueError, match="CLOUDMOLD_WORKFLOW_REGISTRY_TOKEN is required"):
        await module._get_definition(
            runtime=_runtime(),
            workflow_id="skill.cloudmold.inventory.stockout-diagnosis.v1",
            workflow_version="1.0.0",
        )


@pytest.mark.asyncio
async def test_registry_token_subject_must_match_current_deerflow_user(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("CLOUDMOLD_WORKFLOW_REGISTRY_DEERFLOW_USER_ID", "bob")

    with pytest.raises(ValueError, match="not delegated to the current DeerFlow user"):
        await module._get_observations(
            runtime=_runtime(),
            source="managed_runs",
            skill_id="skill.cloudmold.inventory.stockout-diagnosis.v1",
            page_no=1,
            page_size=20,
        )


@pytest.mark.asyncio
async def test_registry_verifies_actual_cloudmold_bearer_subject():
    def handler(_: httpx.Request) -> httpx.Response:
        raise AssertionError("business endpoint must not be called for a mismatched token subject")

    with pytest.raises(ValueError, match="not authenticated as the configured CloudMold subject"):
        await module._get_observations(
            runtime=_runtime(),
            source="managed_runs",
            skill_id="skill.cloudmold.inventory.stockout-diagnosis.v1",
            page_no=1,
            page_size=20,
            transport=_authenticated_transport(handler, cloudmold_subject="999"),
        )


@pytest.mark.asyncio
async def test_registry_rejects_plain_http_except_explicit_loopback(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("CLOUDMOLD_WORKFLOW_REGISTRY_BASE_URL", "http://cloudmold.internal/admin-api")

    with pytest.raises(ValueError, match="must use HTTPS"):
        await module._get_observations(
            runtime=_runtime(),
            source="managed_runs",
            skill_id="skill.cloudmold.inventory.stockout-diagnosis.v1",
            page_no=1,
            page_size=20,
        )

    monkeypatch.setenv("CLOUDMOLD_WORKFLOW_REGISTRY_BASE_URL", "http://127.0.0.1:48080/admin-api")
    monkeypatch.setenv("CLOUDMOLD_WORKFLOW_ALLOW_INSECURE_LOOPBACK", "true")

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"code": 0, "data": {"list": [], "total": 0}})

    result = await module._get_observations(
        runtime=_runtime(),
        source="managed_runs",
        skill_id="skill.cloudmold.inventory.stockout-diagnosis.v1",
        page_no=1,
        page_size=20,
        transport=_authenticated_transport(handler),
    )
    assert result["data"]["total"] == 0


@pytest.mark.asyncio
async def test_observation_get_uses_fixed_allowlisted_endpoint_and_bounded_page():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/admin-api/cloudmold/ai-operations/managed-runs/page"
        assert request.url.params["skillId"] == "skill.cloudmold.inventory.stockout-diagnosis.v1"
        assert request.url.params["pageNo"] == "2"
        assert request.url.params["pageSize"] == "50"
        return httpx.Response(200, json={"code": 0, "data": {"list": [{"status": "FAILED"}], "total": 1}})

    result = await module._get_observations(
        runtime=_runtime(),
        source="managed_runs",
        skill_id="skill.cloudmold.inventory.stockout-diagnosis.v1",
        page_no=2,
        page_size=1000,
        transport=_authenticated_transport(handler),
    )

    assert result == {
        "source": "managed_runs",
        "skill_id": "skill.cloudmold.inventory.stockout-diagnosis.v1",
        "page_no": 2,
        "page_size": 50,
        "data": {"list": [{"status": "FAILED"}], "total": 1},
    }


@pytest.mark.asyncio
async def test_model_observation_get_uses_explicit_model_workflow_namespace():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/admin-api/cloudmold/ai-operations/observations/page"
        assert request.url.params["workflowId"] == "workflow-42"
        assert "skillId" not in request.url.params
        return httpx.Response(200, json={"code": 0, "data": {"list": [], "total": 0}})

    result = await module._get_observations(
        runtime=_runtime(),
        source="model_observations",
        model_workflow_id="workflow-42",
        page_no=1,
        page_size=20,
        transport=_authenticated_transport(handler),
    )

    assert result["model_workflow_id"] == "workflow-42"
    assert "skill_id" not in result


@pytest.mark.asyncio
async def test_observation_get_rejects_identifier_from_wrong_namespace():
    with pytest.raises(ValueError, match="model_workflow_id is required"):
        await module._get_observations(
            runtime=_runtime(),
            source="model_observations",
            skill_id="skill.cloudmold.inventory.stockout-diagnosis.v1",
            page_no=1,
            page_size=20,
        )


async def _create_local_proposal_bundle() -> tuple[str, str]:
    definition = _definition()
    issued_at = int(time.time())
    attestation_material = {
        "issuer": "cloudmold-workflow-registry",
        "workflow_id": "stockout-diagnosis",
        "owner_user_id": "alice",
        "version_id": "1.0.0",
        "definition_sha256": manage_module._sha256(definition),
        "issued_at": issued_at,
    }
    imported = json.loads(
        await workflow_manage.coroutine(
            runtime=_runtime(),
            action="import_active",
            workflow_id="stockout-diagnosis",
            definition=definition,
            attestation={
                **attestation_material,
                "signature": hmac.new(
                    b"registry-secret",
                    manage_module._canonical_bytes(attestation_material),
                    hashlib.sha256,
                ).hexdigest(),
            },
        )
    )
    active_sha = imported["active_import"]["sha256"]
    draft = json.loads(
        await workflow_manage.coroutine(
            runtime=_runtime(),
            action="create_draft",
            workflow_id="stockout-diagnosis",
            base_sha256=active_sha,
        )
    )
    patched = json.loads(
        await workflow_manage.coroutine(
            runtime=_runtime(),
            action="apply_patch",
            workflow_id="stockout-diagnosis",
            expected_draft_sha256=draft["draft"]["draft_sha256"],
            patch=[{"op": "replace", "path": "/skill_version", "value": "1.0.1"}],
        )
    )
    await workflow_manage.coroutine(
        runtime=_runtime(),
        action="validate",
        workflow_id="stockout-diagnosis",
        expected_draft_sha256=patched["draft"]["draft_sha256"],
    )
    proposal = json.loads(
        await workflow_manage.coroutine(
            runtime=_runtime(),
            action="create_proposal",
            workflow_id="stockout-diagnosis",
            expected_draft_sha256=patched["draft"]["draft_sha256"],
            proposal=_proposal(),
        )
    )
    return "stockout-diagnosis", proposal["proposal"]["proposal_id"]


@pytest.mark.asyncio
async def test_proposal_status_get_reads_fixed_registry_status_endpoint():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/admin-api/cloudmold/ai-operations/workflow-registry/workflows/stockout-diagnosis"
        return httpx.Response(
            200,
            json={"code": 0, "data": {"workflow_id": "stockout-diagnosis", "pointer_version": 7, "status": "SUBMITTED"}},
        )

    result = await module._get_workflow_registry_status(
        runtime=_runtime(),
        workflow_id="stockout-diagnosis",
        transport=_authenticated_transport(handler),
    )

    assert result["workflow_id"] == "stockout-diagnosis"
    assert result["pointer_version"] == 7


@pytest.mark.asyncio
async def test_proposal_submit_uses_local_immutable_bundle_and_remote_pointer(_workflow_artifacts: Path):
    workflow_id, proposal_id = await _create_local_proposal_bundle()

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            assert request.url.path == "/admin-api/cloudmold/ai-operations/workflow-registry/workflows/stockout-diagnosis"
            return httpx.Response(
                200,
                json={"code": 0, "data": {"workflow_id": workflow_id, "pointer_version": 7, "candidate_version": None}},
            )
        assert request.method == "POST"
        assert request.url.path == "/admin-api/cloudmold/ai-operations/workflow-registry/proposals"
        payload = json.loads(request.content.decode("utf-8"))
        assert payload["expected_pointer_version"] == 7
        assert payload["proposal"]["proposal_id"] == proposal_id
        assert payload["base_definition"]["skill_version"] == "1.0.0"
        assert payload["candidate_definition"]["skill_version"] == "1.0.1"
        assert payload["validation"]["passed"] is True
        return httpx.Response(
            200,
            json={
                "code": 0,
                "data": {
                    "proposal_id": proposal_id,
                    "pointer_version": 8,
                    "status": "SUBMITTED",
                    "candidate_version": "1.0.1",
                },
            },
        )

    result = await module._submit_workflow_proposal(
        runtime=_runtime(),
        workflow_id=workflow_id,
        proposal_id=proposal_id,
        transport=_authenticated_transport(handler),
    )

    assert result["workflow_id"] == workflow_id
    assert result["proposal_id"] == proposal_id
    assert result["registry"]["pointer_version"] == 8


@pytest.mark.asyncio
async def test_proposal_submit_bootstraps_pointer_version_zero_when_registry_row_is_absent(_workflow_artifacts: Path):
    workflow_id, proposal_id = await _create_local_proposal_bundle()

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            assert request.url.path == "/admin-api/cloudmold/ai-operations/workflow-registry/workflows/stockout-diagnosis"
            return httpx.Response(404, json={"code": 404, "msg": "not found"})
        payload = json.loads(request.content.decode("utf-8"))
        assert payload["expected_pointer_version"] == 0
        return httpx.Response(200, json={"code": 0, "data": {"proposal_id": proposal_id, "pointer_version": 1, "status": "SUBMITTED"}})

    result = await module._submit_workflow_proposal(
        runtime=_runtime(),
        workflow_id=workflow_id,
        proposal_id=proposal_id,
        transport=_authenticated_transport(handler),
    )

    assert result["expected_pointer_version"] == 0
    assert result["registry"]["pointer_version"] == 1


@pytest.mark.asyncio
async def test_cloudmold_workflow_tools_reject_non_steward_agent():
    with pytest.raises(ValueError, match="restricted to the managed workflow-steward"):
        await module._get_observations(
            runtime=_runtime(agent_name="other-agent"),
            source="managed_runs",
            skill_id="skill.cloudmold.inventory.stockout-diagnosis.v1",
            page_no=1,
            page_size=20,
        )


@pytest.mark.asyncio
async def test_proposal_registry_status_uses_fixed_workflow_endpoint():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        assert request.url.path == ("/admin-api/cloudmold/ai-operations/workflow-registry/workflows/skill.cloudmold.inventory.stockout-diagnosis.v1")
        return httpx.Response(
            200,
            json={
                "code": 0,
                "data": {"pointer_version": 3, "stable_version": "1.0.0", "candidate_version": None},
            },
        )

    result = await module._get_proposal_registry_status(
        runtime=_runtime(),
        workflow_id="skill.cloudmold.inventory.stockout-diagnosis.v1",
        transport=_authenticated_transport(handler),
    )

    assert result["pointer_version"] == 3


@pytest.mark.asyncio
async def test_proposal_submit_loads_managed_bundle_and_posts_cas_payload(monkeypatch: pytest.MonkeyPatch):
    bundle = _managed_bundle()
    monkeypatch.setattr(module, "load_proposal_for_submission", lambda *_: bundle)

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert request.url.path == "/admin-api/cloudmold/ai-operations/workflow-registry/proposals"
        payload = json.loads(request.content)
        assert payload == {"expected_pointer_version": 3, **bundle}
        return httpx.Response(
            200,
            json={
                "code": 0,
                "data": {
                    "proposal_id": "proposal-aabbccddeeff0011",
                    "pointer_version": 4,
                    "status": "SUBMITTED",
                },
            },
        )

    result = await module._submit_proposal(
        runtime=_runtime(),
        workflow_id="skill.cloudmold.inventory.stockout-diagnosis.v1",
        proposal_id="proposal-aabbccddeeff0011",
        expected_pointer_version=3,
        transport=_authenticated_transport(handler),
    )

    assert result["pointer_version"] == 4
    assert result["status"] == "SUBMITTED"


@pytest.mark.asyncio
async def test_governance_status_uses_fixed_endpoint():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        assert request.url.path == "/admin-api/cloudmold/ai-operations/workflow-registry/governance/workflows/skill.cloudmold.inventory.stockout-diagnosis.v1"
        return httpx.Response(
            200,
            json={
                "code": 0,
                "data": {
                    "workflow_id": "skill.cloudmold.inventory.stockout-diagnosis.v1",
                    "candidate_version_id": "1.0.1",
                    "pointer_version": 8,
                    "current_status": "READY_FOR_REVIEW",
                    "kill_switch_enabled": False,
                },
            },
        )

    result = await module._get_governance_status(
        runtime=_runtime(),
        workflow_id="skill.cloudmold.inventory.stockout-diagnosis.v1",
        transport=_authenticated_transport(handler),
    )

    assert result["candidate_version_id"] == "1.0.1"
    assert result["pointer_version"] == 8


@pytest.mark.asyncio
async def test_governance_list_discovers_tenant_scoped_workflows_from_fixed_endpoint():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        assert request.url.path == "/admin-api/cloudmold/ai-operations/workflow-registry/governance/workflows"
        assert request.url.params["limit"] == "100"
        return httpx.Response(
            200,
            json={
                "code": 0,
                "data": [
                    {
                        "workflow_id": "skill.cloudmold.inventory.stockout-diagnosis.v1",
                        "stable_version_id": "wrv-1",
                        "pointer_version": 8,
                    }
                ],
            },
        )

    result = await module._list_governance_statuses(
        runtime=_runtime(),
        transport=_authenticated_transport(handler),
    )

    assert [item["workflow_id"] for item in result] == [
        "skill.cloudmold.inventory.stockout-diagnosis.v1"
    ]

    with pytest.raises(ValueError, match="between 1 and 200"):
        await module._list_governance_statuses(runtime=_runtime(), limit=201)


@pytest.mark.asyncio
async def test_validation_start_derives_candidate_and_idempotency_from_governance_status():
    expected_key = module._derived_idempotency_key(
        "validation",
        {
            "workflow_id": "skill.cloudmold.inventory.stockout-diagnosis.v1",
            "candidate_version_id": "1.0.1",
            "expected_pointer_version": 8,
        },
    )

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            assert request.url.path == "/admin-api/cloudmold/ai-operations/workflow-registry/governance/workflows/skill.cloudmold.inventory.stockout-diagnosis.v1"
            return httpx.Response(
                200,
                json={
                    "code": 0,
                    "data": {
                        "workflow_id": "skill.cloudmold.inventory.stockout-diagnosis.v1",
                        "candidate_version_id": "1.0.1",
                        "pointer_version": 8,
                        "current_status": "READY_FOR_REVIEW",
                        "kill_switch_enabled": False,
                    },
                },
            )
        payload = json.loads(request.content)
        assert request.url.path == "/admin-api/cloudmold/ai-operations/workflow-registry/governance/validation-requests"
        assert payload == {
            "workflow_id": "skill.cloudmold.inventory.stockout-diagnosis.v1",
            "candidate_version_id": "1.0.1",
            "expected_pointer_version": 8,
            "idempotency_key": expected_key,
        }
        return httpx.Response(
            200,
            json={
                "code": 0,
                "data": {
                    "workflow_id": "skill.cloudmold.inventory.stockout-diagnosis.v1",
                    "candidate_version_id": "1.0.1",
                    "pointer_version": 9,
                    "current_status": "VALIDATING",
                },
            },
        )

    result = await module._start_validation(
        runtime=_runtime(),
        workflow_id="skill.cloudmold.inventory.stockout-diagnosis.v1",
        transport=_authenticated_transport(handler),
    )

    assert result["idempotency_key"] == expected_key
    assert result["governance"]["current_status"] == "VALIDATING"


@pytest.mark.asyncio
async def test_workflow_evidence_timeline_uses_fixed_query_and_bounded_page():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        assert request.url.path == "/admin-api/cloudmold/ai-operations/workflow-evidence/query"
        assert request.url.params["workflowId"] == "skill.cloudmold.inventory.stockout-diagnosis.v1"
        assert request.url.params["pageNo"] == "2"
        assert request.url.params["pageSize"] == "100"
        assert request.url.params["windowStart"] == "2026-07-25T00:00:00"
        assert request.url.params["windowEnd"] == "2026-07-31T00:00:00"
        return httpx.Response(
            200,
            json={"code": 0, "data": {"list": [{"recordType": "PROBLEM"}], "total": 1}},
        )

    result = await module._query_evidence_timeline(
        runtime=_runtime(),
        workflow_id="skill.cloudmold.inventory.stockout-diagnosis.v1",
        window_start="2026-07-25T00:00:00Z",
        window_end="2026-07-31T00:00:00Z",
        page_no=2,
        page_size=200,
        transport=_authenticated_transport(handler),
    )

    assert result["page_size"] == 100
    assert result["data"]["total"] == 1


@pytest.mark.asyncio
async def test_workflow_evidence_digest_uses_daily_and_weekly_fixed_paths():
    seen_paths: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_paths.append(request.url.path)
        return httpx.Response(200, json={"code": 0, "data": {"workflowId": "skill.cloudmold.inventory.stockout-diagnosis.v1"}})

    daily = await module._query_evidence_digest(
        runtime=_runtime(),
        workflow_id="skill.cloudmold.inventory.stockout-diagnosis.v1",
        window_start="2026-07-25T00:00:00",
        window_end="2026-07-31T00:00:00",
        granularity="daily",
        transport=_authenticated_transport(handler),
    )
    weekly = await module._query_evidence_digest(
        runtime=_runtime(),
        workflow_id="skill.cloudmold.inventory.stockout-diagnosis.v1",
        window_start="2026-07-01T00:00:00",
        window_end="2026-07-31T00:00:00",
        granularity="weekly",
        transport=_authenticated_transport(handler),
    )

    assert daily["granularity"] == "daily"
    assert weekly["granularity"] == "weekly"
    assert seen_paths == [
        "/admin-api/cloudmold/ai-operations/workflow-evidence/digests/daily",
        "/admin-api/cloudmold/ai-operations/workflow-evidence/digests/weekly",
    ]


@pytest.mark.asyncio
async def test_workflow_evidence_ingest_derives_lineage_version_and_idempotency(monkeypatch: pytest.MonkeyPatch):
    bundle = _managed_bundle()
    monkeypatch.setattr(module, "load_proposal_for_submission", lambda *_: bundle)
    expected_lineage = module._derived_lineage_id(
        "skill.cloudmold.inventory.stockout-diagnosis.v1",
        "1.0.1",
        "proposal-aabbccddeeff0011",
    )
    expected_key = module._derived_idempotency_key(
        "evidence",
        {
            "workflow_id": "skill.cloudmold.inventory.stockout-diagnosis.v1",
            "proposal_id": "proposal-aabbccddeeff0011",
            "workflow_version": "1.0.1",
            "source_type": "SYSTEM_LOG",
            "headline": "Repeated timeout spike",
            "status": "CAPTURED",
            "observed_at": "2026-07-31T09:30:00",
            "window_start": "2026-07-25T00:00:00",
            "window_end": "2026-07-31T00:00:00",
        },
    )

    def handler(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content)
        assert request.url.path == "/admin-api/cloudmold/ai-operations/workflow-evidence/ingest"
        assert payload["workflowVersion"] == "1.0.1"
        assert payload["lineageId"] == expected_lineage
        assert payload["proposalId"] == "proposal-aabbccddeeff0011"
        assert payload["idempotencyKey"] == expected_key
        assert payload["externalSnapshots"][0]["sourceClass"] == "REGULATION"
        assert payload["externalSnapshots"][0]["contentHashSha256"] == hashlib.sha256(
            b"redacted policy excerpt"
        ).hexdigest()
        assert "content_digest_material" not in payload["externalSnapshots"][0]
        return httpx.Response(
            200,
            json={
                "code": 0,
                "data": {
                    "aggregateType": "WORKFLOW_OBSERVATION",
                    "aggregateId": "wfo-1",
                    "lineageId": expected_lineage,
                    "workflowVersion": "1.0.1",
                    "proposalId": "proposal-aabbccddeeff0011",
                    "duplicate": False,
                },
            },
        )

    result = await module._ingest_workflow_evidence(
        runtime=_runtime(),
        workflow_id="skill.cloudmold.inventory.stockout-diagnosis.v1",
        proposal_id="proposal-aabbccddeeff0011",
        source_type="SYSTEM_LOG",
        headline="Repeated timeout spike",
        detail_text="The governed run timed out twice in the same decision step.",
        severity="HIGH",
        dqc_status="WARN",
        status="CAPTURED",
        observed_at="2026-07-31T09:30:00Z",
        window_start="2026-07-25T00:00:00Z",
        window_end="2026-07-31T00:00:00Z",
        summary_source_refs=["cloudmold://managed-run/123"],
        metrics={"timeout_count": 2},
        external_snapshots=[
            {
                "url": "https://example.com/policy",
                "fetched_at": "2026-07-31T08:00:00Z",
                "summary": "Operator policy tightened the retry window.",
                "content_digest_material": "redacted policy excerpt",
                "source_class": "REGULATION",
                "confidence": 0.7,
                "severity": "MEDIUM",
                "dqc_status": "PASS",
                "status": "VERIFIED",
                "window_start": "2026-07-25T00:00:00Z",
                "window_end": "2026-07-31T00:00:00Z",
            }
        ],
        transport=_authenticated_transport(handler),
    )

    assert result["lineage_id"] == expected_lineage
    assert result["result"]["aggregateType"] == "WORKFLOW_OBSERVATION"


@pytest.mark.asyncio
async def test_workflow_problem_report_derives_context_from_managed_bundle(monkeypatch: pytest.MonkeyPatch):
    bundle = _managed_bundle()
    monkeypatch.setattr(module, "load_proposal_for_submission", lambda *_: bundle)

    def handler(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content)
        assert request.url.path == "/admin-api/cloudmold/ai-operations/workflow-evidence/problem"
        assert payload["workflowVersion"] == "1.0.1"
        assert payload["proposalId"] == "proposal-aabbccddeeff0011"
        assert payload["status"] == "OPEN"
        return httpx.Response(
            200,
            json={"code": 0, "data": {"aggregateType": "WORKFLOW_PROBLEM", "aggregateId": "wfp-1"}},
        )

    result = await module._record_workflow_problem(
        runtime=_runtime(),
        workflow_id="skill.cloudmold.inventory.stockout-diagnosis.v1",
        proposal_id="proposal-aabbccddeeff0011",
        source_type="USER_BEHAVIOR",
        headline="Operators repeatedly override the same branch",
        problem_detail="Three takeovers happened after the same wait step.",
        severity="MEDIUM",
        dqc_status="UNKNOWN",
        status="OPEN",
        observed_at="2026-07-31T10:00:00",
        window_start="2026-07-25T00:00:00",
        window_end="2026-07-31T00:00:00",
        transport=_authenticated_transport(handler),
    )

    assert result["result"]["aggregateType"] == "WORKFLOW_PROBLEM"


@pytest.mark.asyncio
async def test_workflow_feedback_report_derives_context_from_managed_bundle(monkeypatch: pytest.MonkeyPatch):
    bundle = _managed_bundle()
    monkeypatch.setattr(module, "load_proposal_for_submission", lambda *_: bundle)

    def handler(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content)
        assert request.url.path == "/admin-api/cloudmold/ai-operations/workflow-evidence/feedback"
        assert payload["workflowVersion"] == "1.0.1"
        assert payload["feedbackType"] == "USER_FEEDBACK"
        assert payload["status"] == "RECEIVED"
        return httpx.Response(
            200,
            json={"code": 0, "data": {"aggregateType": "WORKFLOW_USER_FEEDBACK", "aggregateId": "wff-1"}},
        )

    result = await module._record_workflow_feedback(
        runtime=_runtime(),
        workflow_id="skill.cloudmold.inventory.stockout-diagnosis.v1",
        proposal_id="proposal-aabbccddeeff0011",
        source_type="USER_BEHAVIOR",
        feedback_type="USER_FEEDBACK",
        feedback_label="Skipped explanation",
        feedback_text="The user skipped the explanatory branch and manually resolved the task.",
        severity="LOW",
        dqc_status="NOT_APPLICABLE",
        status="RECEIVED",
        observed_at="2026-07-31T10:30:00",
        window_start="2026-07-25T00:00:00",
        window_end="2026-07-31T00:00:00",
        transport=_authenticated_transport(handler),
    )

    assert result["result"]["aggregateType"] == "WORKFLOW_USER_FEEDBACK"
