from __future__ import annotations

import hashlib
import hmac
import json
import time

import httpx
import pytest
from langchain.tools import ToolRuntime

from deerflow.tools import cloudmold_workflow_tools as module


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
