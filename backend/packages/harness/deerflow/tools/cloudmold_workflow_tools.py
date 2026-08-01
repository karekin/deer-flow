"""Trusted read-only CloudMold inputs for the managed Workflow Steward."""

from __future__ import annotations

import json
import os
import re
from typing import Any, Literal
from urllib.parse import urlsplit

import httpx
from langchain.tools import tool

from deerflow.runtime.user_context import resolve_runtime_user_id
from deerflow.tools.types import Runtime
from deerflow.tools.workflow_manage_tool import _canonical_bytes, _sha256, _verify_active_attestation

_WORKFLOW_STEWARD_AGENT_NAME = "workflow-steward"
_BASE_URL_ENV = "CLOUDMOLD_WORKFLOW_REGISTRY_BASE_URL"
_TOKEN_ENV = "CLOUDMOLD_WORKFLOW_REGISTRY_TOKEN"
_DEERFLOW_USER_ENV = "CLOUDMOLD_WORKFLOW_REGISTRY_DEERFLOW_USER_ID"
_TOKEN_SUBJECT_ENV = "CLOUDMOLD_WORKFLOW_REGISTRY_TOKEN_SUBJECT"
_TIMEOUT_ENV = "CLOUDMOLD_WORKFLOW_REGISTRY_TIMEOUT_SECONDS"
_ALLOW_INSECURE_LOOPBACK_ENV = "CLOUDMOLD_WORKFLOW_ALLOW_INSECURE_LOOPBACK"
_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9_.-]{1,191}$")
_MAX_RESPONSE_BYTES = 2 * 1024 * 1024
_LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}
_TRUE_VALUES = {"1", "true", "yes", "on"}


def _require_steward(runtime: Runtime) -> str:
    context = runtime.context if isinstance(runtime.context, dict) else {}
    if context.get("agent_name") != _WORKFLOW_STEWARD_AGENT_NAME:
        raise ValueError("CloudMold workflow reads are restricted to the managed workflow-steward agent")
    return resolve_runtime_user_id(runtime)


def _require_safe_id(value: str, field: str) -> str:
    if not isinstance(value, str) or not _SAFE_ID_RE.fullmatch(value):
        raise ValueError(f"{field} may contain only letters, digits, dots, underscores, and hyphens")
    return value


def _connection_config(deerflow_user_id: str) -> tuple[str, str, str, float]:
    base_url = os.environ.get(_BASE_URL_ENV, "").strip().rstrip("/")
    if not base_url:
        raise ValueError(f"{_BASE_URL_ENV} is required")
    parsed = urlsplit(base_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError(f"{_BASE_URL_ENV} must be an operator-configured HTTPS URL without credentials")
    if parsed.query or parsed.fragment:
        raise ValueError(f"{_BASE_URL_ENV} must not contain a query or fragment")
    insecure_loopback_allowed = parsed.scheme == "http" and parsed.hostname.lower() in _LOOPBACK_HOSTS and os.environ.get(_ALLOW_INSECURE_LOOPBACK_ENV, "").strip().lower() in _TRUE_VALUES
    if parsed.scheme != "https" and not insecure_loopback_allowed:
        raise ValueError(f"{_BASE_URL_ENV} must use HTTPS; plain HTTP is allowed only for explicitly enabled loopback development")

    token = os.environ.get(_TOKEN_ENV, "").strip()
    if not token:
        raise ValueError(f"{_TOKEN_ENV} is required")
    # This bridge intentionally supports one explicit DeerFlow -> CloudMold
    # subject delegation per process. Multi-user deployments must resolve a
    # per-user delegated token instead of sharing a privileged service token.
    delegated_deerflow_user = os.environ.get(_DEERFLOW_USER_ENV, "").strip()
    if not delegated_deerflow_user:
        raise ValueError(f"{_DEERFLOW_USER_ENV} is required")
    if delegated_deerflow_user != deerflow_user_id:
        raise ValueError("CloudMold registry token is not delegated to the current DeerFlow user")
    token_subject = os.environ.get(_TOKEN_SUBJECT_ENV, "").strip()
    if not token_subject:
        raise ValueError(f"{_TOKEN_SUBJECT_ENV} is required")
    try:
        timeout = float(os.environ.get(_TIMEOUT_ENV, "10"))
    except ValueError as exc:
        raise ValueError(f"{_TIMEOUT_ENV} must be numeric") from exc
    if timeout <= 0 or timeout > 60:
        raise ValueError(f"{_TIMEOUT_ENV} must be greater than 0 and at most 60")
    return base_url, token, token_subject, timeout


async def _request_cloudmold(
    path: str,
    *,
    deerflow_user_id: str,
    params: dict[str, Any] | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
) -> tuple[Any, str]:
    base_url, token, token_subject, timeout = _connection_config(deerflow_user_id)
    client_args: dict[str, Any] = {
        "base_url": base_url,
        "headers": {"Authorization": f"Bearer {token}", "Accept": "application/json"},
        "timeout": httpx.Timeout(timeout),
        "follow_redirects": False,
        "trust_env": False,
    }
    if transport is not None:
        client_args["transport"] = transport
    try:
        async with httpx.AsyncClient(**client_args) as client:
            subject_response = await client.get("/cloudmold/workflow-registry/subject")
            subject = _unwrap_cloudmold_response(subject_response)
            if not isinstance(subject, dict) or subject.get("owner_user_id") != token_subject:
                raise ValueError("CloudMold bearer token is not authenticated as the configured CloudMold subject")
            response = await client.get(path, params=params)
    except httpx.HTTPError as exc:
        raise ValueError("CloudMold registry request failed") from exc

    return _unwrap_cloudmold_response(response), token_subject


def _unwrap_cloudmold_response(response: httpx.Response) -> Any:
    """Validate the fixed CloudMold response envelope without exposing secrets."""

    if response.is_redirect:
        raise ValueError("CloudMold registry redirects are forbidden")
    if response.status_code != 200:
        raise ValueError(f"CloudMold registry returned HTTP {response.status_code}")
    if len(response.content) > _MAX_RESPONSE_BYTES:
        raise ValueError("CloudMold registry response exceeds the 2 MiB limit")
    try:
        payload = response.json()
    except ValueError as exc:
        raise ValueError("CloudMold registry returned invalid JSON") from exc
    if not isinstance(payload, dict) or payload.get("code") != 0 or "data" not in payload:
        raise ValueError("CloudMold registry returned an unsuccessful or malformed result")
    return payload["data"]


async def _get_definition(
    *,
    runtime: Runtime,
    workflow_id: str,
    workflow_version: str,
    transport: httpx.AsyncBaseTransport | None = None,
) -> dict[str, Any]:
    deerflow_user_id = _require_steward(runtime)
    workflow_id = _require_safe_id(workflow_id, "workflow_id")
    workflow_version = _require_safe_id(workflow_version, "workflow_version")
    data, cloudmold_subject = await _request_cloudmold(
        f"/cloudmold/workflow-registry/definitions/{workflow_id}/{workflow_version}",
        deerflow_user_id=deerflow_user_id,
        transport=transport,
    )
    if not isinstance(data, dict):
        raise ValueError("CloudMold registry definition result must be an object")
    definition = data.get("definition")
    attestation = data.get("attestation")
    if not isinstance(definition, dict):
        raise ValueError("CloudMold registry did not return a workflow definition")
    verified = _verify_active_attestation(
        workflow_id=workflow_id,
        owner_user_id=cloudmold_subject,
        definition=definition,
        attestation=attestation,
        current_pointer=None,
    )
    if verified["version_id"] != workflow_version:
        raise ValueError("CloudMold registry returned a different workflow version")
    return {"definition": definition, "attestation": {**verified, "signature": attestation["signature"]}}


async def _get_observations(
    *,
    runtime: Runtime,
    source: Literal["managed_runs", "model_observations"],
    page_no: int,
    page_size: int,
    skill_id: str | None = None,
    model_workflow_id: str | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
) -> dict[str, Any]:
    deerflow_user_id = _require_steward(runtime)
    if source == "managed_runs":
        if not skill_id or model_workflow_id is not None:
            raise ValueError("skill_id is required for managed_runs and model_workflow_id must be omitted")
        source_id_name = "skill_id"
        source_id = _require_safe_id(skill_id, source_id_name)
        path = "/cloudmold/ai-operations/managed-runs/page"
        request_parameter = "skillId"
    elif source == "model_observations":
        if not model_workflow_id or skill_id is not None:
            raise ValueError("model_workflow_id is required for model_observations and skill_id must be omitted")
        source_id_name = "model_workflow_id"
        source_id = _require_safe_id(model_workflow_id, source_id_name)
        path = "/cloudmold/ai-operations/observations/page"
        request_parameter = "workflowId"
    else:
        raise ValueError("source must be managed_runs or model_observations")
    if not isinstance(page_no, int) or page_no < 1:
        raise ValueError("page_no must be a positive integer")
    if not isinstance(page_size, int) or page_size < 1:
        raise ValueError("page_size must be a positive integer")
    bounded_page_size = min(page_size, 50)
    data, _cloudmold_subject = await _request_cloudmold(
        path,
        deerflow_user_id=deerflow_user_id,
        params={request_parameter: source_id, "pageNo": page_no, "pageSize": bounded_page_size},
        transport=transport,
    )
    if not isinstance(data, (dict, list)):
        raise ValueError("CloudMold observation result must be an object or array")
    return {
        "source": source,
        source_id_name: source_id,
        "page_no": page_no,
        "page_size": bounded_page_size,
        "data": data,
    }


@tool(parse_docstring=True)
async def workflow_definition_get(
    workflow_id: str,
    workflow_version: str,
    runtime: Runtime,
) -> str:
    """Retrieve and verify an authoritative CloudMold workflow definition.

    Use the returned definition and attestation together with
    ``workflow_manage(import_active)``. This tool is read-only and cannot
    publish, activate, or execute a workflow.

    Args:
        workflow_id: Registered CloudMold Skill workflow identifier.
        workflow_version: Exact immutable workflow version to retrieve.
    """
    result = await _get_definition(
        runtime=runtime,
        workflow_id=workflow_id,
        workflow_version=workflow_version,
    )
    return json.dumps(result, ensure_ascii=False, sort_keys=True)


@tool(parse_docstring=True)
async def workflow_observation_get(
    source: Literal["managed_runs", "model_observations"],
    runtime: Runtime,
    skill_id: str | None = None,
    model_workflow_id: str | None = None,
    page_no: int = 1,
    page_size: int = 20,
) -> str:
    """Read tenant-scoped CloudMold workflow observations from fixed endpoints.

    The current slice exposes durable managed-run outcomes and governed model
    invocation observations. It does not expose arbitrary URLs, raw secrets,
    business writes, releases, or approvals.

    Args:
        source: ``managed_runs`` or ``model_observations``.
        skill_id: SkillTask skill identifier; required only for ``managed_runs``.
        model_workflow_id: AI Operations workflow identifier; required only for
            ``model_observations``. This is a different namespace from skill_id.
        page_no: One-based result page.
        page_size: Requested page size, capped by the service at 50.
    """
    result = await _get_observations(
        runtime=runtime,
        source=source,
        skill_id=skill_id,
        model_workflow_id=model_workflow_id,
        page_no=page_no,
        page_size=page_size,
    )
    return json.dumps(result, ensure_ascii=False, sort_keys=True)


__all__ = [
    "workflow_definition_get",
    "workflow_observation_get",
    "_canonical_bytes",
    "_sha256",
]
