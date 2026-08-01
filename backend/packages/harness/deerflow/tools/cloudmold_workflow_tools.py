"""Trusted CloudMold registry inputs and candidate handoff for Workflow Steward."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation
from typing import Any, Literal
from urllib.parse import urlsplit

import httpx
from langchain.tools import tool

from deerflow.runtime.user_context import resolve_runtime_user_id
from deerflow.tools.types import Runtime
from deerflow.tools.workflow_manage_tool import (
    _canonical_bytes,
    _sha256,
    _verify_active_attestation,
    load_proposal_for_submission,
)

_WORKFLOW_STEWARD_AGENT_NAME = "workflow-steward"
_BASE_URL_ENV = "CLOUDMOLD_WORKFLOW_REGISTRY_BASE_URL"
_TOKEN_ENV = "CLOUDMOLD_WORKFLOW_REGISTRY_TOKEN"
_DEERFLOW_USER_ENV = "CLOUDMOLD_WORKFLOW_REGISTRY_DEERFLOW_USER_ID"
_TOKEN_SUBJECT_ENV = "CLOUDMOLD_WORKFLOW_REGISTRY_TOKEN_SUBJECT"
_TIMEOUT_ENV = "CLOUDMOLD_WORKFLOW_REGISTRY_TIMEOUT_SECONDS"
_ALLOW_INSECURE_LOOPBACK_ENV = "CLOUDMOLD_WORKFLOW_ALLOW_INSECURE_LOOPBACK"
_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9_.-]{1,191}$")
_SAFE_REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/#-]{0,254}$")
_PROPOSAL_ID_RE = re.compile(r"^proposal-[0-9a-f]{16}$")
_SHA256_RE = re.compile(r"^[A-Fa-f0-9]{64}$")
_MAX_RESPONSE_BYTES = 2 * 1024 * 1024
_LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}
_TRUE_VALUES = {"1", "true", "yes", "on"}
_SOURCE_TYPES = {"USER_BEHAVIOR", "SYSTEM_RUN", "SYSTEM_LOG", "BUSINESS_KPI", "DQC", "APPROVAL", "WORK_ORDER", "EXTERNAL_WEB"}
_SEVERITIES = {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
_DQC_STATUSES = {"PASS", "WARN", "FAIL", "UNKNOWN", "NOT_APPLICABLE"}
_OBSERVATION_STATUSES = {"CAPTURED", "CONFIRMED", "STALE", "REJECTED"}
_PROBLEM_STATUSES = {"OPEN", "ACKNOWLEDGED", "MITIGATED", "DISMISSED"}
_FEEDBACK_STATUSES = {"RECEIVED", "ACKNOWLEDGED", "APPLIED", "REJECTED"}
_FEEDBACK_TYPES = {"USER_FEEDBACK", "APPROVAL_NOTE", "RELEASE_SIGNAL", "BUSINESS_REVIEW"}
_EXTERNAL_SOURCE_CLASSES = {"NEWS", "REGULATION", "MARKETPLACE", "SOCIAL", "VENDOR_DOC", "THIRD_PARTY_ANALYSIS"}
_EXTERNAL_STATUSES = {"CAPTURED", "VERIFIED", "STALE", "REJECTED"}
_MAX_SUMMARY_REFS = 10
_MAX_CORROBORATING_SOURCE_TYPES = 8


def _require_steward(runtime: Runtime) -> str:
    context = runtime.context if isinstance(runtime.context, dict) else {}
    if context.get("agent_name") != _WORKFLOW_STEWARD_AGENT_NAME:
        raise ValueError("CloudMold workflow reads are restricted to the managed workflow-steward agent")
    return resolve_runtime_user_id(runtime)


def _require_safe_id(value: str, field: str) -> str:
    if not isinstance(value, str) or not _SAFE_ID_RE.fullmatch(value):
        raise ValueError(f"{field} may contain only letters, digits, dots, underscores, and hyphens")
    return value


def _require_proposal_id(value: str) -> str:
    if not isinstance(value, str) or not _PROPOSAL_ID_RE.fullmatch(value):
        raise ValueError("proposal_id must use the managed proposal hash identifier")
    return value


def _require_enum(value: str, field: str, allowed: set[str]) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a string")
    normalized = value.strip().upper()
    if normalized not in allowed:
        raise ValueError(f"{field} must be one of {', '.join(sorted(allowed))}")
    return normalized


def _require_text(value: str, field: str, *, max_length: int) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} is required")
    normalized = value.strip()
    if len(normalized) > max_length:
        raise ValueError(f"{field} must be at most {max_length} characters")
    return normalized


def _optional_text(value: str | None, field: str, *, max_length: int) -> str | None:
    if value is None:
        return None
    return _require_text(value, field, max_length=max_length)


def _parse_iso_datetime(value: str, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be an ISO-8601 datetime string")
    normalized = value.strip()
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ValueError(f"{field} must be an ISO-8601 datetime string") from exc
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(UTC).replace(tzinfo=None)
    return parsed.replace(microsecond=0).isoformat()


def _optional_iso_datetime(value: str | None, field: str) -> str | None:
    if value is None:
        return None
    return _parse_iso_datetime(value, field)


def _normalize_window(window_start: str, window_end: str) -> tuple[str, str]:
    start_text = _parse_iso_datetime(window_start, "window_start")
    end_text = _parse_iso_datetime(window_end, "window_end")
    start = datetime.fromisoformat(start_text)
    end = datetime.fromisoformat(end_text)
    if start >= end:
        raise ValueError("window_start must be earlier than window_end")
    if (end - start).days > 366:
        raise ValueError("window duration must not exceed 366 days")
    return start_text, end_text


def _bounded_page(page_no: int, page_size: int, *, max_page_size: int) -> tuple[int, int]:
    if not isinstance(page_no, int) or page_no < 1:
        raise ValueError("page_no must be a positive integer")
    if not isinstance(page_size, int) or page_size < 1:
        raise ValueError("page_size must be a positive integer")
    return page_no, min(page_size, max_page_size)


def _normalize_summary_source_refs(refs: list[str] | None) -> list[str]:
    if refs is None:
        return []
    if not isinstance(refs, list):
        raise ValueError("summary_source_refs must be a list of safe opaque references")
    if len(refs) > _MAX_SUMMARY_REFS:
        raise ValueError(f"summary_source_refs must not exceed {_MAX_SUMMARY_REFS} items")
    normalized: list[str] = []
    for index, item in enumerate(refs, start=1):
        if not isinstance(item, str) or not _SAFE_REF_RE.fullmatch(item.strip()):
            raise ValueError(f"summary_source_refs[{index}] must be a safe opaque reference")
        normalized.append(item.strip())
    return normalized


def _normalize_corroborating_source_types(source_types: list[str] | None) -> list[str]:
    if source_types is None:
        return []
    if not isinstance(source_types, list):
        raise ValueError("corroborating_source_types must be a list of source type identifiers")
    if len(source_types) > _MAX_CORROBORATING_SOURCE_TYPES:
        raise ValueError(f"corroborating_source_types must not exceed {_MAX_CORROBORATING_SOURCE_TYPES} items")
    return [_require_enum(value, "corroborating_source_types", _SOURCE_TYPES) for value in source_types]


def _normalize_metrics(metrics: dict[str, Any] | None) -> dict[str, Any] | None:
    if metrics is None:
        return None
    if not isinstance(metrics, dict):
        raise ValueError("metrics must be a JSON object")
    return metrics


def _normalized_confidence(value: float | int | str) -> str:
    try:
        confidence = Decimal(str(value))
    except (InvalidOperation, ValueError) as exc:
        raise ValueError("external_snapshots[].confidence must be numeric") from exc
    if confidence < Decimal("0") or confidence > Decimal("1"):
        raise ValueError("external_snapshots[].confidence must be between 0 and 1")
    return format(confidence.normalize(), "f")


def _require_sha256(value: str, field: str) -> str:
    if not isinstance(value, str) or not _SHA256_RE.fullmatch(value.strip()):
        raise ValueError(f"{field} must be a 64-character hexadecimal SHA-256 digest")
    return value.strip().lower()


def _derived_idempotency_key(prefix: str, payload: dict[str, Any]) -> str:
    return f"{prefix}-{_sha256(payload)[:24]}"


def _derived_lineage_id(workflow_id: str, workflow_version: str, proposal_id: str) -> str:
    return f"lineage-{_sha256({'workflow_id': workflow_id, 'workflow_version': workflow_version, 'proposal_id': proposal_id})[:24]}"


def _normalize_external_snapshots(external_snapshots: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    if external_snapshots is None:
        return []
    if not isinstance(external_snapshots, list):
        raise ValueError("external_snapshots must be a list of structured external evidence snapshots")
    if len(external_snapshots) > 3:
        raise ValueError("external_snapshots must not exceed 3 items")
    normalized: list[dict[str, Any]] = []
    for index, snapshot in enumerate(external_snapshots, start=1):
        if not isinstance(snapshot, dict):
            raise ValueError(f"external_snapshots[{index}] must be an object")
        digest_value = snapshot.get("content_hash_sha256") or snapshot.get("contentHashSha256")
        digest_material = snapshot.get("content_digest_material") or snapshot.get("contentDigestMaterial")
        if digest_value is None:
            digest_text = _require_text(
                str(digest_material or ""),
                f"external_snapshots[{index}].content_digest_material",
                max_length=65_536,
            )
            digest_value = hashlib.sha256(digest_text.encode("utf-8")).hexdigest()
        item = {
            "url": _require_text(str(snapshot.get("url") or ""), f"external_snapshots[{index}].url", max_length=2048),
            "fetchedAt": _parse_iso_datetime(str(snapshot.get("fetched_at") or snapshot.get("fetchedAt") or ""), f"external_snapshots[{index}].fetched_at"),
            "summary": _require_text(str(snapshot.get("summary") or ""), f"external_snapshots[{index}].summary", max_length=2000),
            "contentHashSha256": _require_sha256(str(digest_value), f"external_snapshots[{index}].content_hash_sha256"),
            "sourceClass": _require_enum(str(snapshot.get("source_class") or snapshot.get("sourceClass") or ""), f"external_snapshots[{index}].source_class", _EXTERNAL_SOURCE_CLASSES),
            "confidence": _normalized_confidence(snapshot.get("confidence")),
            "severity": _require_enum(str(snapshot.get("severity") or ""), f"external_snapshots[{index}].severity", _SEVERITIES),
            "dqcStatus": _require_enum(str(snapshot.get("dqc_status") or snapshot.get("dqcStatus") or ""), f"external_snapshots[{index}].dqc_status", _DQC_STATUSES),
            "status": _require_enum(str(snapshot.get("status") or ""), f"external_snapshots[{index}].status", _EXTERNAL_STATUSES),
        }
        published_at = snapshot.get("published_at") or snapshot.get("publishedAt")
        if published_at is not None:
            item["publishedAt"] = _optional_iso_datetime(str(published_at), f"external_snapshots[{index}].published_at")
        fresh_until = snapshot.get("fresh_until") or snapshot.get("freshUntil")
        if fresh_until is not None:
            item["freshUntil"] = _optional_iso_datetime(str(fresh_until), f"external_snapshots[{index}].fresh_until")
        window_start = snapshot.get("window_start") or snapshot.get("windowStart")
        window_end = snapshot.get("window_end") or snapshot.get("windowEnd")
        if window_start is None or window_end is None:
            raise ValueError(f"external_snapshots[{index}] requires window_start and window_end")
        normalized_start, normalized_end = _normalize_window(str(window_start), str(window_end))
        item["windowStart"] = normalized_start
        item["windowEnd"] = normalized_end
        region = snapshot.get("region")
        if region is not None:
            item["region"] = _optional_text(str(region), f"external_snapshots[{index}].region", max_length=128)
        applicability = snapshot.get("applicability")
        if applicability is not None:
            item["applicability"] = _optional_text(str(applicability), f"external_snapshots[{index}].applicability", max_length=512)
        snapshot_id = snapshot.get("snapshot_id") or snapshot.get("snapshotId")
        if snapshot_id is not None:
            item["snapshotId"] = _require_safe_id(str(snapshot_id), f"external_snapshots[{index}].snapshot_id")
        normalized.append(item)
    return normalized


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
    method: Literal["GET", "POST"] = "GET",
    params: dict[str, Any] | None = None,
    json_body: dict[str, Any] | None = None,
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
            response = await client.request(method, path, params=params, json=json_body)
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


async def _get_proposal_registry_status(
    *,
    runtime: Runtime,
    workflow_id: str,
    transport: httpx.AsyncBaseTransport | None = None,
) -> dict[str, Any]:
    deerflow_user_id = _require_steward(runtime)
    workflow_id = _require_safe_id(workflow_id, "workflow_id")
    data, _cloudmold_subject = await _request_cloudmold(
        f"/cloudmold/ai-operations/workflow-registry/workflows/{workflow_id}",
        deerflow_user_id=deerflow_user_id,
        transport=transport,
    )
    if not isinstance(data, dict):
        raise ValueError("CloudMold proposal registry status must be an object")
    return data


_get_workflow_registry_status = _get_proposal_registry_status


async def _get_governance_status(
    *,
    runtime: Runtime,
    workflow_id: str,
    transport: httpx.AsyncBaseTransport | None = None,
) -> dict[str, Any]:
    deerflow_user_id = _require_steward(runtime)
    workflow_id = _require_safe_id(workflow_id, "workflow_id")
    data, _cloudmold_subject = await _request_cloudmold(
        f"/cloudmold/ai-operations/workflow-registry/governance/workflows/{workflow_id}",
        deerflow_user_id=deerflow_user_id,
        transport=transport,
    )
    if not isinstance(data, dict):
        raise ValueError("CloudMold workflow governance status must be an object")
    return data


async def _list_governance_statuses(
    *,
    runtime: Runtime,
    limit: int = 100,
    transport: httpx.AsyncBaseTransport | None = None,
) -> list[dict[str, Any]]:
    deerflow_user_id = _require_steward(runtime)
    if not isinstance(limit, int) or limit < 1 or limit > 200:
        raise ValueError("limit must be between 1 and 200")
    data, _cloudmold_subject = await _request_cloudmold(
        "/cloudmold/ai-operations/workflow-registry/governance/workflows",
        deerflow_user_id=deerflow_user_id,
        params={"limit": limit},
        transport=transport,
    )
    if not isinstance(data, list) or any(not isinstance(item, dict) for item in data):
        raise ValueError("CloudMold workflow governance list must be an array of objects")
    return data


async def _start_validation(
    *,
    runtime: Runtime,
    workflow_id: str,
    candidate_version_id: str | None = None,
    expected_pointer_version: int | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
) -> dict[str, Any]:
    governance = await _get_governance_status(runtime=runtime, workflow_id=workflow_id, transport=transport)
    resolved_candidate_version = candidate_version_id or governance.get("candidate_version_id")
    if not isinstance(resolved_candidate_version, str) or not resolved_candidate_version.strip():
        raise ValueError("CloudMold governance status does not expose an active candidate_version_id")
    resolved_candidate_version = _require_safe_id(resolved_candidate_version.strip(), "candidate_version_id")
    if expected_pointer_version is None:
        pointer_version = governance.get("pointer_version")
        if not isinstance(pointer_version, int) or pointer_version < 0:
            raise ValueError("CloudMold governance status did not return a valid pointer_version")
    else:
        if not isinstance(expected_pointer_version, int) or expected_pointer_version < 0:
            raise ValueError("expected_pointer_version must be a non-negative integer")
        pointer_version = expected_pointer_version
    payload = {
        "workflow_id": workflow_id,
        "candidate_version_id": resolved_candidate_version,
        "expected_pointer_version": pointer_version,
    }
    idempotency_key = _derived_idempotency_key("validation", payload)
    deerflow_user_id = _require_steward(runtime)
    result, _cloudmold_subject = await _request_cloudmold(
        "/cloudmold/ai-operations/workflow-registry/governance/validation-requests",
        deerflow_user_id=deerflow_user_id,
        method="POST",
        json_body={**payload, "idempotency_key": idempotency_key},
        transport=transport,
    )
    if not isinstance(result, dict):
        raise ValueError("CloudMold workflow validation start result must be an object")
    return {
        "workflow_id": workflow_id,
        "candidate_version_id": resolved_candidate_version,
        "expected_pointer_version": pointer_version,
        "idempotency_key": idempotency_key,
        "governance": result,
    }


async def _query_evidence_timeline(
    *,
    runtime: Runtime,
    workflow_id: str,
    window_start: str,
    window_end: str,
    page_no: int,
    page_size: int,
    transport: httpx.AsyncBaseTransport | None = None,
) -> dict[str, Any]:
    deerflow_user_id = _require_steward(runtime)
    workflow_id = _require_safe_id(workflow_id, "workflow_id")
    normalized_start, normalized_end = _normalize_window(window_start, window_end)
    page_no, bounded_page_size = _bounded_page(page_no, page_size, max_page_size=100)
    data, _cloudmold_subject = await _request_cloudmold(
        "/cloudmold/ai-operations/workflow-evidence/query",
        deerflow_user_id=deerflow_user_id,
        params={
            "workflowId": workflow_id,
            "windowStart": normalized_start,
            "windowEnd": normalized_end,
            "pageNo": page_no,
            "pageSize": bounded_page_size,
        },
        transport=transport,
    )
    return {
        "workflow_id": workflow_id,
        "window_start": normalized_start,
        "window_end": normalized_end,
        "page_no": page_no,
        "page_size": bounded_page_size,
        "data": data,
    }


async def _query_evidence_digest(
    *,
    runtime: Runtime,
    workflow_id: str,
    window_start: str,
    window_end: str,
    granularity: Literal["daily", "weekly"],
    transport: httpx.AsyncBaseTransport | None = None,
) -> dict[str, Any]:
    deerflow_user_id = _require_steward(runtime)
    workflow_id = _require_safe_id(workflow_id, "workflow_id")
    normalized_start, normalized_end = _normalize_window(window_start, window_end)
    path = "/cloudmold/ai-operations/workflow-evidence/digests/daily" if granularity == "daily" else "/cloudmold/ai-operations/workflow-evidence/digests/weekly"
    data, _cloudmold_subject = await _request_cloudmold(
        path,
        deerflow_user_id=deerflow_user_id,
        params={
            "workflowId": workflow_id,
            "windowStart": normalized_start,
            "windowEnd": normalized_end,
        },
        transport=transport,
    )
    return {
        "workflow_id": workflow_id,
        "granularity": granularity,
        "window_start": normalized_start,
        "window_end": normalized_end,
        "data": data,
    }


async def _load_local_proposal_context(
    *,
    runtime: Runtime,
    workflow_id: str,
    proposal_id: str,
) -> dict[str, Any]:
    workflow_id = _require_safe_id(workflow_id, "workflow_id")
    proposal_id = _require_proposal_id(proposal_id)
    bundle = await asyncio.to_thread(load_proposal_for_submission, runtime, workflow_id, proposal_id)
    if not isinstance(bundle, dict):
        raise ValueError("CloudMold workflow proposal bundle must be an object")
    proposal = bundle.get("proposal")
    candidate_definition = bundle.get("candidate_definition")
    if not isinstance(proposal, dict) or not isinstance(candidate_definition, dict):
        raise ValueError("CloudMold workflow proposal bundle is missing proposal metadata")
    bundle_workflow_id = proposal.get("workflow_id")
    workflow_version = candidate_definition.get("skill_version")
    if bundle_workflow_id != workflow_id:
        raise ValueError("Managed proposal bundle does not belong to the requested workflow")
    if proposal.get("proposal_id") != proposal_id:
        raise ValueError("Managed proposal bundle does not match the requested proposal_id")
    if not isinstance(workflow_version, str) or not workflow_version.strip():
        raise ValueError("Managed proposal bundle does not include candidate skill_version")
    normalized_workflow_version = workflow_version.strip()
    return {
        "workflow_id": workflow_id,
        "proposal_id": proposal_id,
        "workflow_version": normalized_workflow_version,
        "lineage_id": _derived_lineage_id(workflow_id, normalized_workflow_version, proposal_id),
        "bundle": bundle,
    }


async def _post_evidence_write(
    *,
    runtime: Runtime,
    path: str,
    json_body: dict[str, Any],
    workflow_id: str,
    proposal_id: str,
    workflow_version: str,
    lineage_id: str,
    idempotency_key: str,
    transport: httpx.AsyncBaseTransport | None = None,
) -> dict[str, Any]:
    deerflow_user_id = _require_steward(runtime)
    data, _cloudmold_subject = await _request_cloudmold(
        path,
        deerflow_user_id=deerflow_user_id,
        method="POST",
        json_body=json_body,
        transport=transport,
    )
    if not isinstance(data, dict):
        raise ValueError("CloudMold workflow evidence result must be an object")
    return {
        "workflow_id": workflow_id,
        "workflow_version": workflow_version,
        "proposal_id": proposal_id,
        "lineage_id": lineage_id,
        "idempotency_key": idempotency_key,
        "result": data,
    }


async def _submit_proposal(
    *,
    runtime: Runtime,
    workflow_id: str,
    proposal_id: str,
    expected_pointer_version: int,
    transport: httpx.AsyncBaseTransport | None = None,
) -> dict[str, Any]:
    deerflow_user_id = _require_steward(runtime)
    workflow_id = _require_safe_id(workflow_id, "workflow_id")
    if not isinstance(expected_pointer_version, int) or expected_pointer_version < 0:
        raise ValueError("expected_pointer_version must be a non-negative integer")
    bundle = await asyncio.to_thread(load_proposal_for_submission, runtime, workflow_id, proposal_id)
    data, _cloudmold_subject = await _request_cloudmold(
        "/cloudmold/ai-operations/workflow-registry/proposals",
        deerflow_user_id=deerflow_user_id,
        method="POST",
        json_body={"expected_pointer_version": expected_pointer_version, **bundle},
        transport=transport,
    )
    if not isinstance(data, dict):
        raise ValueError("CloudMold proposal submission result must be an object")
    return data


async def _submit_workflow_proposal(
    *,
    runtime: Runtime,
    workflow_id: str,
    proposal_id: str,
    expected_pointer_version: int | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
) -> dict[str, Any]:
    if expected_pointer_version is None:
        try:
            registry = await _get_proposal_registry_status(
                runtime=runtime,
                workflow_id=workflow_id,
                transport=transport,
            )
        except ValueError as exc:
            if "HTTP 404" not in str(exc):
                raise
            pointer_version = 0
        else:
            pointer_version = registry.get("pointer_version")
            if pointer_version in {None, ""}:
                pointer_version = 0
            if not isinstance(pointer_version, int) or pointer_version < 0:
                raise ValueError("CloudMold proposal registry did not return a valid pointer_version")
    else:
        if not isinstance(expected_pointer_version, int) or expected_pointer_version < 0:
            raise ValueError("expected_pointer_version must be a non-negative integer")
        pointer_version = expected_pointer_version
    submitted = await _submit_proposal(
        runtime=runtime,
        workflow_id=workflow_id,
        proposal_id=proposal_id,
        expected_pointer_version=pointer_version,
        transport=transport,
    )
    return {
        "workflow_id": workflow_id,
        "proposal_id": proposal_id,
        "expected_pointer_version": pointer_version,
        "registry": submitted,
    }


async def _ingest_workflow_evidence(
    *,
    runtime: Runtime,
    workflow_id: str,
    proposal_id: str,
    source_type: str,
    headline: str,
    detail_text: str,
    severity: str,
    dqc_status: str,
    status: str,
    observed_at: str,
    window_start: str,
    window_end: str,
    evidence_ref: str | None = None,
    summary_source_refs: list[str] | None = None,
    model_summary: str | None = None,
    metrics: dict[str, Any] | None = None,
    release_eligible: bool = False,
    corroborating_source_types: list[str] | None = None,
    fresh_until: str | None = None,
    external_snapshots: list[dict[str, Any]] | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
) -> dict[str, Any]:
    proposal_context = await _load_local_proposal_context(runtime=runtime, workflow_id=workflow_id, proposal_id=proposal_id)
    normalized_source_type = _require_enum(source_type, "source_type", _SOURCE_TYPES)
    normalized_severity = _require_enum(severity, "severity", _SEVERITIES)
    normalized_dqc_status = _require_enum(dqc_status, "dqc_status", _DQC_STATUSES)
    normalized_status = _require_enum(status, "status", _OBSERVATION_STATUSES)
    normalized_window_start, normalized_window_end = _normalize_window(window_start, window_end)
    normalized_observed_at = _parse_iso_datetime(observed_at, "observed_at")
    normalized_fresh_until = _optional_iso_datetime(fresh_until, "fresh_until")
    normalized_external_snapshots = _normalize_external_snapshots(external_snapshots)
    normalized_summary_refs = _normalize_summary_source_refs(summary_source_refs)
    normalized_corroborating_types = _normalize_corroborating_source_types(corroborating_source_types)
    if normalized_source_type == "EXTERNAL_WEB" and release_eligible:
        raise ValueError("External web evidence cannot be marked release_eligible")
    payload = {
        "lineageId": proposal_context["lineage_id"],
        "workflowId": workflow_id,
        "workflowVersion": proposal_context["workflow_version"],
        "proposalId": proposal_id,
        "sourceType": normalized_source_type,
        "headline": _require_text(headline, "headline", max_length=512),
        "detailText": _require_text(detail_text, "detail_text", max_length=2000),
        "severity": normalized_severity,
        "dqcStatus": normalized_dqc_status,
        "status": normalized_status,
        "releaseEligible": bool(release_eligible),
        "windowStart": normalized_window_start,
        "windowEnd": normalized_window_end,
        "observedAt": normalized_observed_at,
    }
    if evidence_ref is not None:
        if not isinstance(evidence_ref, str) or not _SAFE_REF_RE.fullmatch(evidence_ref.strip()):
            raise ValueError("evidence_ref must be a safe opaque reference")
        payload["evidenceRef"] = evidence_ref.strip()
    if normalized_summary_refs:
        payload["summarySourceRefs"] = normalized_summary_refs
    if model_summary is not None:
        payload["modelSummary"] = _optional_text(model_summary, "model_summary", max_length=2000)
    if metrics is not None:
        payload["metrics"] = _normalize_metrics(metrics)
    if normalized_fresh_until is not None:
        payload["freshUntil"] = normalized_fresh_until
    if normalized_corroborating_types:
        payload["corroboratingSourceTypes"] = normalized_corroborating_types
    if normalized_external_snapshots:
        payload["externalSnapshots"] = normalized_external_snapshots
    idempotency_key = _derived_idempotency_key(
        "evidence",
        {
            "workflow_id": workflow_id,
            "proposal_id": proposal_id,
            "workflow_version": proposal_context["workflow_version"],
            "source_type": normalized_source_type,
            "headline": payload["headline"],
            "status": normalized_status,
            "observed_at": normalized_observed_at,
            "window_start": normalized_window_start,
            "window_end": normalized_window_end,
        },
    )
    payload["idempotencyKey"] = idempotency_key
    return await _post_evidence_write(
        runtime=runtime,
        path="/cloudmold/ai-operations/workflow-evidence/ingest",
        json_body=payload,
        workflow_id=workflow_id,
        proposal_id=proposal_id,
        workflow_version=proposal_context["workflow_version"],
        lineage_id=proposal_context["lineage_id"],
        idempotency_key=idempotency_key,
        transport=transport,
    )


async def _record_workflow_problem(
    *,
    runtime: Runtime,
    workflow_id: str,
    proposal_id: str,
    source_type: str,
    headline: str,
    problem_detail: str,
    severity: str,
    dqc_status: str,
    status: str,
    observed_at: str,
    window_start: str,
    window_end: str,
    evidence_ref: str | None = None,
    summary_source_refs: list[str] | None = None,
    model_summary: str | None = None,
    metrics: dict[str, Any] | None = None,
    release_eligible: bool = False,
    corroborating_source_types: list[str] | None = None,
    fresh_until: str | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
) -> dict[str, Any]:
    proposal_context = await _load_local_proposal_context(runtime=runtime, workflow_id=workflow_id, proposal_id=proposal_id)
    normalized_source_type = _require_enum(source_type, "source_type", _SOURCE_TYPES)
    normalized_severity = _require_enum(severity, "severity", _SEVERITIES)
    normalized_dqc_status = _require_enum(dqc_status, "dqc_status", _DQC_STATUSES)
    normalized_status = _require_enum(status, "status", _PROBLEM_STATUSES)
    normalized_window_start, normalized_window_end = _normalize_window(window_start, window_end)
    normalized_observed_at = _parse_iso_datetime(observed_at, "observed_at")
    normalized_fresh_until = _optional_iso_datetime(fresh_until, "fresh_until")
    normalized_summary_refs = _normalize_summary_source_refs(summary_source_refs)
    normalized_corroborating_types = _normalize_corroborating_source_types(corroborating_source_types)
    if normalized_source_type == "EXTERNAL_WEB" and release_eligible:
        raise ValueError("External web evidence cannot be marked release_eligible")
    payload = {
        "lineageId": proposal_context["lineage_id"],
        "workflowId": workflow_id,
        "workflowVersion": proposal_context["workflow_version"],
        "proposalId": proposal_id,
        "sourceType": normalized_source_type,
        "headline": _require_text(headline, "headline", max_length=512),
        "problemDetail": _require_text(problem_detail, "problem_detail", max_length=2000),
        "severity": normalized_severity,
        "dqcStatus": normalized_dqc_status,
        "status": normalized_status,
        "releaseEligible": bool(release_eligible),
        "windowStart": normalized_window_start,
        "windowEnd": normalized_window_end,
        "observedAt": normalized_observed_at,
    }
    if evidence_ref is not None:
        if not isinstance(evidence_ref, str) or not _SAFE_REF_RE.fullmatch(evidence_ref.strip()):
            raise ValueError("evidence_ref must be a safe opaque reference")
        payload["evidenceRef"] = evidence_ref.strip()
    if normalized_summary_refs:
        payload["summarySourceRefs"] = normalized_summary_refs
    if model_summary is not None:
        payload["modelSummary"] = _optional_text(model_summary, "model_summary", max_length=2000)
    if metrics is not None:
        payload["metrics"] = _normalize_metrics(metrics)
    if normalized_fresh_until is not None:
        payload["freshUntil"] = normalized_fresh_until
    if normalized_corroborating_types:
        payload["corroboratingSourceTypes"] = normalized_corroborating_types
    idempotency_key = _derived_idempotency_key(
        "problem",
        {
            "workflow_id": workflow_id,
            "proposal_id": proposal_id,
            "workflow_version": proposal_context["workflow_version"],
            "source_type": normalized_source_type,
            "headline": payload["headline"],
            "status": normalized_status,
            "observed_at": normalized_observed_at,
            "window_start": normalized_window_start,
            "window_end": normalized_window_end,
        },
    )
    payload["idempotencyKey"] = idempotency_key
    return await _post_evidence_write(
        runtime=runtime,
        path="/cloudmold/ai-operations/workflow-evidence/problem",
        json_body=payload,
        workflow_id=workflow_id,
        proposal_id=proposal_id,
        workflow_version=proposal_context["workflow_version"],
        lineage_id=proposal_context["lineage_id"],
        idempotency_key=idempotency_key,
        transport=transport,
    )


async def _record_workflow_feedback(
    *,
    runtime: Runtime,
    workflow_id: str,
    proposal_id: str,
    source_type: str,
    feedback_type: str,
    feedback_label: str,
    feedback_text: str,
    severity: str,
    dqc_status: str,
    status: str,
    observed_at: str,
    window_start: str,
    window_end: str,
    evidence_ref: str | None = None,
    summary_source_refs: list[str] | None = None,
    model_summary: str | None = None,
    metrics: dict[str, Any] | None = None,
    release_eligible: bool = False,
    corroborating_source_types: list[str] | None = None,
    fresh_until: str | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
) -> dict[str, Any]:
    proposal_context = await _load_local_proposal_context(runtime=runtime, workflow_id=workflow_id, proposal_id=proposal_id)
    normalized_source_type = _require_enum(source_type, "source_type", _SOURCE_TYPES)
    normalized_feedback_type = _require_enum(feedback_type, "feedback_type", _FEEDBACK_TYPES)
    normalized_severity = _require_enum(severity, "severity", _SEVERITIES)
    normalized_dqc_status = _require_enum(dqc_status, "dqc_status", _DQC_STATUSES)
    normalized_status = _require_enum(status, "status", _FEEDBACK_STATUSES)
    normalized_window_start, normalized_window_end = _normalize_window(window_start, window_end)
    normalized_observed_at = _parse_iso_datetime(observed_at, "observed_at")
    normalized_fresh_until = _optional_iso_datetime(fresh_until, "fresh_until")
    normalized_summary_refs = _normalize_summary_source_refs(summary_source_refs)
    normalized_corroborating_types = _normalize_corroborating_source_types(corroborating_source_types)
    if normalized_source_type == "EXTERNAL_WEB" and release_eligible:
        raise ValueError("External web evidence cannot be marked release_eligible")
    payload = {
        "lineageId": proposal_context["lineage_id"],
        "workflowId": workflow_id,
        "workflowVersion": proposal_context["workflow_version"],
        "proposalId": proposal_id,
        "sourceType": normalized_source_type,
        "feedbackType": normalized_feedback_type,
        "feedbackLabel": _require_text(feedback_label, "feedback_label", max_length=512),
        "feedbackText": _require_text(feedback_text, "feedback_text", max_length=2000),
        "severity": normalized_severity,
        "dqcStatus": normalized_dqc_status,
        "status": normalized_status,
        "releaseEligible": bool(release_eligible),
        "windowStart": normalized_window_start,
        "windowEnd": normalized_window_end,
        "observedAt": normalized_observed_at,
    }
    if evidence_ref is not None:
        if not isinstance(evidence_ref, str) or not _SAFE_REF_RE.fullmatch(evidence_ref.strip()):
            raise ValueError("evidence_ref must be a safe opaque reference")
        payload["evidenceRef"] = evidence_ref.strip()
    if normalized_summary_refs:
        payload["summarySourceRefs"] = normalized_summary_refs
    if model_summary is not None:
        payload["modelSummary"] = _optional_text(model_summary, "model_summary", max_length=2000)
    if metrics is not None:
        payload["metrics"] = _normalize_metrics(metrics)
    if normalized_fresh_until is not None:
        payload["freshUntil"] = normalized_fresh_until
    if normalized_corroborating_types:
        payload["corroboratingSourceTypes"] = normalized_corroborating_types
    idempotency_key = _derived_idempotency_key(
        "feedback",
        {
            "workflow_id": workflow_id,
            "proposal_id": proposal_id,
            "workflow_version": proposal_context["workflow_version"],
            "source_type": normalized_source_type,
            "feedback_type": normalized_feedback_type,
            "feedback_label": payload["feedbackLabel"],
            "status": normalized_status,
            "observed_at": normalized_observed_at,
            "window_start": normalized_window_start,
            "window_end": normalized_window_end,
        },
    )
    payload["idempotencyKey"] = idempotency_key
    return await _post_evidence_write(
        runtime=runtime,
        path="/cloudmold/ai-operations/workflow-evidence/feedback",
        json_body=payload,
        workflow_id=workflow_id,
        proposal_id=proposal_id,
        workflow_version=proposal_context["workflow_version"],
        lineage_id=proposal_context["lineage_id"],
        idempotency_key=idempotency_key,
        transport=transport,
    )


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


@tool(parse_docstring=True)
async def workflow_proposal_status(workflow_id: str, runtime: Runtime) -> str:
    """Read CloudMold's stable/candidate registry state and CAS pointer version.

    Args:
        workflow_id: Registered CloudMold Skill workflow identifier.
    """
    result = await _get_proposal_registry_status(runtime=runtime, workflow_id=workflow_id)
    return json.dumps(result, ensure_ascii=False, sort_keys=True)


@tool(parse_docstring=True)
async def workflow_proposal_submit(
    workflow_id: str,
    proposal_id: str,
    runtime: Runtime,
    expected_pointer_version: int | None = None,
) -> str:
    """Submit a locally verified immutable proposal to CloudMold's candidate registry.

    The tool reloads the managed review bundle from the current thread and
    verifies its hashes before submission. It cannot accept model-supplied
    definitions, approve, promote, execute, release, or roll back a workflow.

    Args:
        workflow_id: Registered CloudMold Skill workflow identifier.
        proposal_id: Immutable proposal hash identifier returned by workflow_manage.
        expected_pointer_version: Optional CAS version returned by
            ``workflow_proposal_status``. When omitted, the tool reads the
            current pointer version from CloudMold before submitting.
    """
    result = await _submit_workflow_proposal(
        runtime=runtime,
        workflow_id=workflow_id,
        proposal_id=proposal_id,
        expected_pointer_version=expected_pointer_version,
    )
    return json.dumps(result, ensure_ascii=False, sort_keys=True)


@tool(parse_docstring=True)
async def workflow_governance_status(workflow_id: str, runtime: Runtime) -> str:
    """Read CloudMold's governed validation and release status for one workflow.

    Args:
        workflow_id: Registered CloudMold Skill workflow identifier.
    """
    result = await _get_governance_status(runtime=runtime, workflow_id=workflow_id)
    return json.dumps(result, ensure_ascii=False, sort_keys=True)


@tool(parse_docstring=True)
async def workflow_governance_list(runtime: Runtime, limit: int = 100) -> str:
    """List tenant-scoped workflows maintained by CloudMold governance.

    Use this read-only tool at the start of scheduled daily or weekly stewardship
    runs so the model does not invent workflow identifiers.

    Args:
        limit: Maximum number of workflow pointers to return, from 1 to 200.
    """
    result = await _list_governance_statuses(runtime=runtime, limit=limit)
    return json.dumps(result, ensure_ascii=False, sort_keys=True)


@tool(parse_docstring=True)
async def workflow_validation_start(
    workflow_id: str,
    runtime: Runtime,
    candidate_version_id: str | None = None,
    expected_pointer_version: int | None = None,
) -> str:
    """Request CloudMold's independent validator to start validating a candidate.

    When omitted, ``candidate_version_id`` and ``expected_pointer_version`` are
    derived from the current governance status so the model does not invent CAS
    inputs or candidate identifiers.

    Args:
        workflow_id: Registered CloudMold Skill workflow identifier.
        candidate_version_id: Optional explicit candidate version identifier.
        expected_pointer_version: Optional explicit expected governance pointer
            version. When omitted, DeerFlow reads the current value first.
    """
    result = await _start_validation(
        runtime=runtime,
        workflow_id=workflow_id,
        candidate_version_id=candidate_version_id,
        expected_pointer_version=expected_pointer_version,
    )
    return json.dumps(result, ensure_ascii=False, sort_keys=True)


@tool(parse_docstring=True)
async def workflow_evidence_timeline(
    workflow_id: str,
    window_start: str,
    window_end: str,
    runtime: Runtime,
    page_no: int = 1,
    page_size: int = 20,
) -> str:
    """Query one workflow's evidence timeline from CloudMold's fixed endpoint.

    Args:
        workflow_id: Registered CloudMold Skill workflow identifier.
        window_start: Inclusive ISO-8601 start datetime.
        window_end: Exclusive ISO-8601 end datetime.
        page_no: One-based page number.
        page_size: Requested page size, capped at 100.
    """
    result = await _query_evidence_timeline(
        runtime=runtime,
        workflow_id=workflow_id,
        window_start=window_start,
        window_end=window_end,
        page_no=page_no,
        page_size=page_size,
    )
    return json.dumps(result, ensure_ascii=False, sort_keys=True)


@tool(parse_docstring=True)
async def workflow_evidence_digest(
    workflow_id: str,
    window_start: str,
    window_end: str,
    granularity: Literal["daily", "weekly"],
    runtime: Runtime,
) -> str:
    """Read CloudMold's aggregated workflow evidence digest for one time window.

    Args:
        workflow_id: Registered CloudMold Skill workflow identifier.
        window_start: Inclusive ISO-8601 start datetime.
        window_end: Exclusive ISO-8601 end datetime.
        granularity: ``daily`` or ``weekly``.
    """
    result = await _query_evidence_digest(
        runtime=runtime,
        workflow_id=workflow_id,
        window_start=window_start,
        window_end=window_end,
        granularity=granularity,
    )
    return json.dumps(result, ensure_ascii=False, sort_keys=True)


@tool(parse_docstring=True)
async def workflow_evidence_ingest(
    workflow_id: str,
    proposal_id: str,
    source_type: str,
    headline: str,
    detail_text: str,
    severity: str,
    dqc_status: str,
    status: str,
    observed_at: str,
    window_start: str,
    window_end: str,
    runtime: Runtime,
    evidence_ref: str | None = None,
    summary_source_refs: list[str] | None = None,
    model_summary: str | None = None,
    metrics: dict[str, Any] | None = None,
    release_eligible: bool = False,
    corroborating_source_types: list[str] | None = None,
    fresh_until: str | None = None,
    external_snapshots: list[dict[str, Any]] | None = None,
) -> str:
    """Append one governed workflow observation and optional external snapshots.

    The tool derives ``workflowVersion``, ``lineageId``, and the idempotency key
    from the local immutable proposal bundle so the model does not invent those
    fields. External web snapshots are evidence only and cannot self-authorize a
    release.

    Args:
        workflow_id: Registered CloudMold Skill workflow identifier.
        proposal_id: Managed immutable proposal identifier returned by
            ``workflow_manage(create_proposal)``.
        source_type: One of USER_BEHAVIOR, SYSTEM_RUN, SYSTEM_LOG, BUSINESS_KPI,
            DQC, APPROVAL, WORK_ORDER, or EXTERNAL_WEB.
        headline: Short evidence title.
        detail_text: Redacted evidence detail text.
        severity: One of INFO, LOW, MEDIUM, HIGH, or CRITICAL.
        dqc_status: One of PASS, WARN, FAIL, UNKNOWN, or NOT_APPLICABLE.
        status: One of CAPTURED, CONFIRMED, STALE, or REJECTED.
        observed_at: ISO-8601 evidence timestamp.
        window_start: Inclusive ISO-8601 evidence window start.
        window_end: Exclusive ISO-8601 evidence window end.
        evidence_ref: Optional safe opaque evidence reference.
        summary_source_refs: Optional safe source-reference list.
        model_summary: Optional redacted model summary.
        metrics: Optional JSON object of derived metrics.
        release_eligible: Whether this record can support release decisions.
        corroborating_source_types: Optional supporting source types when
            ``release_eligible`` is true.
        fresh_until: Optional ISO-8601 freshness-expiry datetime.
        external_snapshots: Optional list of up to 3 structured external-web
            snapshots. Each item may include ``url``, ``published_at``,
            ``fetched_at``, ``summary``, either ``content_hash_sha256`` or bounded
            ``content_digest_material`` (hashed locally and never persisted), ``source_class``,
            ``confidence``, ``region``, ``applicability``, ``severity``,
            ``dqc_status``, ``status``, ``fresh_until``, ``window_start``, and
            ``window_end``.
    """
    result = await _ingest_workflow_evidence(
        runtime=runtime,
        workflow_id=workflow_id,
        proposal_id=proposal_id,
        source_type=source_type,
        headline=headline,
        detail_text=detail_text,
        severity=severity,
        dqc_status=dqc_status,
        status=status,
        observed_at=observed_at,
        window_start=window_start,
        window_end=window_end,
        evidence_ref=evidence_ref,
        summary_source_refs=summary_source_refs,
        model_summary=model_summary,
        metrics=metrics,
        release_eligible=release_eligible,
        corroborating_source_types=corroborating_source_types,
        fresh_until=fresh_until,
        external_snapshots=external_snapshots,
    )
    return json.dumps(result, ensure_ascii=False, sort_keys=True)


@tool(parse_docstring=True)
async def workflow_problem_report(
    workflow_id: str,
    proposal_id: str,
    source_type: str,
    headline: str,
    problem_detail: str,
    severity: str,
    dqc_status: str,
    status: str,
    observed_at: str,
    window_start: str,
    window_end: str,
    runtime: Runtime,
    evidence_ref: str | None = None,
    summary_source_refs: list[str] | None = None,
    model_summary: str | None = None,
    metrics: dict[str, Any] | None = None,
    release_eligible: bool = False,
    corroborating_source_types: list[str] | None = None,
    fresh_until: str | None = None,
) -> str:
    """Append one governed workflow problem record tied to a local proposal.

    Args:
        workflow_id: Registered CloudMold Skill workflow identifier.
        proposal_id: Managed immutable proposal identifier returned by
            ``workflow_manage(create_proposal)``.
        source_type: One of USER_BEHAVIOR, SYSTEM_RUN, SYSTEM_LOG, BUSINESS_KPI,
            DQC, APPROVAL, WORK_ORDER, or EXTERNAL_WEB.
        headline: Short problem title.
        problem_detail: Redacted problem detail text.
        severity: One of INFO, LOW, MEDIUM, HIGH, or CRITICAL.
        dqc_status: One of PASS, WARN, FAIL, UNKNOWN, or NOT_APPLICABLE.
        status: One of OPEN, ACKNOWLEDGED, MITIGATED, or DISMISSED.
        observed_at: ISO-8601 problem timestamp.
        window_start: Inclusive ISO-8601 evidence window start.
        window_end: Exclusive ISO-8601 evidence window end.
        evidence_ref: Optional safe opaque evidence reference.
        summary_source_refs: Optional safe source-reference list.
        model_summary: Optional redacted model summary.
        metrics: Optional JSON object of derived metrics.
        release_eligible: Whether this record can support release decisions.
        corroborating_source_types: Optional supporting source types when
            ``release_eligible`` is true.
        fresh_until: Optional ISO-8601 freshness-expiry datetime.
    """
    result = await _record_workflow_problem(
        runtime=runtime,
        workflow_id=workflow_id,
        proposal_id=proposal_id,
        source_type=source_type,
        headline=headline,
        problem_detail=problem_detail,
        severity=severity,
        dqc_status=dqc_status,
        status=status,
        observed_at=observed_at,
        window_start=window_start,
        window_end=window_end,
        evidence_ref=evidence_ref,
        summary_source_refs=summary_source_refs,
        model_summary=model_summary,
        metrics=metrics,
        release_eligible=release_eligible,
        corroborating_source_types=corroborating_source_types,
        fresh_until=fresh_until,
    )
    return json.dumps(result, ensure_ascii=False, sort_keys=True)


@tool(parse_docstring=True)
async def workflow_feedback_report(
    workflow_id: str,
    proposal_id: str,
    source_type: str,
    feedback_type: str,
    feedback_label: str,
    feedback_text: str,
    severity: str,
    dqc_status: str,
    status: str,
    observed_at: str,
    window_start: str,
    window_end: str,
    runtime: Runtime,
    evidence_ref: str | None = None,
    summary_source_refs: list[str] | None = None,
    model_summary: str | None = None,
    metrics: dict[str, Any] | None = None,
    release_eligible: bool = False,
    corroborating_source_types: list[str] | None = None,
    fresh_until: str | None = None,
) -> str:
    """Append one governed workflow feedback record tied to a local proposal.

    Args:
        workflow_id: Registered CloudMold Skill workflow identifier.
        proposal_id: Managed immutable proposal identifier returned by
            ``workflow_manage(create_proposal)``.
        source_type: One of USER_BEHAVIOR, SYSTEM_RUN, SYSTEM_LOG, BUSINESS_KPI,
            DQC, APPROVAL, WORK_ORDER, or EXTERNAL_WEB.
        feedback_type: One of USER_FEEDBACK, APPROVAL_NOTE, RELEASE_SIGNAL, or
            BUSINESS_REVIEW.
        feedback_label: Short feedback label.
        feedback_text: Redacted feedback text.
        severity: One of INFO, LOW, MEDIUM, HIGH, or CRITICAL.
        dqc_status: One of PASS, WARN, FAIL, UNKNOWN, or NOT_APPLICABLE.
        status: One of RECEIVED, ACKNOWLEDGED, APPLIED, or REJECTED.
        observed_at: ISO-8601 feedback timestamp.
        window_start: Inclusive ISO-8601 evidence window start.
        window_end: Exclusive ISO-8601 evidence window end.
        evidence_ref: Optional safe opaque evidence reference.
        summary_source_refs: Optional safe source-reference list.
        model_summary: Optional redacted model summary.
        metrics: Optional JSON object of derived metrics.
        release_eligible: Whether this record can support release decisions.
        corroborating_source_types: Optional supporting source types when
            ``release_eligible`` is true.
        fresh_until: Optional ISO-8601 freshness-expiry datetime.
    """
    result = await _record_workflow_feedback(
        runtime=runtime,
        workflow_id=workflow_id,
        proposal_id=proposal_id,
        source_type=source_type,
        feedback_type=feedback_type,
        feedback_label=feedback_label,
        feedback_text=feedback_text,
        severity=severity,
        dqc_status=dqc_status,
        status=status,
        observed_at=observed_at,
        window_start=window_start,
        window_end=window_end,
        evidence_ref=evidence_ref,
        summary_source_refs=summary_source_refs,
        model_summary=model_summary,
        metrics=metrics,
        release_eligible=release_eligible,
        corroborating_source_types=corroborating_source_types,
        fresh_until=fresh_until,
    )
    return json.dumps(result, ensure_ascii=False, sort_keys=True)


__all__ = [
    "workflow_evidence_digest",
    "workflow_evidence_ingest",
    "workflow_evidence_timeline",
    "workflow_definition_get",
    "workflow_feedback_report",
    "workflow_governance_list",
    "workflow_governance_status",
    "workflow_observation_get",
    "workflow_problem_report",
    "workflow_proposal_status",
    "workflow_proposal_submit",
    "workflow_validation_start",
    "_canonical_bytes",
    "_sha256",
]
