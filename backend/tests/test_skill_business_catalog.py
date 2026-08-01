from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.gateway import internal_auth
from app.gateway.auth_middleware import AuthMiddleware
from app.gateway.deps import get_config
from app.gateway.routers import skills as skills_router
from deerflow.skills.business_catalog import (
    BusinessCatalogError,
    build_business_skill_catalog,
    read_business_skill_content,
)
from deerflow.skills.storage.local_skill_storage import LocalSkillStorage


def _write_skill(root: Path, name: str, description: str = "Demo skill") -> None:
    skill_dir = root / "public" / name
    skill_dir.mkdir(parents=True, exist_ok=True)
    (skill_dir / "SKILL.md").write_text(
        f"---\nname: {name}\ndescription: {description}\nmetadata:\n  cloudmold:\n    schema_version: 1\n---\n\n# {name}\n\nBody.\n",
        encoding="utf-8",
    )


def _write_taxonomy(root: Path) -> None:
    (root / "public" / "business-taxonomy.json").write_text(
        json.dumps(
            {
                "schema_version": "cloudmold.skill-business-taxonomy/v1",
                "business_units": [
                    {"code": "dewu", "name": "得物", "status": "ACTIVE", "order": 10},
                    {"code": "fashion88", "name": "Fashion88", "status": "PLANNED", "order": 20},
                    {"code": "cloudmold-shared", "name": "共享平台", "status": "ACTIVE", "order": 90},
                ],
                "domains": [
                    {"code": "merchant", "name": "商家域", "order": 10},
                    {"code": "platform", "name": "平台域", "order": 90},
                ],
                "roles": [
                    {"code": "merchant-operator", "name": "商家运营", "domain_code": "merchant", "order": 10},
                    {"code": "shared", "name": "通用能力", "domain_code": "platform", "order": 10},
                ],
                "skill_assignments": [{"business_unit_code": "dewu", "role_code": "merchant-operator", "skill_name": "merchant-skill"}],
                "fallback_assignment": {
                    "business_unit_code": "cloudmold-shared",
                    "role_code": "shared",
                },
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )


def test_build_catalog_groups_runtime_skills_and_keeps_planned_unit(tmp_path: Path) -> None:
    root = tmp_path / "skills"
    (root / "public").mkdir(parents=True)
    _write_skill(root, "merchant-skill")
    _write_skill(root, "platform-skill")
    _write_taxonomy(root)
    storage = LocalSkillStorage(host_path=str(root))

    catalog = build_business_skill_catalog(storage)

    assert catalog["skill_count"] == 2
    assert catalog["assigned_skill_count"] == 2
    assert len(catalog["catalog_sha256"]) == 64
    units = {item["code"]: item for item in catalog["business_units"]}
    assert units["dewu"]["domains"][0]["roles"][0]["skills"][0]["name"] == "merchant-skill"
    assert units["cloudmold-shared"]["domains"][0]["roles"][0]["skills"][0]["name"] == "platform-skill"
    assert units["fashion88"]["skill_count"] == 0
    assert units["fashion88"]["domains"] == []


def test_content_response_externalizes_public_skill_without_host_path(tmp_path: Path) -> None:
    root = tmp_path / "skills"
    (root / "public").mkdir(parents=True)
    _write_skill(root, "merchant-skill", "Operate merchants")
    _write_taxonomy(root)
    storage = LocalSkillStorage(host_path=str(root))

    detail = read_business_skill_content(storage, "merchant-skill")

    assert detail["name"] == "merchant-skill"
    assert detail["description"] == "Operate merchants"
    assert detail["body"].startswith("# merchant-skill")
    assert detail["content"].startswith("---")
    assert detail["metadata"]["cloudmold"]["schema_version"] == 1
    assert len(detail["content_sha256"]) == 64
    assert str(tmp_path) not in json.dumps(detail)


def test_catalog_keeps_public_skill_when_custom_skill_uses_same_name(tmp_path: Path) -> None:
    root = tmp_path / "skills"
    (root / "public").mkdir(parents=True)
    _write_skill(root, "merchant-skill", "Public merchant operations")
    custom = root / "custom" / "merchant-skill"
    custom.mkdir(parents=True)
    (custom / "SKILL.md").write_text(
        "---\nname: merchant-skill\ndescription: Private shadow\n---\n\nPrivate.\n",
        encoding="utf-8",
    )
    _write_taxonomy(root)

    detail = read_business_skill_content(LocalSkillStorage(host_path=str(root)), "merchant-skill")

    assert detail["description"] == "Public merchant operations"
    assert "Private shadow" not in detail["content"]


def test_content_rejects_host_absolute_paths(tmp_path: Path) -> None:
    root = tmp_path / "skills"
    (root / "public").mkdir(parents=True)
    _write_skill(root, "merchant-skill")
    skill_file = root / "public" / "merchant-skill" / "SKILL.md"
    skill_file.write_text(skill_file.read_text(encoding="utf-8") + "\n/Users/example/private/workspace\n", encoding="utf-8")
    _write_taxonomy(root)

    with pytest.raises(BusinessCatalogError, match="host-local absolute path"):
        read_business_skill_content(LocalSkillStorage(host_path=str(root)), "merchant-skill")


def test_content_rejects_custom_skills_and_invalid_names(tmp_path: Path) -> None:
    root = tmp_path / "skills"
    (root / "public").mkdir(parents=True)
    _write_taxonomy(root)
    custom = root / "custom" / "private-skill"
    custom.mkdir(parents=True)
    (custom / "SKILL.md").write_text(
        "---\nname: private-skill\ndescription: Private\n---\nsecret",
        encoding="utf-8",
    )
    storage = LocalSkillStorage(host_path=str(root))

    with pytest.raises(BusinessCatalogError, match="not found"):
        read_business_skill_content(storage, "private-skill")
    with pytest.raises(BusinessCatalogError, match="hyphen-case"):
        read_business_skill_content(storage, "../merchant-skill")


def test_invalid_taxonomy_fails_closed(tmp_path: Path) -> None:
    root = tmp_path / "skills"
    (root / "public").mkdir(parents=True)
    _write_skill(root, "merchant-skill")
    (root / "public" / "business-taxonomy.json").write_text("{}", encoding="utf-8")

    with pytest.raises(BusinessCatalogError, match="schema_version"):
        build_business_skill_catalog(LocalSkillStorage(host_path=str(root)))


def test_read_only_business_catalog_api_returns_grouping_content_and_etag(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / "skills"
    (root / "public").mkdir(parents=True)
    _write_skill(root, "merchant-skill")
    _write_taxonomy(root)
    storage = LocalSkillStorage(host_path=str(root))
    app = FastAPI()

    @app.get("/api/private")
    async def private_route() -> dict[str, bool]:
        return {"ok": True}

    app.add_middleware(AuthMiddleware)
    app.dependency_overrides[get_config] = lambda: object()
    monkeypatch.setattr(skills_router, "_get_user_skill_storage", lambda _config: storage)
    monkeypatch.setattr(internal_auth, "_SKILL_CATALOG_AUTH_TOKEN", "catalog-read-token")
    app.include_router(skills_router.router)

    with TestClient(app) as client:
        headers = {"X-DeerFlow-Skill-Catalog-Token": "catalog-read-token"}
        unauthenticated_response = client.get("/api/skills/business-catalog")
        out_of_scope_response = client.get("/api/private", headers=headers)
        catalog_response = client.get("/api/skills/business-catalog", headers=headers)
        detail_response = client.get("/api/skills/business-catalog/merchant-skill", headers=headers)
        missing_response = client.get("/api/skills/business-catalog/missing-skill", headers=headers)

    assert unauthenticated_response.status_code == 401
    assert out_of_scope_response.status_code == 401
    assert catalog_response.status_code == 200
    assert catalog_response.json()["business_units"][0]["name"] == "得物"
    assert catalog_response.headers["etag"].startswith('"')
    assert detail_response.status_code == 200
    assert detail_response.json()["content"].startswith("---")
    assert detail_response.headers["etag"] == f'"{detail_response.json()["detail_sha256"]}"'
    assert missing_response.status_code == 404
