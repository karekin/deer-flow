"""Read-only CloudMold business taxonomy over the effective runtime skills."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import replace
from pathlib import Path
from typing import Any

from deerflow.skills.frontmatter import split_skill_markdown
from deerflow.skills.parser import parse_skill_file
from deerflow.skills.storage.skill_storage import SkillStorage
from deerflow.skills.types import Skill, SkillCategory

BUSINESS_TAXONOMY_FILE = "business-taxonomy.json"
BUSINESS_TAXONOMY_SCHEMA = "cloudmold.skill-business-taxonomy/v1"
_MAX_TAXONOMY_BYTES = 1_048_576
_MAX_SKILL_CONTENT_BYTES = 2_097_152
_CATALOG_CATEGORIES = {SkillCategory.PUBLIC.value, SkillCategory.INTEGRATION.value}
_HOST_LOCAL_PATH_RE = re.compile(r"(?:/Users/|/home/[^/\s]+/|/var/folders/|[A-Za-z]:\\\\Users\\\\)")


class BusinessCatalogError(ValueError):
    """Raised when the business catalog cannot be produced safely."""


class BusinessTaxonomyUnavailable(BusinessCatalogError):
    """Raised when the authoritative taxonomy cannot be loaded or validated."""


class BusinessSkillNotFound(BusinessCatalogError):
    """Raised when a requested public/integration Skill does not exist."""


class BusinessCatalogInvalidRequest(BusinessCatalogError):
    """Raised when a catalog request contains an invalid Skill name."""


class BusinessSkillContentUnsafe(BusinessCatalogError):
    """Raised when Skill content is unsafe to externalize."""


def _category_value(skill: Skill) -> str:
    value = skill.category
    return value.value if hasattr(value, "value") else str(value)


def _read_text(path: Path, *, limit: int, label: str) -> str:
    try:
        size = path.stat().st_size
    except FileNotFoundError as exc:
        error_type = BusinessTaxonomyUnavailable if label == "Business taxonomy" else BusinessCatalogError
        raise error_type(f"{label} not found") from exc
    if size > limit:
        raise BusinessCatalogError(f"{label} exceeds the {limit}-byte read limit")
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise BusinessCatalogError(f"Unable to read {label}") from exc


def _require_list(payload: dict[str, Any], key: str) -> list[dict[str, Any]]:
    value = payload.get(key)
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        raise BusinessTaxonomyUnavailable(f"Taxonomy field '{key}' must be a list of objects")
    return value


def _index_unique(items: list[dict[str, Any]], *, label: str) -> dict[str, dict[str, Any]]:
    indexed: dict[str, dict[str, Any]] = {}
    for item in items:
        code = item.get("code")
        if not isinstance(code, str) or not code.strip():
            raise BusinessTaxonomyUnavailable(f"Every {label} must have a non-empty code")
        if code in indexed:
            raise BusinessTaxonomyUnavailable(f"Duplicate {label} code '{code}'")
        indexed[code] = item
    return indexed


def _load_taxonomy(storage: SkillStorage) -> tuple[dict[str, Any], str]:
    taxonomy_path = storage.get_skills_root_path() / SkillCategory.PUBLIC.value / BUSINESS_TAXONOMY_FILE
    try:
        taxonomy_path = storage.validate_skill_file_path(taxonomy_path)
    except ValueError as exc:
        raise BusinessTaxonomyUnavailable("Taxonomy path escaped the configured skills root") from exc
    content = _read_text(taxonomy_path, limit=_MAX_TAXONOMY_BYTES, label="Business taxonomy")
    try:
        payload = json.loads(content)
    except json.JSONDecodeError as exc:
        raise BusinessTaxonomyUnavailable("Business taxonomy is not valid JSON") from exc
    if not isinstance(payload, dict):
        raise BusinessTaxonomyUnavailable("Business taxonomy must be a JSON object")
    if payload.get("schema_version") != BUSINESS_TAXONOMY_SCHEMA:
        raise BusinessTaxonomyUnavailable(f"Business taxonomy schema_version must be '{BUSINESS_TAXONOMY_SCHEMA}'")

    units = _index_unique(_require_list(payload, "business_units"), label="business unit")
    domains = _index_unique(_require_list(payload, "domains"), label="domain")
    roles = _index_unique(_require_list(payload, "roles"), label="role")
    assignments = _require_list(payload, "skill_assignments")
    fallback = payload.get("fallback_assignment")
    if not isinstance(fallback, dict):
        raise BusinessTaxonomyUnavailable("Taxonomy field 'fallback_assignment' must be an object")

    for role in roles.values():
        if role.get("domain_code") not in domains:
            raise BusinessTaxonomyUnavailable(f"Role '{role['code']}' references an unknown domain")
    for assignment in [*assignments, fallback]:
        if assignment.get("business_unit_code") not in units:
            raise BusinessTaxonomyUnavailable("Skill assignment references an unknown business unit")
        if assignment.get("role_code") not in roles:
            raise BusinessTaxonomyUnavailable("Skill assignment references an unknown role")
    for assignment in assignments:
        if not isinstance(assignment.get("skill_name"), str) or not assignment["skill_name"]:
            raise BusinessTaxonomyUnavailable("Every explicit skill assignment must have a skill_name")

    digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
    return payload, digest


def _effective_catalog_skills(storage: SkillStorage) -> dict[str, Skill]:
    """Discover governed categories before name de-duplication.

    User-scoped storage may contain a custom Skill with the same name as a
    public Skill. Filtering the already de-duplicated ``load_skills`` result
    would let that custom package hide the governed public source.
    """
    skills: dict[str, Skill] = {}
    for category, category_root, skill_file in storage._iter_skill_files():  # noqa: SLF001 - category-aware storage traversal
        category_value = category.value if hasattr(category, "value") else str(category)
        if category_value not in _CATALOG_CATEGORIES:
            continue
        skill = parse_skill_file(skill_file, category=category, relative_path=skill_file.parent.relative_to(category_root))
        if skill is None:
            continue
        if skill.name in skills:
            raise BusinessCatalogError(f"Duplicate governed Skill name '{skill.name}'")
        skills[skill.name] = skill

    try:
        from deerflow.config.extensions_config import ExtensionsConfig

        extensions = ExtensionsConfig.from_file()
        skills = {name: replace(skill, enabled=extensions.is_skill_enabled(skill.name, skill.category)) for name, skill in skills.items()}
    except Exception:
        # Match the runtime loader's availability behavior: parsing still works
        # when the optional enabled-state file is unavailable.
        pass
    return skills


def _skill_summary(storage: SkillStorage, skill: Skill) -> dict[str, Any]:
    try:
        skill_file = storage.validate_skill_file_path(skill.skill_file)
    except ValueError as exc:
        raise BusinessCatalogError(f"Skill '{skill.name}' resolved outside the configured skills root") from exc
    content = _read_text(skill_file, limit=_MAX_SKILL_CONTENT_BYTES, label=f"Skill '{skill.name}' content")
    return {
        "name": skill.name,
        "description": skill.description,
        "category": _category_value(skill),
        "enabled": skill.enabled,
        "content_sha256": hashlib.sha256(content.encode("utf-8")).hexdigest(),
    }


def _assignment_rows(taxonomy: dict[str, Any], skills: dict[str, Skill]) -> tuple[list[tuple[dict[str, Any], Skill]], list[str]]:
    explicit = taxonomy["skill_assignments"]
    explicit_names = {assignment["skill_name"] for assignment in explicit}
    rows = [(assignment, skills[assignment["skill_name"]]) for assignment in explicit if assignment["skill_name"] in skills]
    fallback = taxonomy["fallback_assignment"]
    rows.extend((fallback, skill) for name, skill in skills.items() if name not in explicit_names)
    missing = sorted(name for name in explicit_names if name not in skills)
    return rows, missing


def _classifications_for_skill(taxonomy: dict[str, Any], skill_name: str) -> list[dict[str, str]]:
    assignments = [item for item in taxonomy["skill_assignments"] if item["skill_name"] == skill_name]
    if not assignments:
        assignments = [taxonomy["fallback_assignment"]]
    units = {item["code"]: item for item in taxonomy["business_units"]}
    domains = {item["code"]: item for item in taxonomy["domains"]}
    roles = {item["code"]: item for item in taxonomy["roles"]}
    result = []
    for assignment in assignments:
        role = roles[assignment["role_code"]]
        domain = domains[role["domain_code"]]
        unit = units[assignment["business_unit_code"]]
        result.append(
            {
                "business_unit_code": unit["code"],
                "business_unit_name": unit["name"],
                "domain_code": domain["code"],
                "domain_name": domain["name"],
                "role_code": role["code"],
                "role_name": role["name"],
            }
        )
    return result


def build_business_skill_catalog(storage: SkillStorage) -> dict[str, Any]:
    """Build the three-level catalog from the effective public skill set."""
    taxonomy, taxonomy_sha256 = _load_taxonomy(storage)
    skills = _effective_catalog_skills(storage)
    rows, missing = _assignment_rows(taxonomy, skills)
    domains = {item["code"]: item for item in taxonomy["domains"]}
    roles = {item["code"]: item for item in taxonomy["roles"]}

    grouped: dict[str, dict[str, dict[str, list[dict[str, Any]]]]] = {}
    summaries = {name: _skill_summary(storage, skill) for name, skill in skills.items()}
    for assignment, skill in rows:
        role = roles[assignment["role_code"]]
        domain_code = role["domain_code"]
        unit_code = assignment["business_unit_code"]
        grouped.setdefault(unit_code, {}).setdefault(domain_code, {}).setdefault(role["code"], []).append(summaries[skill.name])

    unit_responses = []
    for unit in sorted(taxonomy["business_units"], key=lambda item: (item.get("order", 0), item["code"])):
        domain_responses = []
        for domain_code, role_map in grouped.get(unit["code"], {}).items():
            domain = domains[domain_code]
            role_responses = []
            for role_code, role_skills in role_map.items():
                role = roles[role_code]
                role_responses.append(
                    {
                        "code": role["code"],
                        "name": role["name"],
                        "order": role.get("order", 0),
                        "skill_count": len(role_skills),
                        "enabled_skill_count": sum(1 for item in role_skills if item["enabled"]),
                        "skills": sorted(role_skills, key=lambda item: item["name"]),
                    }
                )
            role_responses.sort(key=lambda item: (item["order"], item["code"]))
            domain_responses.append(
                {
                    "code": domain["code"],
                    "name": domain["name"],
                    "order": domain.get("order", 0),
                    "skill_count": sum(item["skill_count"] for item in role_responses),
                    "enabled_skill_count": sum(item["enabled_skill_count"] for item in role_responses),
                    "roles": role_responses,
                }
            )
        domain_responses.sort(key=lambda item: (item["order"], item["code"]))
        unit_responses.append(
            {
                "code": unit["code"],
                "name": unit["name"],
                "status": unit.get("status", "ACTIVE"),
                "order": unit.get("order", 0),
                "skill_count": sum(item["skill_count"] for item in domain_responses),
                "enabled_skill_count": sum(item["enabled_skill_count"] for item in domain_responses),
                "domains": domain_responses,
            }
        )

    stable_payload = {
        "schema_version": BUSINESS_TAXONOMY_SCHEMA,
        "taxonomy_sha256": taxonomy_sha256,
        "skill_count": len(skills),
        "enabled_skill_count": sum(1 for skill in skills.values() if skill.enabled),
        "assigned_skill_count": len(rows),
        "enabled_assigned_skill_count": sum(1 for _, skill in rows if skill.enabled),
        "missing_skill_names": missing,
        "business_units": unit_responses,
    }
    catalog_sha256 = hashlib.sha256(json.dumps(stable_payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    return {**stable_payload, "catalog_sha256": catalog_sha256}


def read_business_skill_content(storage: SkillStorage, skill_name: str) -> dict[str, Any]:
    """Read one effective public/integration SKILL.md without exposing a path."""
    try:
        normalized_name = storage.validate_skill_name(skill_name)
    except ValueError as exc:
        raise BusinessCatalogInvalidRequest(str(exc)) from exc
    taxonomy, taxonomy_sha256 = _load_taxonomy(storage)
    skill = _effective_catalog_skills(storage).get(normalized_name)
    if skill is None:
        raise BusinessSkillNotFound(f"Business skill '{normalized_name}' not found")
    try:
        skill_file = storage.validate_skill_file_path(skill.skill_file)
    except ValueError as exc:
        raise BusinessCatalogError(f"Skill '{normalized_name}' resolved outside the configured skills root") from exc
    content = _read_text(skill_file, limit=_MAX_SKILL_CONTENT_BYTES, label=f"Skill '{normalized_name}' content")
    if _HOST_LOCAL_PATH_RE.search(content):
        raise BusinessSkillContentUnsafe(f"Skill '{normalized_name}' contains a host-local absolute path")
    parts, error = split_skill_markdown(content)
    if parts is None:
        raise BusinessCatalogError(f"Skill '{normalized_name}' has invalid frontmatter: {error}")
    classifications = _classifications_for_skill(taxonomy, normalized_name)
    detail_sha256 = hashlib.sha256(
        json.dumps(
            {
                "classifications": classifications,
                "content_sha256": hashlib.sha256(content.encode("utf-8")).hexdigest(),
                "taxonomy_sha256": taxonomy_sha256,
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    return {
        **_skill_summary(storage, skill),
        "taxonomy_sha256": taxonomy_sha256,
        "detail_sha256": detail_sha256,
        "classifications": classifications,
        "metadata": parts.metadata.get("metadata", {}),
        "body": parts.body,
        "content": content,
    }
