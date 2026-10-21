#!/usr/bin/env python3
"""Independent, read-only G3 evidence reviewer.

This repository is intentionally a consumer of already-produced evidence.  It
does not call WebAuthn, KMS, Cloudflare, D1, GitHub APIs, or any production
resource.  A PASS is only a non-authorizing provenance record; G3 issuance is
owned by the Harness and remains outside this repository.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


SCHEMA = "orchestration.g3-independent-reviewer-provenance.v1"
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,199}\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_HEAD = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_MAX_WINDOW = timedelta(hours=24)

_SECRET_KEYS = {
    "api_key",
    "api_token",
    "access_token",
    "authorization",
    "credential",
    "credentials",
    "password",
    "private_key",
    "private_key_material",
    "secret",
    "token",
}
_SAFE_ABSENCE_KEYS = {
    "access_token_present",
    "access_token_export",
    "private_key_export",
    "private_key_in_harness_or_evidence",
    "private_key_present",
    "token_present",
}


class ReviewError(ValueError):
    """A fail-closed review input error represented by a stable blocker code."""


def _canonical(payload: Mapping[str, Any]) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def reviewer_record_digest(record: Mapping[str, Any]) -> str:
    """Return the digest over the review record without its self field."""
    if not isinstance(record, Mapping):
        raise ReviewError("REVIEW_MAPPING_REQUIRED")
    unsigned = {key: value for key, value in record.items() if key != "review_digest"}
    return hashlib.sha256(_canonical(unsigned)).hexdigest()


def _is_false_absence_key(key: str, value: object) -> bool:
    return key in _SAFE_ABSENCE_KEYS and value is False


def _reject_secrets(value: object) -> None:
    if isinstance(value, Mapping):
        for raw_key, child in value.items():
            key = str(raw_key).lower().replace("-", "_")
            sensitive = (
                key in _SECRET_KEYS
                or "private_key" in key
                or "access_token" in key
                or key == "token"
            )
            if sensitive and not _is_false_absence_key(key, child):
                raise ReviewError("SECRET_IN_EVIDENCE")
            _reject_secrets(child)
    elif isinstance(value, list):
        for child in value:
            _reject_secrets(child)


def _id(value: object, label: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise ReviewError(f"{label.upper()}_INVALID")
    return value


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        raise ReviewError(f"{label.upper()}_DIGEST_INVALID")
    return value


def _head(value: object, label: str) -> str:
    if not isinstance(value, str) or not _HEAD.fullmatch(value):
        raise ReviewError(f"{label.upper()}_INVALID")
    return value


def _time(value: object, label: str) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str) and value.endswith("Z"):
        try:
            parsed = datetime.fromisoformat(value[:-1] + "+00:00")
        except ValueError as exc:
            raise ReviewError(f"{label.upper()}_INVALID") from exc
    else:
        raise ReviewError(f"{label.upper()}_INVALID")
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ReviewError(f"{label.upper()}_INVALID")
    return parsed.astimezone(timezone.utc)


def _wire_time(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _mapping(value: object, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ReviewError(f"{label.upper()}_MAPPING_REQUIRED")
    return value


def _required(mapping: Mapping[str, Any], key: str, label: str | None = None) -> Any:
    if key not in mapping:
        raise ReviewError(f"{(label or key).upper()}_MISSING")
    return mapping[key]


def _contract_binding(g3: Mapping[str, Any], release: Mapping[str, Any]) -> dict[str, str]:
    if g3.get("gate_id") != "G3":
        raise ReviewError("G3_GATE_REQUIRED")
    if g3.get("execution_mode") != "FULL_PLAN_HYBRID" or g3.get("gate_by_gate") is not False:
        raise ReviewError("FULL_PLAN_HYBRID_REQUIRED")

    project_id = _id(_required(g3, "project_id"), "project_id")
    task_id = _id(_required(g3, "task_id"), "task_id")
    del task_id
    plan_sha256 = _digest(_required(g3, "plan_sha256"), "plan_sha256")
    requirements_sha256 = _digest(_required(g3, "requirements_sha256"), "requirements_sha256")
    expected_head = _head(_required(g3, "expected_head"), "expected_head")

    release = _mapping(release, "runtime_release")
    if release.get("project_id") != project_id:
        raise ReviewError("BINDING_MISMATCH:project_id")
    if release.get("gate_id") != "G3":
        raise ReviewError("BINDING_MISMATCH:gate_id")
    if release.get("execution_mode") != "FULL_PLAN_HYBRID" or release.get("gate_by_gate") is not False:
        raise ReviewError("FULL_PLAN_HYBRID_REQUIRED")
    if release.get("plan_sha256") != plan_sha256:
        raise ReviewError("BINDING_MISMATCH:plan_sha256")
    if release.get("requirements_sha256", requirements_sha256) != requirements_sha256:
        raise ReviewError("BINDING_MISMATCH:requirements_sha256")
    if g3.get("expected_branch") is not None and release.get("branch") != g3.get("expected_branch"):
        raise ReviewError("BINDING_MISMATCH:branch")
    if g3.get("contract_digest_sha256") is not None and release.get("contract_sha256") != g3.get("contract_digest_sha256"):
        raise ReviewError("BINDING_MISMATCH:contract_sha256")
    source_head = _head(_required(release, "source_head"), "source_head")
    if source_head != expected_head:
        raise ReviewError("BINDING_MISMATCH:source_head")
    runtime_version_id = _id(_required(release, "runtime_version_id"), "runtime_version_id")
    release_digest = _digest(_required(release, "release_digest"), "release_digest")
    _digest(_required(release, "manifest_sha256"), "manifest_sha256")
    _head(_required(release, "artifact_commit"), "artifact_commit")
    if release.get("official_issue_allowed") is not False:
        raise ReviewError("OFFICIAL_ISSUE_FORBIDDEN")
    if release.get("runtime_current_activation") is not False:
        raise ReviewError("RUNTIME_CURRENT_FORBIDDEN")

    return {
        "project_id": project_id,
        "gate_id": "G3",
        "plan_sha256": plan_sha256,
        "requirements_sha256": requirements_sha256,
        "source_head": source_head,
        "runtime_version_id": runtime_version_id,
        "release_digest": release_digest,
    }


def _check_readback(
    readback: Mapping[str, Any],
    *,
    decision: str,
    binding: Mapping[str, str],
    g3: Mapping[str, Any],
) -> None:
    if readback.get("decision") != decision:
        raise ReviewError(f"{decision}_READBACK_REQUIRED")
    for field in (
        "schema_version",
        "ceremony_id",
        "challenge_id",
        "approval_id",
        "activation_id",
        "jti",
        "replay_nonce",
        "owner_actor_id",
        "issuer",
        "audience",
        "key_id",
        "algorithm",
        "key_custody",
    ):
        _id(readback.get(field), f"readback.{field}")
    for field in ("project_id", "gate_id", "runtime_version_id"):
        if readback.get(field) != binding[field]:
            raise ReviewError(f"BINDING_MISMATCH:{field}")
    for field in ("plan_sha256", "release_digest"):
        if readback.get(field) != binding[field]:
            raise ReviewError(f"BINDING_MISMATCH:{field}")
    if readback.get("source_head") != binding["source_head"]:
        raise ReviewError("BINDING_MISMATCH:source_head")
    if readback.get("task_id") is None:
        raise ReviewError("READBACK_TASK_ID_MISSING")
    if readback.get("schema_version") != "orchestration.g3-owner-approval-readback.v1":
        raise ReviewError("READBACK_SCHEMA_INVALID")
    origin = readback.get("origin")
    if not isinstance(origin, str) or not origin.startswith("https://"):
        raise ReviewError("READBACK_ORIGIN_INVALID")
    if readback.get("challenge_consumed") is not True:
        raise ReviewError("CHALLENGE_NOT_CONSUMED")
    if readback.get("user_verification") is not True:
        raise ReviewError("USER_VERIFICATION_REQUIRED")
    if readback.get("signature_valid") is not True:
        raise ReviewError("SIGNATURE_INVALID")
    if readback.get("algorithm") != "EdDSA":
        raise ReviewError("EDDSA_REQUIRED")
    if readback.get("key_custody") != "KMS_ONLY":
        raise ReviewError("KMS_ONLY_REQUIRED")
    if readback.get("issuer") != "google-cloud-kms":
        raise ReviewError("GOOGLE_KMS_REQUIRED")
    if readback.get("audience") != "ai-office-harness":
        raise ReviewError("AUDIENCE_MISMATCH")
    jws_contract = g3.get("jws_contract")
    if isinstance(jws_contract, Mapping):
        expected_key_id = jws_contract.get("key_id_pin")
        if expected_key_id is not None and readback.get("key_id") != expected_key_id:
            raise ReviewError("KMS_KEY_PIN_MISMATCH")
    if decision == "APPROVE" and readback.get("revoked") is not False:
        raise ReviewError("APPROVE_MUST_BE_ACTIVE")
    if decision == "REJECT" and readback.get("revoked") is not True:
        raise ReviewError("REJECT_MUST_BE_REVOKED")
    _time(readback.get("issued_at"), "readback.issued_at")
    _time(readback.get("expires_at"), "readback.expires_at")


def _check_bundle(bundle: Mapping[str, Any], binding: Mapping[str, str], g3: Mapping[str, Any]) -> None:
    if bundle.get("status") != "PREFLIGHT_PASS":
        raise ReviewError("READBACK_EVIDENCE_INCOMPLETE")
    if not isinstance(bundle.get("readbacks"), Mapping):
        raise ReviewError("READBACK_EVIDENCE_INCOMPLETE")
    if bundle.get("scope") != "LOCAL_READ_ONLY_STAGING_PREFLIGHT":
        raise ReviewError("READBACK_SCOPE_INVALID")
    source_sha256 = _mapping(bundle.get("source_sha256"), "source_sha256")
    for side in ("approve", "reject"):
        side_digests = _mapping(source_sha256.get(side), f"source_sha256.{side}")
        for field in ("expected", "webauthn", "d1", "kms"):
            _digest(_required(side_digests, field, f"source_sha256.{side}.{field}"), f"source_sha256.{side}.{field}")
    if bundle.get("mutation_performed") is not False:
        raise ReviewError("READBACK_MUTATION_FORBIDDEN")
    if bundle.get("official_issue_allowed") is not False:
        raise ReviewError("OFFICIAL_ISSUE_FORBIDDEN")
    readbacks = _mapping(bundle.get("readbacks"), "readbacks")
    approve = _mapping(readbacks.get("approve"), "approve_readback")
    reject = _mapping(readbacks.get("reject"), "reject_readback")
    _check_readback(approve, decision="APPROVE", binding=binding, g3=g3)
    _check_readback(reject, decision="REJECT", binding=binding, g3=g3)
    for left, right in (("ceremony_id", "ceremony_id"), ("challenge_id", "challenge_id"), ("jti", "jti"), ("replay_nonce", "replay_nonce")):
        if approve.get(left) == reject.get(right):
            raise ReviewError(f"READBACK_IDENTITIES_NOT_DISTINCT:{left}")
    for side in ("approve", "reject"):
        d1 = _mapping(_mapping(bundle.get("d1"), "d1").get(side), f"d1.{side}")
        if d1.get("rows_written") != 0 or d1.get("changed_db") is not False:
            raise ReviewError(f"D1_MUTATION_DETECTED:{side}")
        kms = _mapping(_mapping(bundle.get("kms"), "kms").get(side), f"kms.{side}")
        if kms.get("private_key_present") is not False or kms.get("token_present") is not False:
            raise ReviewError(f"KMS_SECRET_ATTESTATION_FAILED:{side}")


def _make_result(
    *,
    decision: str,
    blockers: list[str],
    binding: Mapping[str, str] | None,
    reviewer_id: str,
    reviewer_process_id: str,
    implementation_actor_id: str,
    issuer_actor_id: str,
    repository: str,
    workflow_path: str,
    workflow_source_sha256: str,
    review_run_id: str,
    evidence_bundle_sha256: str,
    reviewed_at: datetime,
    expires_at: datetime,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "schema_version": SCHEMA,
        "status": "PASS" if decision == "PASS" else "REVIEW_BLOCKED",
        "decision": decision,
        "reviewer_id": reviewer_id,
        "reviewer_process_id": reviewer_process_id,
        "implementation_actor_id": implementation_actor_id,
        "issuer_actor_id": issuer_actor_id,
        "repository": repository,
        "workflow_path": workflow_path,
        "workflow_source_sha256": workflow_source_sha256,
        "review_run_id": review_run_id,
        "evidence_bundle_sha256": evidence_bundle_sha256,
        "reviewed_at": _wire_time(reviewed_at),
        "expires_at": _wire_time(expires_at),
        "project_id": binding.get("project_id") if binding else None,
        "gate_id": binding.get("gate_id") if binding else None,
        "plan_sha256": binding.get("plan_sha256") if binding else None,
        "source_head": binding.get("source_head") if binding else None,
        "runtime_version_id": binding.get("runtime_version_id") if binding else None,
        "release_digest": binding.get("release_digest") if binding else None,
        "issue_authority": False,
        "mutation_performed": False,
        "official_issue_allowed": False,
    }
    # Diagnostics are useful for a blocked run but are intentionally omitted
    # from PASS records so PASS remains exactly consumable by the Harness
    # provenance contract.
    if blockers:
        result["blockers"] = list(dict.fromkeys(blockers))
    result["review_digest"] = reviewer_record_digest(result)
    return result


def review_evidence(
    *,
    g3: Mapping[str, Any],
    readback_bundle: Mapping[str, Any],
    runtime_release: Mapping[str, Any],
    reviewer_id: str,
    implementation_actor_id: str,
    issuer_actor_id: str,
    repository: str,
    workflow_path: str,
    workflow_source_sha256: str,
    evidence_bundle_sha256: str,
    reviewed_at: datetime | str,
    expires_at: datetime | str,
    now: datetime | str,
    reviewer_process_id: str = "independent-g3-reviewer",
    review_run_id: str | None = None,
) -> dict[str, Any]:
    """Review a complete evidence bundle without performing external actions."""
    blockers: list[str] = []
    binding: dict[str, str] | None = None
    try:
        _reject_secrets({"g3": g3, "readback_bundle": readback_bundle, "runtime_release": runtime_release})
    except ReviewError as exc:
        blockers.append(str(exc))

    def check(code: str, fn: Any) -> None:
        try:
            fn()
        except (ReviewError, TypeError, AttributeError, KeyError) as exc:
            blockers.append(str(exc) or code)

    check("REVIEWER_ID_INVALID", lambda: _id(reviewer_id, "reviewer_id"))
    check("IMPLEMENTATION_ACTOR_ID_INVALID", lambda: _id(implementation_actor_id, "implementation_actor_id"))
    check("ISSUER_ACTOR_ID_INVALID", lambda: _id(issuer_actor_id, "issuer_actor_id"))
    if reviewer_id == implementation_actor_id or reviewer_id == issuer_actor_id or implementation_actor_id == issuer_actor_id:
        blockers.append("REVIEWER_IDENTITY_SEPARATION_REQUIRED")
    if not isinstance(repository, str) or not repository.startswith("https://"):
        blockers.append("REVIEWER_REPOSITORY_INVALID")
    if not isinstance(workflow_path, str) or not workflow_path.startswith(".github/workflows/"):
        blockers.append("REVIEWER_WORKFLOW_INVALID")
    check("WORKFLOW_SOURCE_DIGEST_INVALID", lambda: _digest(workflow_source_sha256, "workflow_source_sha256"))
    check("EVIDENCE_BUNDLE_DIGEST_INVALID", lambda: _digest(evidence_bundle_sha256, "evidence_bundle_sha256"))
    try:
        reviewed = _time(reviewed_at, "reviewed_at")
        expires = _time(expires_at, "expires_at")
        current = _time(now, "now")
        if expires <= current or expires <= reviewed or expires - reviewed > _MAX_WINDOW:
            blockers.append("REVIEW_WINDOW_INVALID")
        if reviewed > current + timedelta(seconds=60):
            blockers.append("REVIEWED_AT_IN_FUTURE")
    except ReviewError as exc:
        blockers.append(str(exc))
        reviewed = datetime.now(timezone.utc)
        expires = reviewed

    try:
        binding = _contract_binding(_mapping(g3, "g3"), _mapping(runtime_release, "runtime_release"))
    except ReviewError as exc:
        blockers.append(str(exc))

    if binding is not None:
        try:
            _check_bundle(_mapping(readback_bundle, "readback_bundle"), binding, _mapping(g3, "g3"))
        except ReviewError as exc:
            blockers.append(str(exc))
    else:
        blockers.append("READBACK_EVIDENCE_INCOMPLETE")

    if review_run_id is None:
        review_run_id = f"review-{workflow_source_sha256[:12]}"
    # These are validated even for NO-GO so malformed provenance cannot look
    # like a usable reviewer result.
    for value, label in (
        (reviewer_process_id, "reviewer_process_id"),
        (review_run_id, "review_run_id"),
    ):
        check(f"{label.upper()}_INVALID", lambda value=value, label=label: _id(value, label))

    decision = "PASS" if not blockers else "NO-GO"
    return _make_result(
        decision=decision,
        blockers=blockers,
        binding=binding,
        reviewer_id=reviewer_id if isinstance(reviewer_id, str) else "invalid-reviewer",
        reviewer_process_id=reviewer_process_id if isinstance(reviewer_process_id, str) else "invalid-process",
        implementation_actor_id=implementation_actor_id if isinstance(implementation_actor_id, str) else "invalid-implementation",
        issuer_actor_id=issuer_actor_id if isinstance(issuer_actor_id, str) else "invalid-issuer",
        repository=repository if isinstance(repository, str) else "invalid-repository",
        workflow_path=workflow_path if isinstance(workflow_path, str) else "invalid-workflow",
        workflow_source_sha256=workflow_source_sha256 if isinstance(workflow_source_sha256, str) else "0" * 64,
        review_run_id=review_run_id if isinstance(review_run_id, str) else "invalid-run",
        evidence_bundle_sha256=evidence_bundle_sha256 if isinstance(evidence_bundle_sha256, str) else "0" * 64,
        reviewed_at=reviewed,
        expires_at=expires,
    )


def _load(path: str) -> Mapping[str, Any]:
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ReviewError("INPUT_JSON_INVALID") from exc
    return _mapping(value, "input")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Read-only independent G3 evidence reviewer")
    parser.add_argument("--g3", required=True)
    parser.add_argument("--readback-bundle", required=True)
    parser.add_argument("--runtime-release", required=True)
    parser.add_argument("--reviewer-id", required=True)
    parser.add_argument("--reviewer-process-id", default="independent-g3-reviewer")
    parser.add_argument("--implementation-actor-id", required=True)
    parser.add_argument("--issuer-actor-id", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--workflow-path", required=True)
    parser.add_argument("--workflow-source-sha256", required=True)
    parser.add_argument("--review-run-id")
    parser.add_argument("--evidence-bundle-sha256", required=True)
    parser.add_argument("--reviewed-at", required=True)
    parser.add_argument("--expires-at", required=True)
    parser.add_argument("--now", required=True)
    parser.add_argument("--output", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = review_evidence(
            g3=_load(args.g3),
            readback_bundle=_load(args.readback_bundle),
            runtime_release=_load(args.runtime_release),
            reviewer_id=args.reviewer_id,
            reviewer_process_id=args.reviewer_process_id,
            implementation_actor_id=args.implementation_actor_id,
            issuer_actor_id=args.issuer_actor_id,
            repository=args.repository,
            workflow_path=args.workflow_path,
            workflow_source_sha256=args.workflow_source_sha256,
            review_run_id=args.review_run_id,
            evidence_bundle_sha256=args.evidence_bundle_sha256,
            reviewed_at=args.reviewed_at,
            expires_at=args.expires_at,
            now=args.now,
        )
    except ReviewError as exc:
        result = {
            "schema_version": SCHEMA,
            "status": "REVIEW_BLOCKED",
            "decision": "NO-GO",
            "blockers": [str(exc)],
            "issue_authority": False,
            "mutation_performed": False,
            "official_issue_allowed": False,
        }
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result.get("decision") == "PASS" else 10


if __name__ == "__main__":
    sys.exit(main())
