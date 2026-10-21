from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from reviewer import review_evidence, reviewer_record_digest


PROJECT = "OCP-RDC-EXEC-CANARY-20260923-R2"
G3 = {
    "project_id": PROJECT,
    "gate_id": "G3",
    "task_id": "TASK-003",
    "execution_mode": "FULL_PLAN_HYBRID",
    "gate_by_gate": False,
    "plan_sha256": "a" * 64,
    "requirements_sha256": "1" * 64,
    "expected_branch": "main",
    "expected_head": "2c97006583c90dad35c80ecc42e516cc759cf977",
    "contract_digest_sha256": "2" * 64,
    "jws_contract": {"key_id_pin": "gcp-kms-ed25519-staging-v1"},
}
RELEASE = {
    "project_id": PROJECT,
    "gate_id": "G3",
    "execution_mode": "FULL_PLAN_HYBRID",
    "gate_by_gate": False,
    "plan_sha256": G3["plan_sha256"],
    "requirements_sha256": G3["requirements_sha256"],
    "branch": "main",
    "contract_sha256": G3["contract_digest_sha256"],
    "source_head": G3["expected_head"],
    "artifact_commit": G3["expected_head"],
    "runtime_version_id": "runtime-g3-isolated-reviewer",
    "release_digest": "b" * 64,
    "manifest_sha256": "c" * 64,
    "official_issue_allowed": False,
    "runtime_current_activation": False,
}


def _readback(decision: str, approval_id: str, revoked: bool) -> dict:
    return {
        "schema_version": "orchestration.g3-owner-approval-readback.v1",
        "ceremony_id": f"ceremony-{decision.lower()}",
        "challenge_consumed": True,
        "challenge_id": f"challenge-{decision.lower()}",
        "decision": decision,
        "origin": "https://owner.example.test",
        "owner_actor_id": "owner-ywjo",
        "user_verification": True,
        "approval_id": approval_id,
        "activation_id": f"activation-{decision.lower()}",
        "jti": f"jti-{decision.lower()}",
        "project_id": PROJECT,
        "task_id": "TASK-003",
        "gate_id": "G3",
        "replay_nonce": f"nonce-{decision.lower()}",
        "source_head": G3["expected_head"],
        "plan_sha256": G3["plan_sha256"],
        "runtime_version_id": RELEASE["runtime_version_id"],
        "release_digest": RELEASE["release_digest"],
        "issuer": "google-cloud-kms",
        "audience": "ai-office-harness",
        "key_id": "gcp-kms-ed25519-staging-v1",
        "algorithm": "EdDSA",
        "key_custody": "KMS_ONLY",
        "signature_valid": True,
        "revoked": revoked,
        "event_hash": "c" * 64 if revoked else None,
        "previous_event_hash": None,
        "revocation_version": 1 if revoked else 0,
        "issued_at": "2026-10-21T03:00:00Z",
        "expires_at": "2026-10-22T03:00:00Z",
    }


def _bundle() -> dict:
    return {
        "status": "PREFLIGHT_PASS",
        "scope": "LOCAL_READ_ONLY_STAGING_PREFLIGHT",
        "mutation_performed": False,
        "official_issue_allowed": False,
        "readbacks": {
            "approve": _readback("APPROVE", "approval-active", False),
            "reject": _readback("REJECT", "approval-revoked", True),
        },
        "d1": {
            "approve": {"rows_written": 0, "changed_db": False},
            "reject": {"rows_written": 0, "changed_db": False},
        },
        "kms": {
            "approve": {"private_key_present": False, "token_present": False},
            "reject": {"private_key_present": False, "token_present": False},
        },
        "source_sha256": {
            "approve": {field: "1" * 64 for field in ("expected", "webauthn", "d1", "kms")},
            "reject": {field: "2" * 64 for field in ("expected", "webauthn", "d1", "kms")},
        },
    }


def _review(**overrides):
    values = {
        "g3": G3,
        "readback_bundle": _bundle(),
        "runtime_release": RELEASE,
        "reviewer_id": "reviewer-ci",
        "implementation_actor_id": "implementation-process",
        "issuer_actor_id": "issuer-process",
        "repository": "https://github.com/ywjo86-tech/ai-office-independent-g3-reviewer",
        "workflow_path": ".github/workflows/g3-review.yml",
        "workflow_source_sha256": "d" * 64,
        "evidence_bundle_sha256": "e" * 64,
        "reviewed_at": datetime(2026, 10, 21, 4, 0, tzinfo=timezone.utc),
        "expires_at": datetime(2026, 10, 22, 3, 59, tzinfo=timezone.utc),
        "now": datetime(2026, 10, 21, 4, 1, tzinfo=timezone.utc),
    }
    values.update(overrides)
    return review_evidence(**values)


class ReviewerTests(unittest.TestCase):
    def test_complete_staging_bundle_produces_non_authorizing_pass(self):
        result = _review()

        self.assertEqual(result["decision"], "PASS")
        self.assertFalse(result["issue_authority"])
        self.assertFalse(result["mutation_performed"])
        self.assertFalse(result["official_issue_allowed"])
        self.assertEqual(result["project_id"], PROJECT)

    def test_missing_or_incomplete_evidence_produces_no_go(self):
        result = _review(readback_bundle={"status": "PREFLIGHT_PASS"})

        self.assertEqual(result["decision"], "NO-GO")
        self.assertIn("READBACK_EVIDENCE_INCOMPLETE", result["blockers"])

    def test_binding_drift_produces_no_go(self):
        result = _review(runtime_release={**RELEASE, "source_head": "f" * 40})

        self.assertEqual(result["decision"], "NO-GO")
        self.assertIn("BINDING_MISMATCH:source_head", result["blockers"])

    def test_reviewers_must_be_distinct(self):
        result = _review(implementation_actor_id="reviewer-ci")

        self.assertEqual(result["decision"], "NO-GO")
        self.assertIn("REVIEWER_IDENTITY_SEPARATION_REQUIRED", result["blockers"])

    def test_secrets_are_never_accepted(self):
        result = _review(readback_bundle={**_bundle(), "token": "secret"})

        self.assertEqual(result["decision"], "NO-GO")
        self.assertIn("SECRET_IN_EVIDENCE", result["blockers"])

    def test_digest_excludes_only_the_digest_field(self):
        result = _review()
        self.assertEqual(result["review_digest"], reviewer_record_digest(result))

    def test_pass_record_is_non_authorizing_boundary_shape(self):
        result = _review()
        self.assertNotIn("blockers", result)
        self.assertEqual(
            set(result),
            {
                "schema_version",
                "status",
                "decision",
                "reviewer_id",
                "reviewer_process_id",
                "implementation_actor_id",
                "issuer_actor_id",
                "repository",
                "workflow_path",
                "workflow_source_sha256",
                "review_run_id",
                "evidence_bundle_sha256",
                "reviewed_at",
                "expires_at",
                "project_id",
                "gate_id",
                "plan_sha256",
                "source_head",
                "runtime_version_id",
                "release_digest",
                "issue_authority",
                "mutation_performed",
                "official_issue_allowed",
                "review_digest",
            },
        )

    def test_d1_mutation_is_blocked(self):
        bundle = _bundle()
        bundle["d1"]["approve"]["changed_db"] = True
        result = _review(readback_bundle=bundle)
        self.assertEqual(result["decision"], "NO-GO")
        self.assertIn("D1_MUTATION_DETECTED:approve", result["blockers"])

    def test_kms_secret_attestation_is_blocked(self):
        bundle = _bundle()
        bundle["kms"]["reject"]["token_present"] = True
        result = _review(readback_bundle=bundle)
        self.assertEqual(result["decision"], "NO-GO")
        self.assertIn("KMS_SECRET_ATTESTATION_FAILED:reject", result["blockers"])

    def test_runtime_current_activation_is_blocked(self):
        result = _review(runtime_release={**RELEASE, "runtime_current_activation": True})
        self.assertEqual(result["decision"], "NO-GO")
        self.assertIn("RUNTIME_CURRENT_FORBIDDEN", result["blockers"])

    def test_review_window_over_24_hours_is_blocked(self):
        result = _review(expires_at=datetime(2026, 10, 22, 4, 1, tzinfo=timezone.utc))
        self.assertEqual(result["decision"], "NO-GO")
        self.assertIn("REVIEW_WINDOW_INVALID", result["blockers"])

    def test_cli_writes_no_go_record_without_external_side_effects(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, value in (("g3.json", G3), ("bundle.json", _bundle()), ("release.json", RELEASE)):
                (root / name).write_text(json.dumps(value), encoding="utf-8")
            result = subprocess.run(
                [
                    sys.executable,
                    "reviewer.py",
                    "--g3",
                    str(root / "g3.json"),
                    "--readback-bundle",
                    str(root / "bundle.json"),
                    "--runtime-release",
                    str(root / "release.json"),
                    "--reviewer-id",
                    "reviewer-ci",
                    "--implementation-actor-id",
                    "implementation-process",
                    "--issuer-actor-id",
                    "issuer-process",
                    "--repository",
                    "https://github.com/ywjo86-tech/ai-office-independent-g3-reviewer",
                    "--workflow-path",
                    ".github/workflows/g3-review.yml",
                    "--workflow-source-sha256",
                    "d" * 64,
                    "--evidence-bundle-sha256",
                    "e" * 64,
                    "--reviewed-at",
                    "2026-10-21T04:00:00Z",
                    "--expires-at",
                    "2026-10-22T03:59:00Z",
                    "--now",
                    "2026-10-21T04:01:00Z",
                    "--output",
                    str(root / "review.json"),
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            output = json.loads((root / "review.json").read_text(encoding="utf-8"))
            self.assertEqual(output["decision"], "PASS")


if __name__ == "__main__":
    unittest.main()
