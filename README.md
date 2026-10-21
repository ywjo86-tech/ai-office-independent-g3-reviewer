# AI Office Independent G3 Reviewer

This repository is a separate, read-only reviewer for the AI Office G3
evidence contract. It consumes evidence that has already been collected and
returns either `PASS` or `NO-GO`.

The reviewer never performs a WebAuthn ceremony, calls Google Cloud KMS,
writes D1, issues an approval, creates a G3 issue receipt, changes a Worker,
or deploys anything. A `PASS` is non-authorizing provenance only; the Harness
still owns official G3 issuance.

## Local run

From the repository root:

```bash
PYTHONPATH=. python3 reviewer.py \
  --g3 path/to/g3-successor-contract.json \
  --readback-bundle path/to/readback-bundle.json \
  --runtime-release path/to/g3-runtime-release-mapping.json \
  --reviewer-id independent-reviewer-github-actions \
  --implementation-actor-id harness-implementation \
  --issuer-actor-id canonical-issuer \
  --repository https://github.com/ywjo86-tech/ai-office-independent-g3-reviewer \
  --workflow-path .github/workflows/g3-review.yml \
  --workflow-source-sha256 WORKFLOW_SHA256 \
  --evidence-bundle-sha256 EVIDENCE_SHA256 \
  --reviewed-at 2026-10-21T04:00:00Z \
  --expires-at 2026-10-22T03:59:00Z \
  --now 2026-10-21T04:01:00Z \
  --output independent-g3-review.json
```

The process exits `0` only for `PASS` and exits `10` for a fail-closed
`NO-GO`. It reads JSON files and writes only the requested review record.

## GitHub Actions

`.github/workflows/g3-review.yml` is a manual `workflow_dispatch` workflow.
The evidence artifact must already exist in this reviewer repository. The
workflow downloads that artifact, runs the local reviewer, creates a GitHub
artifact attestation for the generated review record, and uploads the review
record together with its attestation bundle. A fail-closed `NO-GO` remains a
failed workflow result, but its record and attestation are still preserved
when both are available. The workflow skips artifact upload unless both
files exist.

The workflow grants `contents: read`, `actions: read`, `id-token: write`, and
`attestations: write` for GitHub artifact attestation. It does not grant
`artifact-metadata` or contents-write, issue-write, or deployment permissions,
and it has no KMS, WebAuthn, or D1 step.

Before treating the repository as an independent protected reviewer, the
repository owner must make the repository private or otherwise protected and
protect the default branch. The Harness lock must contain the exact workflow
SHA-256 from the committed workflow file; this repository does not self-edit
the Harness lock and does not push to GitHub.

## Tests

```bash
PYTHONPATH=. python3 -m unittest discover -s tests -p 'test_*.py' -v
git diff --check
```
