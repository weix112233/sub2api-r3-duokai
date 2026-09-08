# Sub2API R10

## Current Source

R10 is the latest source line. The default `main` branch and
`delivery/r10-source-20260907` are aligned to the same release revision.
The application changes include:

- R10 response-owner persistence and atomic Redis ownership updates.
- Anti-bypass boundaries and WebSocket inference accounting.
- The selected-model capacity classification fix from
  `62884610775ab62709eb05cac2c1ca304e174f9f`.

The publication-alignment revision changes documentation only relative to
`6288461`; it does not modify backend, frontend, dependencies or tests.

## Capacity Fix

The message `Selected model is at capacity. Please try a different model.`
now enters the shared capacity classification and the existing bounded
same-account and request-wide retry policy.

HTTP, SSE and WebSocket paths retain explicit error-code precedence,
authoritative error-field boundaries and terminal failure semantics. Output
that has already been committed is not replayed. This changes local gateway
handling; it cannot increase an upstream provider's available capacity.

## Existing Validation

The producer's final service/handler module run recorded 14,104 passing test
events and its selected race run recorded 53, both with exit code 0.
The committed application's focused service/handler regression also passed.
The fixed seven-file source/test set and two existing test receipts passed
the approved before/after checksum verification.

These are local source-validation results, not GitHub-hosted CI, deployment,
cross-platform runtime or production-readiness evidence.

## Download Status

The R10 release is the current **source** download. Its locally exported
source ZIP and SHA-256 sidecar are bound to the exact release tag.

An R10 deployment binary has not yet been published in this source release.
Do not download an old R7 deployment ZIP and treat it as R10. Verified R10
binaries must be built locally and delivered with their own provenance,
checksums and platform-validation limits before being added as assets.

## Build And Deployment

The repository includes the frozen frontend assets used by the established
embedded build. For an admitted local build with the required Go 1.27.0
toolchain and existing module cache, the backend Makefile remains the entry:

```sh
make -C backend build BUILD_TAGS=embed \
  VERSION=0.2.0-local-gpt6-production-audit-r10 \
  COMMIT=<exact-source-commit> BUILD_DATE=<fixed-UTC-build-time>
```

Use the approved local build output/cache locations, keep the two build
outputs independently verifiable, and retain the prior known-good runtime.
Installing or switching a running service is a separate operation with
publisher locking, runtime identity, consumer acceptance and rollback checks.

## Historical Releases

The R7 release and production tag are historical recovery records, not the
current repository version. Their artifacts must not be renamed or reused
as R10. Git history and immutable old tags remain available for audit and
rollback; replacing the latest pointers does not erase history.
