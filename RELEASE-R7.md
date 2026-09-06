# Sub2API Production R7

This branch records the local production-derived R7 source snapshot used to
build the deployment package delivered on September 6, 2026.

## Identity

- Version: `0.2.0-local-gpt6-stability-r7`
- Build label: `10bb618-shared-connect-r2`
- Build date: `2026-09-06`
- Source base revision: `10bb6185a4d56f12efebe137fe7207cd369f75fe`
- Go toolchain: `go1.27.0`
- Build flags: embedded frontend, `CGO_ENABLED=0`, `-trimpath`, `-buildvcs=false`,
  stripped symbols and DWARF (`-s -w`)

## Deployment Artifact

- File: `Sub2API-R7-Production-macOS-Windows-Linux-20260906.zip`
- SHA-256:
  `3c7c39010061b320b862a32f77cb0474e79205f1bc5abd79bae54b6c96b28b36`
- Contents: macOS arm64/amd64, Linux amd64/arm64, Windows amd64/arm64,
  embedded frontend resources, launchers, Docker templates and deployment
  documentation.
- The macOS arm64 rebuild is byte-identical to the running local production
  binary with SHA-256
  `d3424041412196927b68f7d4c5531fd2770d509b18160b604389d625cbbc936f`.

## Validation Scope

The published snapshot contains the frozen `backend/internal/web/dist`
production frontend input. It can reproduce the native production executable
without rebuilding the frontend:

```sh
cd backend
CGO_ENABLED=0 GOTOOLCHAIN=go1.27.0 go build -tags embed -trimpath -buildvcs=false \
  -ldflags='-s -w -X main.Version=0.2.0-local-gpt6-stability-r7 -X main.Commit=10bb618-shared-connect-r2 -X main.Date=2026-09-06' \
  -o sub2api ./cmd/server
```

The actual macOS arm64 rebuild from this delivery snapshot matched production
byte for byte. Backend build-input SHA-256:
`561ddacbb82f863edbf02a56f345406ac3d756c3d5375d52a0c5b7e8a3902083`.

The snapshot does not include the old opaque audit archive
`openspec/changes/add-openai-compatible-prompt-audit/source-freeze/aicodex-prompt-audit-untracked.tar.gz`.
It is not a build input. Current application code, frontend source, backend
source/tests and frozen frontend build assets are included.

- Temporary PostgreSQL 16 and Redis initialization, database migrations,
  administrator login, first-login compliance acknowledgement, embedded
  HTML/JavaScript/CSS delivery, negative authentication checks and restart
  persistence passed on macOS arm64.
- macOS Intel launcher passed through Rosetta from a different working
  directory.
- Windows and Linux artifacts were cross-compiled from the same source
  fingerprint. Target-machine runtime validation remains the responsibility
  of the deployment host.
- The deployment ZIP contains no production credentials, database, runtime
  configuration, source-control history or machine-specific relay adapter.

The current worktree contains intentional local production changes. Review the
diff and run the repository's tests before using this snapshot as a public
upstream contribution. This private repository delivery is a storage and
deployment handoff, not a claim that all runtime or cost incidents are closed.

This publication uses `[skip ci]` because construction and validation were
performed locally. No remote CI pass is claimed. Three pre-existing Markdown
hard-line-break whitespace warnings were retained rather than altering the
production-derived documentation solely for a whitespace check. One generated
vendor JavaScript whitespace warning was also retained to preserve the exact
embedded production frontend bytes.
