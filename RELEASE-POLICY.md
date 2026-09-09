# Release Delivery Requirements

Future formal release updates for this maintained repository must deliver
actual binaries for all three operating systems. A source archive, Docker
image or single-platform package is not a complete release.

## Source Synchronization

The user may request a complete source update separately from binary release
and local deployment. In that case, synchronize the complete source, tests,
version and release configuration to the current source branches, explicitly
state pending validation, and do not claim built artifacts or runtime adoption.
This does not relax any build, resource or deployment gate.

Old source-only release entries must no longer claim to be the latest source.
Retain their immutable history/assets as historical drafts; do not fabricate
a new complete release before the required binary matrix is ready.

## Required Artifacts

Both GoReleaser configurations retain the same required binary matrix:

| Operating System | Architecture | Archive | Executable |
| --- | --- | --- | --- |
| macOS | arm64, Apple Silicon | tar.gz | sub2api |
| macOS | amd64, Intel | tar.gz | sub2api |
| Windows | amd64 | zip | sub2api.exe |
| Linux | amd64 | tar.gz | sub2api |
| Linux | arm64 | tar.gz | sub2api |

Windows arm64 is not in this required matrix and must not be advertised as
included without its own built and verified artifact. The simple release
option simplifies container images only; it must not remove binary targets,
archives, checksums or binary uploads.

## Publication Gate

1. Build from one frozen, tested source revision with the same version and
   commit metadata in every binary. Preserve the embedded frontend input and
   dependency lockfiles; release builds must not run `go mod tidy`.
   Align the committed version file and frontend assets before tagging.
   Generated drift must fail validation, not be hidden with `--skip=validate`.
2. Produce all five required archives and the SHA-256 `checksums.txt`.
   Confirm each archive contains the correct executable and platform-specific
   instructions, with no credentials, account exports or runtime data.
3. Check archive integrity, binary format, architecture, metadata and digest.
   Record native runtime validation separately for each platform. Successful
   cross-compilation alone is not a successful native runtime test.
4. Prepare the release as a draft. Upload only the immutable, locally built
   artifacts through the separately authorized delivery entry. Read back the
   complete asset set and digests before marking the release public/latest.
5. A missing target, failed build, mismatched digest or mixed source revision
   keeps the release incomplete. Do not publish a partial package set as the
   complete latest release.

Both configurations default to draft releases. The inherited build-stage
notification has been removed; any announcement belongs to the separately
authorized promotion after complete-asset verification.

## Execution Boundaries

Construction remains on authorized local paths with current resource
admission. Configuration files and checksums are not execution permission.
Do not trigger remote builds, container publication or workflow execution
merely because the repository contains upstream workflow definitions.

Local runtime deployment and Git release delivery are separate operations.
A tested native artifact may follow its existing authorized local deployment
process; the subsequent Git release still requires the complete matrix.
Service switching retains its own source/build bindings, single publisher,
runtime acceptance and rollback requirements.

Existing R10 source-only and macOS-arm64 deliveries retain their historical
scope. This policy does not relabel them as a three-system release or claim
that later optimization candidates have been built or deployed.
