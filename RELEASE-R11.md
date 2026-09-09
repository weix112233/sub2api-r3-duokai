# Sub2API R11 Source Update

Status: current repository source, not a tested binary release.
The complete application/source candidate was committed as
`c5ae2f2fcca7bb634f125c4420523ec8c60eab60`, based on R10
`10e35ba48ecc38b02cd61ec6dfdd570ac3d145a3`. The current `main` and
`delivery/r11-source-20260909` branches contain that commit plus the
source-delivery documentation update. Use the full current commit as the
source identity; a branch name alone is not immutable.

The user requested source synchronization before local runtime deployment.
This update does not publish verified binary packages, restart a service or
turn historical R10 test counts into R11 validation.

## Included Changes

- HTTP anti-bypass admission no longer treats `X-Client-Request-ID` as a
  single immutable operation. The original trace header and body continue
  downstream. Multi-turn conversations and tool results may reuse the trace.
- Explicit `Idempotency-Key` conflicts, RPM, concurrency, identity
  cardinality and cross-key replay checks remain enabled. WebSocket
  `event_id` retains its operation checks. No Redis purge is required.
- Healthy OpenAI OAuth/setup-token sessions are no longer moved solely
  because an account-wide TTFT average exceeds the threshold. Error, quota,
  compatibility and full-concurrency checks remain in place. This is not
  measured latency improvement and does not lower model reasoning effort.
- Both release configurations require the same five native binary targets,
  SHA-256 checksums and draft publication. Builds preserve dependency files
  and embed explicit version/commit metadata.

## Source And Version Identity

The candidate version file is `0.2.0-local-gpt6-production-audit-r11`.
The source revision is the complete Git commit containing this file,
application changes, regression tests and release configuration. Build
metadata must contain that exact full commit, not a custom label such as
`download-r11` or the Docker default `docker`.

The existing Docker build accepts `VERSION`, `COMMIT` and `DATE` arguments.
The release owner must supply the exact source version, commit and fixed
build time. A matching image name or version string alone is not provenance.
No remote container has been updated by this candidate.

## Validation Status

The HTTP trace-ID and session-affinity increments received independent static
reviews without a definite new blocker in their reviewed scopes. Static
review does not execute the source or prove real consumer behavior.

Regression source covers evolving turns/tools, preserved headers/body,
explicit idempotency, old request-ID state, RPM/concurrency/cross-key
controls, WS operation IDs and OAuth affinity/error behavior. The new Go
tests and fixed builds have not run. Application validation and deployment
remain blocked on the existing maintenance/resource-admission boundary.

## Required Delivery

The complete asset set is defined in [RELEASE-POLICY.md](RELEASE-POLICY.md):
macOS arm64/amd64, Windows amd64, Linux arm64/amd64 and `checksums.txt`.
No R11 platform archive has yet been built or published.

Before public promotion, verify archive contents, binary format, version,
commit and checksums against one tested snapshot, and read back all uploaded
assets. Native runtime validation remains distinct from cross-compilation.
Do not announce an incomplete set as the latest complete release.

## Replacement And Rollback

Current source branches and repository descriptions identify R11. The old
R10 source release is retained as a historical draft, not the latest download;
use GitHub's current `main` source until validated platform assets are ready.
Old artifacts keep their original tags, digests and history for rollback.
Do not force-rewrite history, delete unique
recovery data, mix binaries from different revisions or rename R10 packages
as R11. Existing installations change only through their authorized runtime
publication and consumer acceptance process.
