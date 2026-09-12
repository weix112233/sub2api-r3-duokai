# Sub2API R11 Source Update

Status: current repository source, not a production-deployment assertion.
The R11 source history is based on R10
`10e35ba48ecc38b02cd61ec6dfdd570ac3d145a3`. The current `main` and
`delivery/r11-source-20260909` branches are the Git source surfaces for this
release line. Use the full current commit as the source identity; a branch
name alone is not immutable.

The latest source synchronization also includes the complete generic TLS
profile transport infrastructure and the R11 operational additions. The
source includes the application code, generated Ent code, database
migrations, management UI source, embedded frontend build output, focused
regression tests, and the isolated HTTP/2 engine copy. No production runtime,
account data, or deployment target is modified by a Git source update.

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
review does not prove real consumer behavior.

Regression source covers evolving turns/tools, preserved headers/body,
explicit idempotency, old request-ID state, RPM/concurrency/cross-key
controls, WS operation IDs and OAuth affinity/error behavior. The current
source synchronization was revalidated with the Go default suite, the full
integration-tag suite, the TLS profile unit suite, frontend tests, frontend
type checking, and the frontend production build. These checks are local
source evidence; they do not prove production adoption or real-account
acceptance.

The generalized external TLS capture test remains opt-in. A
`TLSFINGERPRINT_CAPTURE_URL` and external YAML fixture are required before
real endpoint JA3 comparison can be claimed.

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
