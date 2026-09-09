# Sub2API R11 Source Candidate

Status: source candidate, not a tested binary release. The last completed
Git delivery is R10 at `10e35ba48ecc38b02cd61ec6dfdd570ac3d145a3`.
This candidate must pass current-generation validation before replacing the
default release or an installed service. Historical R10 test counts do not
validate R11.

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

On verified release, move the current source/download pointers together.
Old artifacts leave current download selection but keep their original tags,
digests and history for rollback. Do not force-rewrite history, delete unique
recovery data, mix binaries from different revisions or rename R10 packages
as R11. Existing installations change only through their authorized runtime
publication and consumer acceptance process.
