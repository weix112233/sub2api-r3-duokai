# Application Anti-Bypass Business Boundary Repair

This change repairs the application gateway anti-bypass feature. It does not
change Codex execution hooks, storage admission, account routes or production
configuration. Source delivery is not runtime deployment.

## Unreleased HTTP Trace-ID Compatibility Follow-Up

HTTP `X-Client-Request-ID` can identify a conversation rather than a single
immutable operation. The HTTP middleware now leaves that header intact for
tracing/downstream use without assigning it to the guard's operation-ID
signature and attempt budget. A normal next turn or tool result must not be
rejected merely because its trace ID is unchanged.

Explicit `Idempotency-Key` signature conflicts remain rejected. Authenticated
RPM, concurrency, identity cardinality and cross-key replay checks are
unchanged. Responses WebSocket `event_id` remains a per-operation identifier
with its existing conflicting-body and attempt-limit checks.

Old HTTP request-ID Redis entries are not deleted or rewritten by this
repair. They expire normally, and other budget/lease state is retained.
Mixed old/new server generations can still expose the old rejection on the
old binary; do not clear Redis or disable protection to represent completion.
Rejection logs now include the non-secret current/limit counters.

Regression source covers evolving HTTP turns and tool results, path changes,
same-body retries, explicit idempotency conflicts, retained legacy Redis
state, RPM/concurrency/cross-key protections and WebSocket operation IDs.
Execution, platform builds and release/runtime acceptance for this follow-up
are still pending; historical results below do not validate the new revision.

## Repaired Boundaries

| Finding | Source behavior after repair |
| --- | --- |
| F1: multipart requests create artificial client identities | Request Content-Type, Accept and Accept-Language no longer participate in the client fingerprint |
| F2: implicit 2 MiB request cap and truncated prompt extraction | HTTP and WS honor configured wire limits; text has a separate bounded inspection budget; media fields do not consume the text budget; exceeded budgets/depth return explicit errors |
| F3: quoted examples and simple negation variants misclassified | Explicit translation/test-fixture tasks can treat quotes as data, while direct commands outside quotes and requests to execute quoted instructions remain blocked |
| F4: network/negotiation changes treated as cross-identity replay | Replay identity uses the authenticated API key in the existing user scope; IP and fingerprint cardinality policies remain separate |
| F5: Responses WebSocket handshake counted instead of inference turns | Each accepted create frame gets a numbered inference lease; controls do not consume request quota; exact turn completion or connection cleanup releases the lease |
| F6: caller-supplied instruction roles assumed trusted | Client system/developer and supported instruction fields are inspected; source-controlled instructions added later in the server are outside this inbound middleware |

## Behavior And Compatibility

- HTTP body limits use `gateway.max_body_size`, bounded by the server body
  limit when set. The default gateway wire limit is 256 MiB.
- Responses WS uses `gateway.openai_ws.client_read_limit_bytes`, bounded by
  the wire limit. The default frame budget is 64 MiB.
- Extracted text uses `gateway.text_max_body_size`, bounded by the wire/frame
  limit. Its default is 32 MiB. This is an inspection budget, not a model
  context guarantee. Large media bodies still incur bounded JSON parsing cost.
- Unsupported nested prompt structures fail explicitly. The detector no
  longer silently returns allowed merely because a permitted request extends
  beyond its former 2 MiB text collector.
- Tool results, assistant history and non-text media remain data, not direct
  instruction fields. This is a deliberate inspection scope, not proof that
  arbitrary prompt injection is impossible.
- The gateway still applies its normal per-user RPM, concurrency, distinct
  key/IP/client, explicit idempotency, WS operation ID and cross-key replay
  policies when enabled. HTTP tracing headers are not operation identities.
- Fingerprint cardinality uses a versioned `fingerprints:v2` dimension so
  old multipart-boundary noise cannot exhaust the new stable-client budget.
  Existing RPM, key, IP and inference lease dimensions are not reset.
- The replay reader accepts the prior key/IP/fingerprint identity encoding
  only for the same authenticated key. A different key still cannot claim
  that prior payload within the user scope.
- Deploy a uniform new writer generation. Old binaries do not understand
  the new replay value and keep their old fingerprint dimension. A mixed
  rollout or immediate rollback can retain temporary policy differences
  until the bounded replay/fingerprint windows expire; no Redis purge is
  authorized by this source change.

## Responses WebSocket Lifecycle

The middleware installs a per-connection frame policy before upgrading.
It retains the authenticated subject, not the raw credential. It counts
explicit create frames and the native protocol's implicit/trimmed create
forms. Control frames such as response.cancel do not count as inference.

Disabled create frames still advance the local turn sequence without taking
a lease. If the existing cached switch later enables protection, completion
of an older disabled turn cannot release a newer protected turn.

The lease is stored by exact accepted turn number. Repeating an old completion
does not release newer work. The common Responses handler's AfterTurn callback
finishes this lease in native, HTTP-bridge and passthrough paths; upstream
retries within one client turn are not extra client-frame admissions.
Middleware cleanup cancels renewal and releases any unfinished turns when the
connection closes or the handler fails. Existing independent WS draining still
waits until the terminal frame is written to the client.

The standalone Realtime transport retains its existing connection policy;
this repair does not claim that it was converted to Responses turn accounting.

## Error Visibility

- Wire overflow: HTTP 413 or WS message-too-big, `ANTI_BYPASS_BODY_TOO_LARGE`.
- Text/depth inspection budget: `ANTI_BYPASS_INSPECTION_LIMIT`.
- Positive prompt rule: `ANTI_BYPASS_PROMPT_BLOCKED`.
- WS request budget: `ANTI_BYPASS_BLOCKED`, rate-limit type and explicit
  machine-readable reason.
- Settings/Redis failure: `ANTI_BYPASS_UNAVAILABLE`; no fail-open fallback.

## Validation And Release Boundary

New regressions cover multipart identity, same-key network changes, legacy
replay/fingerprint state, quoted data plus external/quoted execution attacks,
caller instruction roles, long text beyond 2 MiB, media/text budgets, depth
limits, WS controls, implicit types, toggling, duplicate/late completion,
cross-HTTP/WS concurrency and connection cleanup.

The actual Responses handler drain test now enables the guard for all three
ingress modes and checks one initial inference admission and eventual release.
Full backend and selected race results are recorded in the accompanying
source-delivery validation manifest when complete.

These are local fixture and code-regression checks, not paid-provider tests,
production load acceptance or a guarantee of complete natural-language
intent recognition. No application binary was built or deployed for this
source-repair delivery. Keep the prior source commit for a scoped rollback.
