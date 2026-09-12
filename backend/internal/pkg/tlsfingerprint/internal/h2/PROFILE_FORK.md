# Controlled HTTP/2 Client Copy

Source: `golang.org/x/net v0.56.0`, already locked by this repository.
`UPSTREAM.json` records the original file hashes. The original BSD license and
copyright notices are retained. This package is internal to TLS fingerprints.
No upstream server, scheduler, h2c server, or HPACK copy is included. HPACK,
HTTP validation and IDNA reuse the existing locked modules.

The legacy client implementation is deliberately compiled on Go 1.27 rather
than the upstream Go 1.27 standard-library wrapper. The copied build selectors
are removed, and the Go 1.26+ configuration accessor is selected explicitly.
This repository already requires Go 1.27.

Local differences:

- Relocated internal HTTP request helpers; removed server configuration entry.
- Optional receive windows, exact header-list limit (including zero), push
  advertisement and cancellation policy; defaults preserve upstream behavior.
- TLS connection adoption for ALPN dispatch from the existing HTTP/1 transport.
- A no-dial HTTP/2 pool: upstream's documented-broken `OnlyCachedConn` option
  cannot accidentally send a standard ClientHello instead of the profile.
- Preserve regenerated request bodies across GOAWAY/refused-stream redial.
- CONNECT/SOCKS and HTTP/1 socket creation remain outside this engine.
- Tests and future source maintenance belong to the TLS profile module owner.

Updating this copy requires a separate source/version review. Do not regenerate
over local patches. Rollback removes this package and its profile-only caller;
the normal application HTTP transport does not import it.
