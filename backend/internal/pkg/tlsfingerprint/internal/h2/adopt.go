package http2

import (
	"errors"
	"net"
	"net/http"
)

// NeedsConnectionError carries the replayable request after an HTTP/2 retry
// loses its cached connection. Its body may differ from the original request.
type NeedsConnectionError struct{ Request *http.Request }

func (*NeedsConnectionError) Error() string { return "http2: retry requires a negotiated connection" }
func (*NeedsConnectionError) Unwrap() error { return ErrNoCachedConn }

// NewProfileTransport inherits HTTP/1 lifecycle policy but never installs the
// standard TLS protocol hook (fingerprint connections are not *tls.Conn).
func NewProfileTransport(base *http.Transport) *Transport {
	t := &Transport{
		StrictMaxConcurrentStreams: true,
		transportInternal:          transportInternal{t1: base},
	}
	t.ConnPool = noDialClientConnPool{&clientConnPool{t: t}}
	return t
}

// AdoptConn takes ownership of a connection already negotiated as h2.
func (t *Transport) AdoptConn(addr string, conn net.Conn) error {
	pool, ok := t.connPool().(noDialClientConnPool)
	if !ok {
		conn.Close()
		return errors.New("http2: connection adoption requires the default pool")
	}
	used, err := pool.addConnIfNeeded(addr, t, conn)
	if err != nil || !used {
		conn.Close()
	}
	return err
}
