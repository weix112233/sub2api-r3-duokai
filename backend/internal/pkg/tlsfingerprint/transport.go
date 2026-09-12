package tlsfingerprint

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"

	h2 "github.com/Wei-Shaw/sub2api/internal/pkg/tlsfingerprint/internal/h2"
	utls "github.com/refraction-networking/utls"
)

var errNegotiatedHTTP2 = errors.New("TLS profile negotiated HTTP/2")

// Transport retains the HTTP/1 pool and uses the isolated HTTP/2 engine only
// when the profile explicitly advertises h2. Configure before first use.
type Transport struct {
	*http.Transport
	h2 *h2.Transport
}

func NewTransport(base *http.Transport, profile *Profile) (*Transport, error) {
	if err := profile.Validate(); err != nil {
		return nil, err
	}
	t := &Transport{Transport: base}
	if !profile.HasHTTP2() {
		return t, nil
	}
	snapshot := profile.Clone()
	t.h2 = h2.NewProfileTransport(base)
	t.h2.IdleConnTimeout = base.IdleConnTimeout
	if cfg := snapshot.HTTP2; cfg != nil {
		t.h2.InitialWindowSize = cfg.InitialWindowSize
		t.h2.ConnectionWindowUpdate = cfg.ConnectionWindowUpdate
		t.h2.HeaderListSize = cfg.MaxHeaderListSize
		t.h2.EnablePush = cfg.EnablePush
	}
	dial := base.DialTLSContext
	if dial == nil {
		return nil, errors.New("HTTP/2 TLS profile requires a fingerprint dialer")
	}
	// All socket creation stays in the HTTP/1 transport, preserving its
	// concurrency, proxy and cancellation policy. No HTTP/1 bytes are written
	// to a socket that negotiated h2.
	base.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, err := dial(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		if negotiatedProtocol(conn) != "h2" {
			return conn, nil
		}
		if c, ok := conn.(*utls.UConn); ok {
			conn = &standardTLSStateConn{UConn: c}
		}
		if err := t.h2.AdoptConn(addr, conn); err != nil {
			return nil, err
		}
		return nil, errNegotiatedHTTP2
	}
	return t, nil
}

type standardTLSStateConn struct{ *utls.UConn }

func (c *standardTLSStateConn) ConnectionState() tls.ConnectionState {
	s := c.UConn.ConnectionState()
	return tls.ConnectionState{
		Version: s.Version, HandshakeComplete: s.HandshakeComplete,
		DidResume: s.DidResume, CipherSuite: s.CipherSuite,
		NegotiatedProtocol: s.NegotiatedProtocol, ServerName: s.ServerName,
		PeerCertificates: s.PeerCertificates, VerifiedChains: s.VerifiedChains,
		SignedCertificateTimestamps: s.SignedCertificateTimestamps,
		OCSPResponse:                s.OCSPResponse, TLSUnique: s.TLSUnique,
	}
}

func negotiatedProtocol(conn net.Conn) string {
	switch c := conn.(type) {
	case interface{ ConnectionState() utls.ConnectionState }:
		return c.ConnectionState().NegotiatedProtocol
	case interface{ ConnectionState() tls.ConnectionState }:
		return c.ConnectionState().NegotiatedProtocol
	default:
		return ""
	}
}

func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.h2 == nil || req.URL == nil || req.URL.Scheme != "https" {
		return t.Transport.RoundTrip(req)
	}
	for attempt := 0; attempt < 3; attempt++ {
		res, err := t.h2.RoundTripOpt(req, h2.RoundTripOpt{OnlyCachedConn: true})
		if !errors.Is(err, h2.ErrNoCachedConn) {
			return res, err
		}
		var replay *h2.NeedsConnectionError
		if errors.As(err, &replay) {
			req = replay.Request
		}
		// net/http closes request bodies even when dialing fails. Defer that
		// close until we know whether ALPN hands the untouched body to h2.
		h1req := req.Clone(req.Context())
		var body *negotiationBody
		if req.Body != nil && req.Body != http.NoBody {
			body = &negotiationBody{ReadCloser: req.Body}
			h1req.Body = body
		}
		res, err = t.Transport.RoundTrip(h1req)
		handoff := errors.Is(err, errNegotiatedHTTP2)
		if body != nil {
			body.finish(handoff)
		}
		if !handoff {
			return res, err
		}
		if err := req.Context().Err(); err != nil {
			if req.Body != nil {
				req.Body.Close()
			}
			return nil, err
		}
	}
	if req.Body != nil {
		req.Body.Close()
	}
	return nil, errors.New("TLS profile: HTTP/2 peer repeatedly closed before request")
}

func (t *Transport) CloseIdleConnections() {
	t.Transport.CloseIdleConnections()
	if t.h2 != nil {
		t.h2.CloseIdleConnections()
	}
}

type negotiationBody struct {
	io.ReadCloser
	mu      sync.Mutex
	closed  bool
	decided bool
	handoff bool
}

func (b *negotiationBody) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return nil
	}
	b.closed = true
	if b.decided && !b.handoff {
		return b.ReadCloser.Close()
	}
	return nil
}

func (b *negotiationBody) finish(handoff bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.decided, b.handoff = true, handoff
	if b.closed && !handoff {
		b.ReadCloser.Close()
	}
}
