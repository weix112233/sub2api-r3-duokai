package tlsfingerprint

import "context"

type profileContextKey struct{}
type contextProfile struct{ profile *Profile }

// WithProfile preserves an explicit nil (fingerprinting disabled), distinct
// from a legacy caller that supplied no account profile.
func WithProfile(ctx context.Context, profile *Profile) context.Context {
	return context.WithValue(ctx, profileContextKey{}, contextProfile{profile.Clone()})
}

func ProfileFromContext(ctx context.Context) (*Profile, bool) {
	value, ok := ctx.Value(profileContextKey{}).(contextProfile)
	return value.profile.Clone(), ok
}

// ForWebSocket keeps the TLS parameters but limits ALPN to the HTTP/1 Upgrade
// transport. Explicit no-ALPN remains absent.
func (p *Profile) ForWebSocket() *Profile {
	out := p.Clone()
	if out == nil {
		return nil
	}
	out.HTTP2 = nil
	if len(out.ALPNProtocols) > 0 {
		out.ALPNProtocols = []string{"http/1.1"}
	}
	return out
}
