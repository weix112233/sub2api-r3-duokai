package tlsfingerprint

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
)

// ConfigureTransport applies a snapshot before a fresh transport is used.
// HTTPS proxies retain net/http's existing TLS-to-proxy behavior.
func ConfigureTransport(base *http.Transport, profile *Profile, proxyURL *url.URL) (http.RoundTripper, error) {
	if base == nil {
		return nil, fmt.Errorf("TLS profile requires an HTTP transport")
	}
	if err := profile.Validate(); err != nil {
		return nil, err
	}
	if proxyURL != nil {
		base.Proxy = http.ProxyURL(proxyURL)
	}
	if profile == nil {
		return base, nil
	}
	if proxyURL == nil {
		base.DialTLSContext = NewDialer(profile, nil).DialTLSContext
	} else {
		switch strings.ToLower(proxyURL.Scheme) {
		case "http":
			base.DialTLSContext = NewHTTPProxyDialer(profile, proxyURL).DialTLSContext
		case "socks5", "socks5h":
			base.DialTLSContext = NewSOCKS5ProxyDialer(profile, proxyURL).DialTLSContext
		case "https":
			slog.Warn("tls_fingerprint_https_proxy_fallback", "fingerprint_applied", false)
			return base, nil
		default:
			return nil, fmt.Errorf("unsupported TLS profile proxy scheme")
		}
	}
	base.Proxy = nil
	base.ForceAttemptHTTP2 = false
	if profile.HasHTTP2() {
		return NewTransport(base, profile)
	}
	return base, nil
}
