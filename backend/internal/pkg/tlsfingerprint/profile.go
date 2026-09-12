package tlsfingerprint

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math"
	"slices"

	utls "github.com/refraction-networking/utls"
)

// HTTP2Config configures the client's initial HTTP/2 frames. Pointers preserve
// the distinction between an omitted setting and an explicit zero or false.
type HTTP2Config struct {
	InitialWindowSize      *uint32 `json:"initial_window_size,omitempty" yaml:"initial_window_size,omitempty"`
	ConnectionWindowUpdate *uint32 `json:"connection_window_update,omitempty" yaml:"connection_window_update,omitempty"`
	MaxHeaderListSize      *uint32 `json:"max_header_list_size,omitempty" yaml:"max_header_list_size,omitempty"`
	EnablePush             *bool   `json:"enable_push,omitempty" yaml:"enable_push,omitempty"`
}

// Clone snapshots all mutable fields before a profile is used by a transport.
func (p *Profile) Clone() *Profile {
	if p == nil {
		return nil
	}
	out := *p
	out.CipherSuites = slices.Clone(p.CipherSuites)
	out.Curves = slices.Clone(p.Curves)
	out.PointFormats = slices.Clone(p.PointFormats)
	out.SignatureAlgorithms = slices.Clone(p.SignatureAlgorithms)
	out.ALPNProtocols = slices.Clone(p.ALPNProtocols)
	out.SupportedVersions = slices.Clone(p.SupportedVersions)
	out.KeyShareGroups = slices.Clone(p.KeyShareGroups)
	out.PSKModes = slices.Clone(p.PSKModes)
	out.Extensions = slices.Clone(p.Extensions)
	if p.HTTP2 != nil {
		out.HTTP2 = &HTTP2Config{
			InitialWindowSize:      clonePointer(p.HTTP2.InitialWindowSize),
			ConnectionWindowUpdate: clonePointer(p.HTTP2.ConnectionWindowUpdate),
			MaxHeaderListSize:      clonePointer(p.HTTP2.MaxHeaderListSize),
			EnablePush:             clonePointer(p.HTTP2.EnablePush),
		}
	}
	return &out
}

func clonePointer[T any](p *T) *T {
	if p == nil {
		return nil
	}
	value := *p
	return &value
}

func (p *Profile) Validate() error {
	if p == nil {
		return nil
	}
	for _, field := range []struct {
		name   string
		values []uint16
	}{{"point_formats", p.PointFormats}, {"psk_modes", p.PSKModes}} {
		for _, value := range field.values {
			if value > 255 {
				return fmt.Errorf("%s: value exceeds uint8 range", field.name)
			}
		}
	}
	versions := 0
	legacyVersion := false
	for _, v := range p.SupportedVersions {
		if isGREASEValue(v) {
			continue
		}
		if v < utls.VersionTLS10 || v > utls.VersionTLS13 {
			return fmt.Errorf("supported_versions: unsupported TLS version")
		}
		versions++
		legacyVersion = legacyVersion || v <= utls.VersionTLS12
	}
	if len(p.SupportedVersions) > 0 && versions == 0 {
		return fmt.Errorf("supported_versions: at least one non-GREASE version is required")
	}
	if versions > 0 && !legacyVersion && len(p.Extensions) > 0 && !slices.Contains(p.Extensions, uint16(43)) {
		return fmt.Errorf("supported_versions: TLS 1.3 requires extension 43")
	}
	seen := make(map[string]bool)
	for _, protocol := range p.ALPNProtocols {
		if protocol != "h2" && protocol != "http/1.1" {
			return fmt.Errorf("alpn_protocols: unsupported HTTP protocol %q", protocol)
		}
		if seen[protocol] {
			return fmt.Errorf("alpn_protocols: duplicate protocol %q", protocol)
		}
		seen[protocol] = true
	}
	if p.HTTP2 == nil {
		return nil
	}
	if !p.HasHTTP2() {
		return fmt.Errorf("http2 requires h2 in alpn_protocols and extension 16")
	}
	if n := p.HTTP2.InitialWindowSize; n != nil && *n > math.MaxInt32 {
		return fmt.Errorf("http2.initial_window_size exceeds the HTTP/2 flow-control limit")
	}
	if n := p.HTTP2.ConnectionWindowUpdate; n != nil && *n > math.MaxInt32-65535 {
		return fmt.Errorf("http2.connection_window_update overflows the connection window")
	}
	return nil
}

// TransportKey changes when wire behavior changes, including nil versus [].
// Descriptive names do not affect transport reuse.
func (p *Profile) TransportKey() string {
	snapshot := p.Clone()
	if snapshot != nil {
		snapshot.Name = ""
	}
	data, _ := json.Marshal(snapshot)
	return fmt.Sprintf("%x", sha256.Sum256(data))
}

// HasHTTP2 reports whether the ClientHello can negotiate HTTP/2.
func (p *Profile) HasHTTP2() bool {
	if p == nil {
		return false
	}
	hasExtension := len(p.Extensions) == 0
	for _, id := range p.Extensions {
		if id == 16 {
			hasExtension = true
		}
	}
	if hasExtension {
		for _, protocol := range p.ALPNProtocols {
			if protocol == "h2" {
				return true
			}
		}
	}
	return false
}
