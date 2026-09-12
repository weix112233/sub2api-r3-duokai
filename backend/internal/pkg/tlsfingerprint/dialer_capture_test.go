//go:build integration

package tlsfingerprint

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
	"gopkg.in/yaml.v3"
)

// CapturedFingerprint 对应 tls-fingerprint-web 返回的 Fingerprint 结构。
// 用于反序列化 capture server 的 JSON 响应。
type CapturedFingerprint struct {
	JA3Raw              string   `json:"ja3_raw"`
	JA3Hash             string   `json:"ja3_hash"`
	JA4                 string   `json:"ja4"`
	HTTP2               string   `json:"http2"`
	CipherSuites        []int    `json:"cipher_suites"`
	Curves              []int    `json:"curves"`
	PointFormats        []int    `json:"point_formats"`
	Extensions          []int    `json:"extensions"`
	SignatureAlgorithms []int    `json:"signature_algorithms"`
	ALPNProtocols       []string `json:"alpn_protocols"`
	SupportedVersions   []int    `json:"supported_versions"`
	KeyShareGroups      []int    `json:"key_share_groups"`
	PSKModes            []int    `json:"psk_modes"`
	CompressCertAlgos   []int    `json:"compress_cert_algos"`
	EnableGREASE        bool     `json:"enable_grease"`
}

// TestDialerAgainstCaptureServer 连接 tls-fingerprint-web capture server，
// 验证 Dialer 的 TLS 指纹是否匹配配置的 Profile。
//
// 该测试依赖外部服务，默认跳过。需要手动验证时设置：
// TLSFINGERPRINT_CAPTURE_URL=https://localhost:8443
//
// 运行方式：go test -tags=integration -v -run TestDialerAgainstCaptureServer ./internal/pkg/tlsfingerprint/...
func TestDialerAgainstCaptureServer(t *testing.T) {
	captureURL := strings.TrimSpace(os.Getenv("TLSFINGERPRINT_CAPTURE_URL"))
	if captureURL == "" {
		t.Skip("跳过外部 TLS 指纹 capture 测试：未设置 TLSFINGERPRINT_CAPTURE_URL")
	}

	fixturePath := strings.TrimSpace(os.Getenv("TLSFINGERPRINT_PROFILE_YAML"))
	if fixturePath == "" {
		t.Fatal("TLSFINGERPRINT_PROFILE_YAML is required with TLSFINGERPRINT_CAPTURE_URL")
	}
	fixtureFile, err := os.Open(fixturePath)
	if err != nil {
		t.Fatal("open external YAML fixture:", err)
	}
	defer fixtureFile.Close()
	data, err := io.ReadAll(io.LimitReader(fixtureFile, MaxProfileYAMLBytes+1))
	if err != nil || len(data) > MaxProfileYAMLBytes {
		t.Fatal("cannot read bounded external YAML fixture")
	}
	var fixture struct {
		Profile     ProfileDocument `yaml:"profile"`
		ExpectedJA3 string          `yaml:"expected_ja3"`
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&fixture); err != nil {
		t.Fatal("decode fixture:", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF || strings.TrimSpace(fixture.Profile.Name) == "" {
		t.Fatal("fixture requires one document and a named profile")
	}
	if err := fixture.Profile.Validate(); err != nil {
		t.Fatal("invalid fixture profile:", err)
	}
	if _, err := parseJA3(fixture.ExpectedJA3); err != nil {
		t.Fatal("expected_ja3:", err)
	}
	tests := []struct {
		name    string
		profile *Profile
	}{
		{fixture.Profile.Name, &fixture.Profile.Profile},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			captured := fetchCapturedFingerprint(t, captureURL, tc.profile)
			if captured == nil {
				return
			}

			assertJA3Fields(t, fixture.ExpectedJA3, captured.JA3Raw, tc.profile.ShuffleExtensions)

			var expectedALPN []string
			for _, ext := range buildClientHelloSpecFromProfile(tc.profile).Extensions {
				if alpn, ok := ext.(*utls.ALPNExtension); ok {
					expectedALPN = alpn.AlpnProtocols
				}
			}
			assertStringSliceEqual(t, "alpn_protocols", expectedALPN, captured.ALPNProtocols)
		})
	}
}

func fetchCapturedFingerprint(t *testing.T, captureURL string, profile *Profile) *CapturedFingerprint {
	t.Helper()

	target, err := url.Parse(captureURL)
	if err != nil || target.Scheme != "https" || target.Hostname() == "" || target.User != nil {
		t.Fatal("capture URL must be HTTPS without userinfo")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", captureURL, nil)
	if err != nil {
		t.Fatalf("create request: %v", err)
		return nil
	}
	transport, err := NewTransport(&http.Transport{
		DialTLSContext:  NewDialer(profile, nil).DialTLSContext,
		IdleConnTimeout: time.Second,
	}, profile)
	if err != nil {
		t.Fatal("capture transport:", err)
	}
	defer transport.CloseIdleConnections()
	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("capture returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		t.Fatalf("read body: %v", err)
		return nil
	}

	var fp CapturedFingerprint
	if err := json.Unmarshal(body, &fp); err != nil {
		t.Fatalf("parse response: %v", err)
		return nil
	}

	return &fp
}

func assertStringSliceEqual(t *testing.T, name string, expected, actual []string) {
	t.Helper()
	if len(expected) != len(actual) {
		t.Errorf("%s: length mismatch: got %d (%v), want %d (%v)", name, len(actual), actual, len(expected), expected)
		return
	}
	for i := range expected {
		if expected[i] != actual[i] {
			t.Errorf("%s[%d]: got %q, want %q", name, i, actual[i], expected[i])
			return
		}
	}
	t.Logf("  %s: %v OK", name, expected)
}

// TestBuildClientHelloSpecNewFields tests that new Profile fields are correctly applied.
func TestBuildClientHelloSpecNewFields(t *testing.T) {
	// Test custom ALPN, versions, key shares, PSK modes
	profile := &Profile{
		Name:                "custom_full",
		EnableGREASE:        false,
		CipherSuites:        []uint16{0x1301, 0x1302},
		Curves:              []uint16{29, 23},
		PointFormats:        []uint16{0},
		SignatureAlgorithms: []uint16{0x0403, 0x0804},
		ALPNProtocols:       []string{"h2", "http/1.1"},
		SupportedVersions:   []uint16{0x0304},
		KeyShareGroups:      []uint16{29, 23},
		PSKModes:            []uint16{1},
	}

	spec := buildClientHelloSpecFromProfile(profile)

	// Verify cipher suites
	if len(spec.CipherSuites) != 2 || spec.CipherSuites[0] != 0x1301 {
		t.Errorf("cipher suites: got %v", spec.CipherSuites)
	}

	// Check extensions for expected values
	var foundALPN, foundVersions, foundKeyShare, foundPSK, foundSigAlgs bool
	for _, ext := range spec.Extensions {
		switch e := ext.(type) {
		case *utls.ALPNExtension:
			foundALPN = true
			if len(e.AlpnProtocols) != 2 || e.AlpnProtocols[0] != "h2" {
				t.Errorf("ALPN: got %v, want [h2, http/1.1]", e.AlpnProtocols)
			}
		case *utls.SupportedVersionsExtension:
			foundVersions = true
			if len(e.Versions) != 1 || e.Versions[0] != 0x0304 {
				t.Errorf("versions: got %v, want [0x0304]", e.Versions)
			}
		case *utls.KeyShareExtension:
			foundKeyShare = true
			if len(e.KeyShares) != 2 {
				t.Errorf("key shares: got %d entries, want 2", len(e.KeyShares))
			}
		case *utls.PSKKeyExchangeModesExtension:
			foundPSK = true
			if len(e.Modes) != 1 || e.Modes[0] != 1 {
				t.Errorf("PSK modes: got %v, want [1]", e.Modes)
			}
		case *utls.SignatureAlgorithmsExtension:
			foundSigAlgs = true
			if len(e.SupportedSignatureAlgorithms) != 2 {
				t.Errorf("sig algs: got %d, want 2", len(e.SupportedSignatureAlgorithms))
			}
		}
	}

	for name, found := range map[string]bool{
		"ALPN": foundALPN, "Versions": foundVersions, "KeyShare": foundKeyShare,
		"PSK": foundPSK, "SigAlgs": foundSigAlgs,
	} {
		if !found {
			t.Errorf("extension %s not found in spec", name)
		}
	}

	// Test nil profile uses all defaults
	specDefault := buildClientHelloSpecFromProfile(nil)
	for _, ext := range specDefault.Extensions {
		switch e := ext.(type) {
		case *utls.ALPNExtension:
			if len(e.AlpnProtocols) != 1 || e.AlpnProtocols[0] != "http/1.1" {
				t.Errorf("default ALPN: got %v, want [http/1.1]", e.AlpnProtocols)
			}
		case *utls.SupportedVersionsExtension:
			if len(e.Versions) != 2 {
				t.Errorf("default versions: got %v, want 2 entries", e.Versions)
			}
		case *utls.KeyShareExtension:
			if len(e.KeyShares) != 1 {
				t.Errorf("default key shares: got %d, want 1", len(e.KeyShares))
			}
		}
	}

	t.Log("TestBuildClientHelloSpecNewFields passed")
}
