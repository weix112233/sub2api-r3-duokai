package tlsfingerprint

import (
	"encoding/json"
	"reflect"
	"testing"

	utls "github.com/refraction-networking/utls"
	"gopkg.in/yaml.v3"
)

func TestProfileALPNDefaultAndExplicitNone(t *testing.T) {
	for _, tc := range []struct {
		name string
		alpn []string
		want []string
	}{
		{"default", nil, []string{"http/1.1"}},
		{"none", []string{}, nil},
		{"http2", []string{"h2", "http/1.1"}, []string{"h2", "http/1.1"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec := buildClientHelloSpecFromProfile(&Profile{ALPNProtocols: tc.alpn})
			var got []string
			for _, ext := range spec.Extensions {
				if alpn, ok := ext.(*utls.ALPNExtension); ok {
					got = alpn.AlpnProtocols
				}
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("ALPN = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestProfileShufflePreservesConstraintsAndSource(t *testing.T) {
	profile := &Profile{
		ShuffleExtensions: true,
		Extensions:        []uint16{0x0a0a, 0, 10, 11, 13, 16, 21, 0x1a1a},
	}
	original := append([]uint16(nil), profile.Extensions...)
	orders := map[string]bool{}
	for i := 0; i < 32; i++ {
		spec := buildClientHelloSpecFromProfile(profile)
		if _, ok := spec.Extensions[0].(*utls.UtlsGREASEExtension); !ok {
			t.Fatal("leading GREASE moved")
		}
		if _, ok := spec.Extensions[7].(*utls.UtlsGREASEExtension); !ok {
			t.Fatal("trailing GREASE moved")
		}
		if _, ok := spec.Extensions[6].(*utls.UtlsPaddingExtension); !ok {
			t.Fatal("padding moved")
		}
		types := make([]string, len(spec.Extensions))
		for j, ext := range spec.Extensions {
			types[j] = reflect.TypeOf(ext).String()
		}
		key, _ := json.Marshal(types)
		orders[string(key)] = true
	}
	if len(orders) < 2 {
		t.Fatal("shuffle did not vary extension order")
	}
	if !reflect.DeepEqual(profile.Extensions, original) {
		t.Fatal("shuffle mutated source profile")
	}
	profile.ShuffleExtensions = false
	a := buildClientHelloSpecFromProfile(profile)
	b := buildClientHelloSpecFromProfile(profile)
	for i := range a.Extensions {
		if reflect.TypeOf(a.Extensions[i]) != reflect.TypeOf(b.Extensions[i]) {
			t.Fatal("disabled shuffle changed extension order")
		}
	}
}

func TestProfileConfigRoundtripPreservesExplicitValues(t *testing.T) {
	input := []byte("name: custom\nalpn_protocols: [h2]\nshuffle_extensions: true\nhttp2:\n  initial_window_size: 0\n  connection_window_update: 0\n  max_header_list_size: 0\n  enable_push: false\n")
	var p Profile
	if err := yaml.Unmarshal(input, &p); err != nil {
		t.Fatal(err)
	}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	wire, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	var got Profile
	if err := json.Unmarshal(wire, &got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(p, got) {
		t.Fatalf("roundtrip changed configuration: %s", wire)
	}
	if got.HTTP2.EnablePush == nil || *got.HTTP2.EnablePush ||
		got.HTTP2.InitialWindowSize == nil || *got.HTTP2.InitialWindowSize != 0 {
		t.Fatal("explicit zero/false lost")
	}
}

func TestProfileValidationAndDialerSnapshot(t *testing.T) {
	window := uint32(65536)
	p := &Profile{
		ALPNProtocols: []string{"h2"},
		HTTP2:         &HTTP2Config{InitialWindowSize: &window},
	}
	d := NewDialer(p, nil)
	p.ALPNProtocols[0] = "http/1.1"
	*p.HTTP2.InitialWindowSize = 1
	if d.profile.ALPNProtocols[0] != "h2" || *d.profile.HTTP2.InitialWindowSize != 65536 {
		t.Fatal("dialer retained mutable profile fields")
	}
	if err := p.Validate(); err == nil {
		t.Fatal("HTTP/2 without h2 ALPN accepted")
	}
	p.ALPNProtocols = []string{"h2"}
	p.Extensions = []uint16{0, 10}
	if err := p.Validate(); err == nil {
		t.Fatal("HTTP/2 without ALPN extension accepted")
	}
	p.Extensions = nil
	*p.HTTP2.InitialWindowSize = 1 << 31
	if err := p.Validate(); err == nil {
		t.Fatal("invalid stream window accepted")
	}
	p.HTTP2.InitialWindowSize = nil
	p.HTTP2.ConnectionWindowUpdate = new(uint32)
	*p.HTTP2.ConnectionWindowUpdate = (1 << 31) - 1
	if err := p.Validate(); err == nil {
		t.Fatal("overflowing connection window accepted")
	}
	var absent *Profile
	if absent.Clone() != nil {
		t.Fatal("nil profile clone is not nil")
	}
}
