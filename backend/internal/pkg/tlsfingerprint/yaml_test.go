package tlsfingerprint

import (
	"strings"
	"testing"
)

func TestParseProfileYAML(t *testing.T) {
	for _, text := range []string{
		"name: local\nalpn_protocols: []\nshuffle_extensions: true\n",
		"named:\n  name: local\n  alpn_protocols: []\n  shuffle_extensions: true\n",
	} {
		doc, err := ParseProfileYAML([]byte(text))
		if err != nil {
			t.Fatal(err)
		}
		if doc.ALPNProtocols == nil || len(doc.ALPNProtocols) != 0 || !doc.ShuffleExtensions {
			t.Fatal("explicit none or shuffle lost")
		}
	}
	doc, err := ParseProfileYAML([]byte("name: local\nalpn_protocols: [h2]\nhttp2:\n  initial_window_size: 0\n  connection_window_update: 0\n  max_header_list_size: 0\n  enable_push: false\n"))
	if err != nil {
		t.Fatal(err)
	}
	if doc.HTTP2.EnablePush == nil || *doc.HTTP2.EnablePush || *doc.HTTP2.InitialWindowSize != 0 {
		t.Fatal("explicit zero/false lost")
	}
}

func TestParseProfileYAMLRejectsInvalidDocuments(t *testing.T) {
	for _, text := range []string{
		"", "[]", "name: one\nname: two", "name: local\nunknown: true",
		"name: local\nhttp2:\n  ignored: 3", "name: local\n---\nname: other",
		"name: local\nalpn_protocols: []\nhttp2:\n  enable_push: true",
		"name: local\nshuffle_extensions: maybe",
		"name: local\nalpn_protocols: [h2]\nhttp2:\n  initial_window_size: -1",
		"name: local\nalpn_protocols: [h2]\nhttp2:\n  enable_push: true\n  enable_push: false",
		strings.Repeat(" ", MaxProfileYAMLBytes+1),
	} {
		if _, err := ParseProfileYAML([]byte(text)); err == nil {
			t.Errorf("accepted invalid document of length %d", len(text))
		}
	}
}

func TestProfileTransportKey(t *testing.T) {
	p := &Profile{Name: "one"}
	key := p.TransportKey()
	p.Name = "renamed"
	if p.TransportKey() != key {
		t.Fatal("name changed wire key")
	}
	p.ALPNProtocols = []string{}
	if p.TransportKey() == key {
		t.Fatal("nil and empty ALPN conflated")
	}
	p.ALPNProtocols = []string{"h2"}
	p.HTTP2 = &HTTP2Config{EnablePush: new(bool)}
	key = p.TransportKey()
	*p.HTTP2.EnablePush = true
	if p.TransportKey() == key {
		t.Fatal("HTTP/2 edit retained transport key")
	}
}
