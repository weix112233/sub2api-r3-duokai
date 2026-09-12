package http2

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"golang.org/x/net/http2/hpack"
)

func profilePointer[T any](v T) *T { return &v }

func profilePeer(t *testing.T, tr *Transport) (*ClientConn, *Framer, map[SettingID]uint32) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	dialed := make(chan net.Conn, 1)
	go func() {
		c, err := net.DialTimeout("tcp", ln.Addr().String(), time.Second)
		if err == nil {
			dialed <- c
		} else {
			dialed <- nil
		}
	}()
	peer, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	peer.SetDeadline(time.Now().Add(5 * time.Second))
	t.Cleanup(func() { peer.Close() })
	client := <-dialed
	if client == nil {
		t.Fatal("client dial failed")
	}
	cc, err := tr.NewClientConn(client)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cc.Close() })
	preface := make([]byte, len(ClientPreface))
	if _, err := io.ReadFull(peer, preface); err != nil || string(preface) != ClientPreface {
		t.Fatal("client preface:", err)
	}
	fr := NewFramer(peer, peer)
	frame, err := fr.ReadFrame()
	if err != nil {
		t.Fatal(err)
	}
	settings, ok := frame.(*SettingsFrame)
	if !ok {
		t.Fatalf("first frame: %T", frame)
	}
	values := make(map[SettingID]uint32)
	settings.ForeachSetting(func(s Setting) error { values[s.ID] = s.Val; return nil })
	if err := fr.WriteSettings(); err != nil {
		t.Fatal(err)
	}
	if err := fr.WriteSettingsAck(); err != nil {
		t.Fatal(err)
	}
	return cc, fr, values
}

func TestProfileInitialFramesAndWindows(t *testing.T) {
	for _, tc := range []struct {
		name                  string
		stream, conn, headers uint32
		push                  bool
	}{
		{"zero", 0, 0, 0, false},
		{"small", 1024, 4096, 32768, true},
		{"boundary", 1<<31 - 1, 1<<31 - 1 - 65535, 1<<32 - 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tr := &Transport{
				InitialWindowSize:      profilePointer(tc.stream),
				ConnectionWindowUpdate: profilePointer(tc.conn),
				HeaderListSize:         profilePointer(tc.headers), EnablePush: profilePointer(tc.push),
			}
			cc, fr, settings := profilePeer(t, tr)
			if settings[SettingInitialWindowSize] != tc.stream ||
				settings[SettingMaxHeaderListSize] != tc.headers ||
				(settings[SettingEnablePush] == 1) != tc.push {
				t.Fatal("wire settings differ:", settings)
			}
			cc.mu.Lock()
			window, stream := cc.inflow.avail, cc.initialStreamRecvWindowSize
			cc.mu.Unlock()
			if window != int32(tc.conn)+65535 || stream != int32(tc.stream) ||
				cc.fr.maxHeaderListSize() != tc.headers {
				t.Fatalf("runtime windows differ: %d %d", window, stream)
			}
			f, err := fr.ReadFrame()
			if err != nil {
				t.Fatal(err)
			}
			if tc.conn == 0 {
				if ack, ok := f.(*SettingsFrame); !ok || !ack.IsAck() {
					t.Fatalf("zero connection update emitted a frame: %T", f)
				}
			} else if update, ok := f.(*WindowUpdateFrame); !ok || update.Increment != tc.conn {
				t.Fatalf("connection update: %#v", f)
			}
		})
	}
}

func TestProfilePushCancellationKeepsHPACK(t *testing.T) {
	tr := &Transport{EnablePush: profilePointer(true), ConnectionWindowUpdate: profilePointer(uint32(0))}
	cc, fr, _ := profilePeer(t, tr)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://localhost/", nil)
	result := make(chan error, 1)
	go func() {
		resp, err := cc.RoundTrip(req)
		if err == nil {
			data, readErr := io.ReadAll(resp.Body)
			resp.Body.Close()
			if readErr != nil {
				err = readErr
			} else if string(data) != "ok" || resp.Header.Get("X-Push-State") != "dynamic" {
				err = io.ErrUnexpectedEOF
			}
		}
		result <- err
	}()
	var stream uint32
	for stream == 0 {
		f, err := fr.ReadFrame()
		if err != nil {
			t.Fatal(err)
		}
		if headers, ok := f.(*HeadersFrame); ok {
			stream = headers.StreamID
		}
	}
	var block bytes.Buffer
	enc := hpack.NewEncoder(&block)
	for _, h := range []hpack.HeaderField{
		{Name: ":method", Value: "GET"}, {Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: "localhost"}, {Name: ":path", Value: "/push"},
		{Name: "x-push-state", Value: "dynamic"},
	} {
		enc.WriteField(h)
	}
	data := append([]byte(nil), block.Bytes()...)
	if err := fr.WritePushPromise(PushPromiseParam{StreamID: stream, PromiseID: 2, BlockFragment: data[:2]}); err != nil {
		t.Fatal(err)
	}
	if err := fr.WriteContinuation(stream, true, data[2:]); err != nil {
		t.Fatal(err)
	}
	for {
		f, err := fr.ReadFrame()
		if err != nil {
			t.Fatal(err)
		}
		if rst, ok := f.(*RSTStreamFrame); ok {
			if rst.StreamID != 2 || rst.ErrCode != ErrCodeCancel {
				t.Fatalf("unexpected push reset: %#v", rst)
			}
			break
		}
	}
	block.Reset()
	enc.WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
	enc.WriteField(hpack.HeaderField{Name: "x-push-state", Value: "dynamic"})
	if err := fr.WriteHeaders(HeadersFrameParam{StreamID: stream, BlockFragment: block.Bytes(), EndHeaders: true}); err != nil {
		t.Fatal(err)
	}
	if err := fr.WriteData(stream, true, []byte("ok")); err != nil {
		t.Fatal(err)
	}
	if err := <-result; err != nil {
		t.Fatal("push corrupted following response:", err)
	}
}

func TestProfileRejectsPeerViolations(t *testing.T) {
	for _, kind := range []string{"headers-zero", "stream-window-zero", "push-disabled", "push-odd-id", "push-bad-compression"} {
		t.Run(kind, func(t *testing.T) {
			tr := &Transport{ConnectionWindowUpdate: profilePointer(uint32(0))}
			switch kind {
			case "headers-zero":
				tr.HeaderListSize = profilePointer(uint32(0))
			case "stream-window-zero":
				tr.InitialWindowSize = profilePointer(uint32(0))
			case "push-odd-id", "push-bad-compression":
				tr.EnablePush = profilePointer(true)
			default:
				tr.EnablePush = profilePointer(false)
			}
			cc, fr, _ := profilePeer(t, tr)
			req, _ := http.NewRequestWithContext(t.Context(), "GET", "https://localhost/", nil)
			done := make(chan error, 1)
			go func() {
				resp, err := cc.RoundTrip(req)
				if err == nil {
					_, err = io.ReadAll(resp.Body)
					resp.Body.Close()
				}
				done <- err
			}()
			var stream uint32
			for stream == 0 {
				f, err := fr.ReadFrame()
				if err != nil {
					t.Fatal(err)
				}
				if h, ok := f.(*HeadersFrame); ok {
					stream = h.StreamID
				}
			}
			if kind == "headers-zero" || kind == "stream-window-zero" {
				var headers bytes.Buffer
				hpack.NewEncoder(&headers).WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
				if err := fr.WriteHeaders(HeadersFrameParam{StreamID: stream, EndHeaders: true, BlockFragment: headers.Bytes()}); err != nil {
					t.Fatal(err)
				}
				if kind == "stream-window-zero" {
					if err := fr.WriteData(stream, true, []byte("exceeds-zero-window")); err != nil {
						t.Fatal(err)
					}
				}
			} else {
				id := uint32(2)
				if kind == "push-odd-id" {
					id = 3
				}
				if err := fr.WritePushPromise(PushPromiseParam{StreamID: stream, PromiseID: id, EndHeaders: true, BlockFragment: []byte{0xff, 0xff}}); err != nil {
					t.Fatal(err)
				}
			}
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("peer violation was silently accepted")
				}
			case <-time.After(2 * time.Second):
				t.Fatal("peer violation did not terminate the affected request")
			}
		})
	}
}

type retryProfilePool struct {
	cc    *ClientConn
	calls int
}

func (p *retryProfilePool) GetClientConn(*http.Request, string) (*ClientConn, error) {
	p.calls++
	if p.calls > 1 {
		return nil, ErrNoCachedConn
	}
	return p.cc, nil
}
func (*retryProfilePool) MarkDead(*ClientConn) {}

func TestProfileRetryPreservesRegeneratedBody(t *testing.T) {
	tr := &Transport{ConnectionWindowUpdate: profilePointer(uint32(0))}
	cc, fr, _ := profilePeer(t, tr)
	request, _ := http.NewRequestWithContext(t.Context(), "POST", "https://localhost/", bytes.NewBufferString("replay-body"))
	done := make(chan error, 1)
	pool := &retryProfilePool{cc: cc}
	go func() {
		_, err := tr.roundTripViaPool(request, RoundTripOpt{}, pool)
		done <- err
	}()
	var stream uint32
	for stream == 0 {
		f, err := fr.ReadFrame()
		if err != nil {
			t.Fatal(err)
		}
		if d, ok := f.(*DataFrame); ok && d.StreamEnded() {
			stream = d.StreamID
		}
	}
	if err := fr.WriteRSTStream(stream, ErrCodeRefusedStream); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		var retry *NeedsConnectionError
		if !errors.As(err, &retry) {
			t.Fatalf("missing retry request: %v", err)
		}
		if retry.Request == request {
			t.Fatal("retry returned the consumed request")
		}
		body, err := io.ReadAll(retry.Request.Body)
		retry.Request.Body.Close()
		if err != nil || string(body) != "replay-body" {
			t.Fatalf("lost regenerated body: %q %v", body, err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("retry blocked")
	}
}
