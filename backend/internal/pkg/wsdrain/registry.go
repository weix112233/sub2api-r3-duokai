package wsdrain

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	gorilla "github.com/gorilla/websocket"
)

type contextKey struct{}

type Registry struct {
	mu              sync.Mutex
	draining        bool
	sessions        map[*Session]struct{}
	done            chan struct{}
	doneClosed      bool
	pendingUpgrades int
}

type Session struct {
	registry        *Registry
	closeGracefully func()
	closeNow        func()
	active          bool
	turn            int
	closing         bool
	generation      uint64
}

type Attempt struct {
	session    *Session
	generation uint64
}

type Stats struct {
	Connections     int
	Active          int
	Closing         int
	PendingUpgrades int
}

func (r *Registry) Snapshot() Stats {
	r.mu.Lock()
	defer r.mu.Unlock()
	stats := Stats{Connections: len(r.sessions), PendingUpgrades: r.pendingUpgrades}
	for session := range r.sessions {
		if session.active {
			stats.Active++
		}
		if session.closing {
			stats.Closing++
		}
	}
	return stats
}

func upgradeRequested(header http.Header) bool {
	for _, value := range header.Values("Upgrade") {
		for _, token := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(token), "websocket") {
				return true
			}
		}
	}
	return false
}

func New() *Registry {
	return &Registry{sessions: make(map[*Session]struct{}), done: make(chan struct{})}
}

func (r *Registry) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.mu.Lock()
		draining := r.draining
		upgrade := !draining && upgradeRequested(req.Header)
		if upgrade {
			r.pendingUpgrades++
		}
		r.mu.Unlock()
		if draining {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Retry-After", "5")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"error":{"code":"server_restarting","message":"Server is restarting"}}`))
			return
		}
		if upgrade {
			defer func() {
				r.mu.Lock()
				r.pendingUpgrades--
				r.finishLocked()
				r.mu.Unlock()
			}()
		}
		next.ServeHTTP(w, req.WithContext(context.WithValue(req.Context(), contextKey{}, r)))
	})
}

// Continuous sessions stay active until their handler exits. Responses sessions
// instead call BeginTurn/EndTurn, allowing graceful close at a turn boundary.
func Track(ctx context.Context, conn *websocket.Conn, continuous bool) *Session {
	return track(ctx, continuous,
		func() { _ = conn.Close(websocket.StatusServiceRestart, "server restarting") },
		func() { _ = conn.CloseNow() },
	)
}

func TrackGorilla(ctx context.Context, conn *gorilla.Conn) *Session {
	return track(ctx, false, func() {
		_ = conn.WriteControl(gorilla.CloseMessage,
			gorilla.FormatCloseMessage(gorilla.CloseServiceRestart, "server restarting"),
			time.Now().Add(time.Second))
		_ = conn.Close()
	}, func() { _ = conn.Close() })
}

func track(ctx context.Context, continuous bool, closeGracefully, closeNow func()) *Session {
	r, _ := ctx.Value(contextKey{}).(*Registry)
	session := &Session{registry: r, closeGracefully: closeGracefully, closeNow: closeNow, active: continuous}
	if r == nil {
		return session
	}
	r.mu.Lock()
	if r.doneClosed {
		session.closing = true
		r.mu.Unlock()
		closeNow()
		return session
	}
	r.sessions[session] = struct{}{}
	if r.draining {
		session.closeLocked()
	}
	r.mu.Unlock()
	return session
}

// Each invocation of the forwarder has its own local turn numbering. Capture
// the generation in immutable callbacks so an earlier attempt cannot end it.
func (s *Session) BeginAttempt() (*Attempt, bool) {
	if s == nil || s.registry == nil {
		return &Attempt{session: s}, true
	}
	r := s.registry
	r.mu.Lock()
	defer r.mu.Unlock()
	if s.closing || r.draining {
		return nil, false
	}
	s.generation++
	s.turn = 1
	s.active = true
	return &Attempt{session: s, generation: s.generation}, true
}

func (a *Attempt) BeginTurn(turn int) bool {
	if a == nil || a.session == nil || a.session.registry == nil {
		return true
	}
	s := a.session
	r := s.registry
	r.mu.Lock()
	defer r.mu.Unlock()
	if a.generation != s.generation || s.closing || turn <= 0 || turn < s.turn {
		return false
	}
	if s.active && s.turn == turn {
		return true
	}
	if r.draining {
		return false
	}
	s.active = true
	s.turn = turn
	return true
}

func (a *Attempt) EndTurn(turn int) {
	if a == nil || a.session == nil || a.session.registry == nil {
		return
	}
	s := a.session
	r := s.registry
	r.mu.Lock()
	if a.generation == s.generation && s.turn == turn {
		s.active = false
		if r.draining {
			s.closeLocked()
		}
	}
	r.mu.Unlock()
}

func (a *Attempt) Release() {
	if a == nil || a.session == nil || a.session.registry == nil {
		return
	}
	s := a.session
	r := s.registry
	r.mu.Lock()
	if a.generation == s.generation {
		s.active = false
		if r.draining {
			s.closeLocked()
		}
	}
	r.mu.Unlock()
}

func (s *Session) closeLocked() {
	if s.closing {
		return
	}
	s.closing = true
	go s.closeGracefully()
}

func (s *Session) Release() {
	if s == nil || s.registry == nil {
		return
	}
	r := s.registry
	r.mu.Lock()
	s.generation++
	s.closing = true
	delete(r.sessions, s)
	r.finishLocked()
	r.mu.Unlock()
}

func (r *Registry) finishLocked() {
	if r.draining && len(r.sessions) == 0 && r.pendingUpgrades == 0 && !r.doneClosed {
		r.doneClosed = true
		close(r.done)
	}
}

func (r *Registry) BeginDrain() {
	r.mu.Lock()
	r.draining = true
	for s := range r.sessions {
		if !s.active {
			s.closeLocked()
		}
	}
	r.finishLocked()
	r.mu.Unlock()
}

func (r *Registry) Count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.sessions)
}

func (r *Registry) Wait(ctx context.Context) error {
	select {
	case <-r.done:
		return nil
	default:
	}
	select {
	case <-r.done:
		return nil
	case <-ctx.Done():
		r.mu.Lock()
		sessions := make([]*Session, 0, len(r.sessions))
		for s := range r.sessions {
			sessions = append(sessions, s)
		}
		r.mu.Unlock()
		for _, s := range sessions {
			s.closeNow()
		}
		return ctx.Err()
	}
}
