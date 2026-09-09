package middleware

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/antibypass"
)

type antiBypassFrameLease struct {
	decision antibypass.Decision
	done     chan struct{}
	finished chan struct{}
}

type antiBypassFrameSession struct {
	mu             sync.Mutex
	guard          *antibypass.Guard
	request        antibypass.Request
	config         antibypass.Config
	requestContext context.Context
	cancel         context.CancelFunc
	turn           int
	closed         bool
	leases         map[int]*antiBypassFrameLease
}

func (s *antiBypassFrameSession) Inspect(ctx context.Context, payload []byte, enabled bool) (antibypass.Detection, error) {
	var frame struct {
		Type    string `json:"type"`
		EventID string `json:"event_id"`
	}
	if json.Unmarshal(payload, &frame) != nil {
		return antibypass.Detection{}, nil
	}
	eventType := strings.TrimSpace(frame.Type)
	if eventType != "" && eventType != "response.create" {
		return antibypass.Detection{}, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return antibypass.Detection{Reason: antibypass.ReasonStorageUnavailable}, errors.New("frame session closed")
	}
	// Count all inference turns, including disabled ones, so a later toggle
	// cannot shift completion callbacks onto the wrong lease.
	s.turn++
	if !enabled {
		return antibypass.Detection{}, nil
	}
	if s.guard == nil || s.request.UserID <= 0 || s.request.APIKeyID <= 0 {
		return antibypass.Detection{Reason: antibypass.ReasonInvalidSubject}, errors.New("frame identity unavailable")
	}
	request := s.request
	request.Body = payload
	// event_id identifies a frame operation, not the parent HTTP trace.
	request.ClientRequestID = frame.EventID
	request.IdempotencyKey = ""
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	decision, err := s.guard.Check(ctx, s.config, request)
	cancel()
	if err != nil {
		return antibypass.Detection{Reason: antibypass.ReasonStorageUnavailable}, err
	}
	if !decision.Allowed {
		return antibypass.Detection{Reason: decision.Reason}, nil
	}
	lease := &antiBypassFrameLease{decision: decision, done: make(chan struct{}), finished: make(chan struct{})}
	s.leases[s.turn] = lease
	go func() {
		defer close(lease.finished)
		// The request's control context, not the short Redis-call context,
		// owns the admitted turn's lifetime.
		if err := s.guard.MaintainDecision(s.requestContext, decision, lease.done); err != nil {
			s.cancel()
		}
	}()
	return antibypass.Detection{}, nil
}

func (s *antiBypassFrameSession) Finish(turn int) {
	s.mu.Lock()
	lease := s.leases[turn]
	delete(s.leases, turn)
	s.mu.Unlock()
	if lease != nil {
		s.release(lease)
	}
}

func (s *antiBypassFrameSession) release(lease *antiBypassFrameLease) {
	close(lease.done)
	<-lease.finished
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	s.guard.ReleaseDecision(ctx, s.request.UserID, lease.decision)
}

func (s *antiBypassFrameSession) Close() {
	s.mu.Lock()
	s.closed = true
	leases := s.leases
	s.leases = nil
	s.mu.Unlock()
	s.cancel()
	for _, lease := range leases {
		s.release(lease)
	}
}
