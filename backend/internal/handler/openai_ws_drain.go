package handler

import (
	"github.com/Wei-Shaw/sub2api/internal/pkg/wsdrain"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/coder/websocket"
)

func openAIDrainAttemptHooks(base *service.OpenAIWSIngressHooks, session *wsdrain.Session) (*service.OpenAIWSIngressHooks, func(), bool) {
	attempt, ok := session.BeginAttempt()
	if !ok {
		return nil, nil, false
	}
	hooks := *base
	hooks.BeforeRequest = func(turn int, payload []byte, model string) error {
		if !attempt.BeginTurn(turn) {
			return service.NewOpenAIWSClientCloseError(websocket.StatusServiceRestart, "server restarting", nil)
		}
		if base.BeforeRequest != nil {
			return base.BeforeRequest(turn, payload, model)
		}
		return nil
	}
	hooks.AfterClientTerminalWrite = func(turn int) {
		defer attempt.EndTurn(turn)
		if base.AfterClientTerminalWrite != nil {
			base.AfterClientTerminalWrite(turn)
		}
	}
	return &hooks, attempt.Release, true
}
