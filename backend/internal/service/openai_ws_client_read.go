package service

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/antibypass"
	coderws "github.com/coder/websocket"
)

type openAIWSClientReadResult struct {
	messageType coderws.MessageType
	payload     []byte
	err         error
}

// ReadOpenAIWSClientMessage keeps one reader alive while control events send
// their close frame, then closes the transport and joins that reader.
func ReadOpenAIWSClientMessage(
	controlCtx context.Context,
	conn *coderws.Conn,
	timeout time.Duration,
	timeoutStatus coderws.StatusCode,
	timeoutReason string,
) (coderws.MessageType, []byte, error) {
	return readOpenAIWSClientMessageWithTimeoutStart(
		controlCtx,
		conn,
		timeout,
		timeoutStatus,
		timeoutReason,
		nil,
		nil,
	)
}

// readOpenAIWSClientMessageWithTimeoutStart supports readers whose timeout
// starts after a state transition, such as a completed passthrough turn. When
// timeoutActive is nil, a positive timeout starts immediately.
func readOpenAIWSClientMessageWithTimeoutStart(
	controlCtx context.Context,
	conn *coderws.Conn,
	timeout time.Duration,
	timeoutStatus coderws.StatusCode,
	timeoutReason string,
	timeoutStart <-chan struct{},
	timeoutActive func() bool,
) (coderws.MessageType, []byte, error) {
	if conn == nil {
		return 0, nil, errors.New("openai websocket client connection is nil")
	}
	if controlCtx == nil {
		controlCtx = context.Background()
	}

	readDone := make(chan openAIWSClientReadResult, 1)
	go func() {
		messageType, payload, err := conn.Read(context.Background())
		readDone <- openAIWSClientReadResult{messageType: messageType, payload: payload, err: err}
	}()

	var timer *time.Timer
	var timeoutCh <-chan time.Time
	startTimeout := func() {
		if timeout <= 0 || (timeoutActive != nil && !timeoutActive()) {
			return
		}
		if timer == nil {
			timer = time.NewTimer(timeout)
		} else {
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(timeout)
		}
		timeoutCh = timer.C
	}
	if timeoutActive == nil || timeoutActive() {
		startTimeout()
	}
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()

	closeAndJoin := func(status coderws.StatusCode, reason string, cause error) (coderws.MessageType, []byte, error) {
		_ = conn.Close(status, reason)
		_ = conn.CloseNow()
		<-readDone
		return 0, nil, NewOpenAIWSClientCloseError(status, reason, cause)
	}

	for {
		select {
		case result := <-readDone:
			if result.err == nil {
				detection, inspectionErr := antibypass.InspectFrame(controlCtx, result.payload)
				if inspectionErr != nil || detection.Reason != antibypass.ReasonNone {
					status := coderws.StatusPolicyViolation
					code := "ANTI_BYPASS_PROMPT_BLOCKED"
					errorType := "invalid_request_error"
					if inspectionErr != nil {
						status = coderws.StatusTryAgainLater
						code = "ANTI_BYPASS_UNAVAILABLE"
						errorType = "server_error"
					} else if detection.Reason == antibypass.ReasonBodyTooLarge {
						status = coderws.StatusMessageTooBig
						code = "ANTI_BYPASS_BODY_TOO_LARGE"
					} else if detection.Reason == antibypass.ReasonPromptInspectionLimit {
						status = coderws.StatusPolicyViolation
						code = "ANTI_BYPASS_INSPECTION_LIMIT"
					} else if antibypass.IsAdmissionLimit(detection.Reason) {
						status = coderws.StatusTryAgainLater
						code = "ANTI_BYPASS_BLOCKED"
						errorType = "rate_limit_error"
					}
					slog.Warn("anti_bypass_ws_frame_blocked", "reason", detection.Reason, "code", code)
					event, _ := json.Marshal(map[string]any{
						"type": "error",
						"error": map[string]any{"type": errorType, "code": code, "reason": detection.Reason,
							"message": "WebSocket frame blocked by gateway security policy"},
					})
					writeCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
					_ = conn.Write(writeCtx, coderws.MessageText, event)
					cancel()
					_ = conn.Close(status, code)
					_ = conn.CloseNow()
					return 0, nil, NewOpenAIWSClientCloseError(status, code, inspectionErr)
				}
			}
			return result.messageType, result.payload, result.err
		case <-timeoutStart:
			startTimeout()
		case <-timeoutCh:
			return closeAndJoin(timeoutStatus, timeoutReason, context.DeadlineExceeded)
		case <-controlCtx.Done():
			cause := context.Cause(controlCtx)
			if errors.Is(cause, ErrOpenAIWSIngressLeaseLost) {
				return closeAndJoin(
					coderws.StatusTryAgainLater,
					"websocket ingress capacity lease lost; please reconnect",
					cause,
				)
			}
			return closeAndJoin(coderws.StatusGoingAway, "websocket request canceled", cause)
		}
	}
}
