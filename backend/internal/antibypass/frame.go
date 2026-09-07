package antibypass

import "context"

type frameInspectorKey struct{}
type frameTurnFinisherKey struct{}

// FrameInspector lets the HTTP admission policy follow upgraded connections
// without coupling the transport service to HTTP middleware.
type FrameInspector func(context.Context, []byte) (Detection, error)

func WithFrameInspector(ctx context.Context, inspector FrameInspector) context.Context {
	return context.WithValue(ctx, frameInspectorKey{}, inspector)
}

func InspectFrame(ctx context.Context, payload []byte) (Detection, error) {
	if ctx == nil {
		return Detection{}, nil
	}
	inspector, _ := ctx.Value(frameInspectorKey{}).(FrameInspector)
	if inspector == nil {
		return Detection{}, nil
	}
	return inspector(ctx, payload)
}

func WithFrameTurnFinisher(ctx context.Context, finish func(int)) context.Context {
	return context.WithValue(ctx, frameTurnFinisherKey{}, finish)
}

// FinishFrameTurn releases only the named accepted turn, never a later attempt.
func FinishFrameTurn(ctx context.Context, turn int) {
	if ctx == nil {
		return
	}
	if finish, ok := ctx.Value(frameTurnFinisherKey{}).(func(int)); ok {
		finish(turn)
	}
}

func IsAdmissionLimit(reason Reason) bool {
	switch reason {
	case ReasonRPM, ReasonConcurrency, ReasonDistinctKeys, ReasonDistinctIPs,
		ReasonDistinctFingerprints, ReasonReplay, ReasonDuplicateRequest:
		return true
	default:
		return false
	}
}
