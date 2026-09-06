package antibypass

import "context"

type frameInspectorKey struct{}

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
