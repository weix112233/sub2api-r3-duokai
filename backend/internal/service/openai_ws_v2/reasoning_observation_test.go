package openai_ws_v2

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestReasoningObservationRelayReplay(t *testing.T) {
	state := &relayState{}
	message := []byte(`{"type":"response.completed","response":{"usage":{"input_tokens":20,"output_tokens":100,"total_tokens":120,"output_tokens_details":{"reasoning_tokens":60}}}}`)
	usage := parseUsageAndAccumulate(state, message, "response.completed", nil)
	require.Equal(t, 60, usage.ReasoningTokens)
	require.Equal(t, 100, usage.OutputTokens)
	var accumulated Usage
	mergeRelayUsageNonZero(&accumulated, usage)
	mergeRelayUsageNonZero(&accumulated, usage)
	mergeRelayUsageNonZero(&accumulated, Usage{InputTokens: 20, OutputTokens: 100})
	require.Equal(t, 60, accumulated.ReasoningTokens)
	require.Equal(t, 100, accumulated.OutputTokens)
}
