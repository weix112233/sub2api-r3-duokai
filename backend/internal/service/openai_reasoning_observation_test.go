package service

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOpenAIReasoningObservationDoesNotDoubleBill(t *testing.T) {
	for _, document := range []string{
		`{"usage":{"input_tokens":20,"output_tokens":100,"total_tokens":120,"output_tokens_details":{"reasoning_tokens":60}}}`,
		`{"usage":{"prompt_tokens":20,"completion_tokens":100,"total_tokens":120,"completion_tokens_details":{"reasoning_tokens":60}}}`,
		`{"response":{"usage":{"input_tokens":20,"output_tokens":100,"total_tokens":120,"output_tokens_details":{"reasoning_tokens":60}}}}`,
	} {
		usage, ok := extractOpenAIUsageFromJSONBytes([]byte(document))
		require.True(t, ok)
		require.Equal(t, 60, usage.ReasoningTokens)
		require.Equal(t, 100, usage.OutputTokens)
		var accumulated OpenAIUsage
		mergeOpenAIUsageNonZero(&accumulated, usage)
		mergeOpenAIUsageNonZero(&accumulated, usage)
		mergeOpenAIUsageNonZero(&accumulated, OpenAIUsage{InputTokens: 20, OutputTokens: 100})
		require.Equal(t, 60, accumulated.ReasoningTokens, "terminal replay does not sum reasoning twice")
		require.Equal(t, 100, accumulated.OutputTokens)
	}
	svc := &OpenAIGatewayService{}
	var streamed OpenAIUsage
	event := `{"type":"response.completed","response":{"usage":{"input_tokens":20,"output_tokens":100,"total_tokens":120,"output_tokens_details":{"reasoning_tokens":60}}}}`
	svc.parseSSEUsage(event, &streamed)
	svc.parseSSEUsage(event, &streamed)
	require.Equal(t, 60, streamed.ReasoningTokens)
	require.Equal(t, 100, streamed.OutputTokens)
	negative, ok := extractOpenAIUsageFromJSONBytes([]byte(`{"usage":{"input_tokens":20,"output_tokens":100,"output_tokens_details":{"reasoning_tokens":-2}}}`))
	require.True(t, ok)
	require.Zero(t, negative.ReasoningTokens)
}
