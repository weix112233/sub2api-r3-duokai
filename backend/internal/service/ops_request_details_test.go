package service

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestOpsRequestDetailJSONIncludesNullFirstToken(t *testing.T) {
	payload, err := json.Marshal(OpsRequestDetail{
		Kind:      OpsRequestKindError,
		CreatedAt: time.Date(2026, 9, 2, 9, 0, 0, 0, time.UTC),
		RequestID: "req-anonymous",
		Stream:    true,
	})
	require.NoError(t, err)

	var decoded map[string]any
	require.NoError(t, json.Unmarshal(payload, &decoded))
	value, exists := decoded["first_token_ms"]
	require.True(t, exists)
	require.Nil(t, value)
}
