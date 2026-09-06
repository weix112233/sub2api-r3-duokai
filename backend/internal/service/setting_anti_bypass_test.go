package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIsAntiBypassEnabledFailsClosedWithoutSettingRepository(t *testing.T) {
	var service *SettingService

	enabled, err := service.IsAntiBypassEnabled(context.Background())

	require.False(t, enabled)
	require.Error(t, err)
}
