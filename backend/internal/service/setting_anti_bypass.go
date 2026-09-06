package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// IsAntiBypassEnabled reads the dedicated gateway security switch. A missing
// legacy setting is treated as false so existing deployments remain unchanged.
func (s *SettingService) IsAntiBypassEnabled(ctx context.Context) (bool, error) {
	if s == nil || s.settingRepo == nil {
		return false, errors.New("anti-bypass setting repository is unavailable")
	}
	value, err := s.settingRepo.GetValue(ctx, SettingKeyAntiBypassEnabled)
	if errors.Is(err, ErrSettingNotFound) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("get anti-bypass setting: %w", err)
	}
	return strings.TrimSpace(value) == "true", nil
}
