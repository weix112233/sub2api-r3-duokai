package service

import (
	"context"
	"errors"
	"strconv"
	"strings"

	"github.com/Wei-Shaw/sub2api/internal/model"
	"github.com/Wei-Shaw/sub2api/internal/pkg/tlsfingerprint"
)

const SettingKeyOpenAIOAuthDefaultTLSProfileID = "openai_oauth_default_tls_profile_id"

type TLSProfileDefaults struct {
	OpenAIOAuthDefaultTLSProfileID int64 `json:"openai_oauth_default_tls_profile_id"`
}

func (s *TLSFingerprintProfileService) OpenAIOAuthDefaultProfile() *tlsfingerprint.Profile {
	if s == nil {
		return nil
	}
	s.localMu.RLock()
	id := s.openAIOAuthDefaultID
	s.localMu.RUnlock()
	if id == 0 {
		return nil
	}
	return s.GetProfileByID(id)
}

func (s *TLSFingerprintProfileService) GetDefaults(ctx context.Context) (TLSProfileDefaults, error) {
	if s.settings == nil {
		return TLSProfileDefaults{}, nil
	}
	raw, err := s.settings.GetValue(ctx, SettingKeyOpenAIOAuthDefaultTLSProfileID)
	if errors.Is(err, ErrSettingNotFound) {
		return TLSProfileDefaults{}, nil
	}
	if err != nil {
		return TLSProfileDefaults{}, err
	}
	if strings.TrimSpace(raw) == "" {
		return TLSProfileDefaults{}, nil
	}
	id, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || id < 0 {
		return TLSProfileDefaults{}, &model.ValidationError{Field: SettingKeyOpenAIOAuthDefaultTLSProfileID, Message: "invalid stored profile ID"}
	}
	return TLSProfileDefaults{OpenAIOAuthDefaultTLSProfileID: id}, nil
}

func (s *TLSFingerprintProfileService) SetDefaults(ctx context.Context, defaults TLSProfileDefaults) error {
	id := defaults.OpenAIOAuthDefaultTLSProfileID
	if id < 0 {
		return &model.ValidationError{Field: SettingKeyOpenAIOAuthDefaultTLSProfileID, Message: "profile ID must be nonnegative"}
	}
	if s.settings == nil {
		return errors.New("TLS profile settings repository unavailable")
	}
	if id > 0 {
		p, err := s.repo.GetByID(ctx, id)
		if err != nil {
			return err
		}
		if p == nil {
			return &model.ValidationError{Field: SettingKeyOpenAIOAuthDefaultTLSProfileID, Message: "profile not found"}
		}
		if err := p.Validate(); err != nil {
			return err
		}
	}
	if err := s.settings.Set(ctx, SettingKeyOpenAIOAuthDefaultTLSProfileID, strconv.FormatInt(id, 10)); err != nil {
		return err
	}
	s.localMu.Lock()
	s.openAIOAuthDefaultID = id
	s.localMu.Unlock()
	refreshCtx, cancel := s.newCacheRefreshContext()
	defer cancel()
	s.invalidateAndNotify(refreshCtx)
	return nil
}

func (s *TLSFingerprintProfileService) refreshDefaults(ctx context.Context) error {
	defaults, err := s.GetDefaults(ctx)
	s.localMu.Lock()
	defer s.localMu.Unlock()
	// Do not keep applying a stale operational default after a failed refresh.
	s.openAIOAuthDefaultID = defaults.OpenAIOAuthDefaultTLSProfileID
	return err
}
