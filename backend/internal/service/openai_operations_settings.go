package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

const SettingKeyOpenAIOperations = "openai_operations"

type OpenAIRecoverySettings struct {
	Enabled          bool `json:"enabled"`
	IntervalMinutes  int  `json:"interval_minutes"`
	FailureThreshold int  `json:"failure_threshold"`
	BackoffMinutes   int  `json:"backoff_minutes"`
	CooldownMinutes  int  `json:"cooldown_minutes"`
}

type OpenAIReasoningSettings struct {
	WindowHours int `json:"window_hours"`
	SampleLimit int `json:"sample_limit"`
	Threshold   int `json:"threshold"`
}

type OpenAINewAccountDefaults struct {
	ProxyID                 *int64  `json:"proxy_id"`
	EnableTLSFingerprint    *bool   `json:"enable_tls_fingerprint"`
	TLSFingerprintProfileID *int64  `json:"tls_fingerprint_profile_id"`
	CodexFingerprintMode    *string `json:"codex_fingerprint_mode"`
	Concurrency             *int    `json:"concurrency"`
}

type OpenAIOperationsSettings struct {
	Recovery           OpenAIRecoverySettings    `json:"recovery"`
	Reasoning          OpenAIReasoningSettings   `json:"reasoning"`
	NewAccountDefaults *OpenAINewAccountDefaults `json:"new_account_defaults"`
}

func DefaultOpenAIOperationsSettings() OpenAIOperationsSettings {
	return OpenAIOperationsSettings{
		Recovery:  OpenAIRecoverySettings{IntervalMinutes: 10, FailureThreshold: 5, BackoffMinutes: 360, CooldownMinutes: 10},
		Reasoning: OpenAIReasoningSettings{WindowHours: 24, SampleLimit: 1000, Threshold: 50},
	}
}

func (v OpenAIOperationsSettings) Validate() error {
	r := v.Recovery
	if r.IntervalMinutes < 5 || r.IntervalMinutes > 1440 || r.FailureThreshold < 1 || r.FailureThreshold > 100 ||
		r.BackoffMinutes < r.IntervalMinutes || r.BackoffMinutes > 10080 || r.CooldownMinutes < 1 || r.CooldownMinutes > 1440 {
		return fmt.Errorf("invalid recovery interval, failure threshold, backoff or cooldown")
	}
	if v.Reasoning.WindowHours < 1 || v.Reasoning.WindowHours > 168 ||
		v.Reasoning.SampleLimit < 1 || v.Reasoning.SampleLimit > 10000 ||
		v.Reasoning.Threshold < 2 || v.Reasoning.Threshold > v.Reasoning.SampleLimit {
		return fmt.Errorf("invalid reasoning observation window, limit or threshold")
	}
	if d := v.NewAccountDefaults; d != nil {
		if d.ProxyID != nil && *d.ProxyID < 0 {
			return fmt.Errorf("proxy_id must be nonnegative")
		}
		if d.TLSFingerprintProfileID != nil && *d.TLSFingerprintProfileID < -1 {
			return fmt.Errorf("invalid TLS profile ID")
		}
		if d.Concurrency != nil && (*d.Concurrency < 1 || *d.Concurrency > 1000) {
			return fmt.Errorf("concurrency must be between 1 and 1000")
		}
		if d.CodexFingerprintMode != nil {
			switch *d.CodexFingerprintMode {
			case "off", "device", "session", "full", "machine":
			default:
				return fmt.Errorf("invalid codex_fingerprint_mode")
			}
		}
	}
	return nil
}

func (s *SettingService) GetOpenAIOperationsSettings(ctx context.Context) (OpenAIOperationsSettings, error) {
	defaults := DefaultOpenAIOperationsSettings()
	if s == nil || s.settingRepo == nil {
		return defaults, nil
	}
	raw, err := s.settingRepo.GetValue(ctx, SettingKeyOpenAIOperations)
	if errors.Is(err, ErrSettingNotFound) || (err == nil && strings.TrimSpace(raw) == "") {
		return defaults, nil
	}
	if err != nil {
		return defaults, err
	}
	if err := json.Unmarshal([]byte(raw), &defaults); err != nil {
		return DefaultOpenAIOperationsSettings(), fmt.Errorf("invalid stored OpenAI operations settings")
	}
	if err := defaults.Validate(); err != nil {
		return DefaultOpenAIOperationsSettings(), err
	}
	return defaults, nil
}

func (s *SettingService) SetOpenAIOperationsSettings(ctx context.Context, value OpenAIOperationsSettings) error {
	if err := value.Validate(); err != nil {
		return err
	}
	if s == nil || s.settingRepo == nil {
		return fmt.Errorf("settings repository unavailable")
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return s.settingRepo.Set(ctx, SettingKeyOpenAIOperations, string(raw))
}

// A configured template is authoritative for its selected fields at creation
// only. Unconfigured fields retain each import entry's existing behavior.
func applyOpenAINewAccountDefaults(input *CreateAccountInput, defaults *OpenAINewAccountDefaults) *CreateAccountInput {
	if input == nil || input.Platform != PlatformOpenAI || defaults == nil {
		return input
	}
	out := *input
	out.Extra = shallowCopyMap(input.Extra)
	if out.Extra == nil {
		out.Extra = make(map[string]any)
	}
	if defaults.ProxyID != nil {
		out.ProxyID = nil
		if *defaults.ProxyID > 0 {
			id := *defaults.ProxyID
			out.ProxyID = &id
		}
	}
	if defaults.Concurrency != nil {
		out.Concurrency = *defaults.Concurrency
	}
	if defaults.EnableTLSFingerprint != nil {
		out.Extra["enable_tls_fingerprint"] = *defaults.EnableTLSFingerprint
	}
	if defaults.TLSFingerprintProfileID != nil {
		out.Extra["tls_fingerprint_profile_id"] = *defaults.TLSFingerprintProfileID
	}
	if defaults.CodexFingerprintMode != nil {
		out.Extra["codex_fingerprint_mode"] = *defaults.CodexFingerprintMode
	}
	return &out
}
