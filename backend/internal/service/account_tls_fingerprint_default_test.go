package service

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNormalizeTLSFingerprintExtraForCreate(t *testing.T) {
	tests := []struct {
		name     string
		account  *Account
		expected bool
		hasValue bool
	}{
		{
			name:     "anthropic oauth defaults enabled",
			account:  &Account{Platform: PlatformAnthropic, Type: AccountTypeOAuth},
			expected: true,
			hasValue: true,
		},
		{
			name:     "anthropic setup token defaults enabled",
			account:  &Account{Platform: PlatformAnthropic, Type: AccountTypeSetupToken},
			expected: true,
			hasValue: true,
		},
		{
			name: "explicit false is preserved",
			account: &Account{
				Platform: PlatformAnthropic,
				Type:     AccountTypeOAuth,
				Extra:    map[string]any{"enable_tls_fingerprint": false},
			},
			expected: false,
			hasValue: true,
		},
		{
			name:     "anthropic api key is unchanged",
			account:  &Account{Platform: PlatformAnthropic, Type: AccountTypeAPIKey},
			hasValue: false,
		},
		{
			name:     "openai oauth defaults enabled",
			account:  &Account{Platform: PlatformOpenAI, Type: AccountTypeOAuth},
			expected: true,
			hasValue: true,
		},
		{
			name: "openai oauth explicit false is preserved",
			account: &Account{
				Platform: PlatformOpenAI,
				Type:     AccountTypeOAuth,
				Extra:    map[string]any{"enable_tls_fingerprint": false},
			},
			expected: false,
			hasValue: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			NormalizeTLSFingerprintExtraForCreate(tt.account)
			value, ok := tt.account.Extra["enable_tls_fingerprint"].(bool)
			assert.Equal(t, tt.hasValue, ok)
			if ok {
				assert.Equal(t, tt.expected, value)
			}
		})
	}
}
