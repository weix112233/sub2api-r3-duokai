package service

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestOpenAIProxyChainFailureQuarantinesSharedProxyAcrossAccounts(t *testing.T) {
	proxyID := int64(77)
	svc := &OpenAIGatewayService{
		openaiProxyStreamCircuit: newOpenAIProxyStreamCircuit(openAIProxyStreamCircuitSettings{
			failureThreshold: 2,
			failureWindow:    time.Minute,
			quarantineTTL:    10 * time.Minute,
			collapseInterval: 0,
			maxEntries:       16,
		}),
	}
	first := &Account{ID: 101, Platform: PlatformOpenAI, ProxyID: &proxyID}
	second := &Account{ID: 102, Platform: PlatformOpenAI, ProxyID: &proxyID}

	svc.recordOpenAIProxyChainFailure(first, errors.New("proxy chain unavailable"), "req-1")
	require.True(t, svc.isOpenAIProxyStreamQuarantined(nil, first))
	require.True(t, svc.isOpenAIProxyStreamQuarantined(nil, second))
}

func TestOpenAIProxyQuarantineRemainsFailClosedWhenAllCandidatesAreBlocked(t *testing.T) {
	proxyID := int64(78)
	svc := &OpenAIGatewayService{
		openaiProxyStreamCircuit: newOpenAIProxyStreamCircuit(openAIProxyStreamCircuitSettings{
			failureThreshold: 1,
			failureWindow:    time.Minute,
			quarantineTTL:    10 * time.Minute,
			maxEntries:       16,
		}),
	}
	account := &Account{ID: 103, Platform: PlatformOpenAI, ProxyID: &proxyID}
	svc.openaiProxyStreamCircuit.recordFailure(proxyID, time.Now())

	require.True(t, svc.isOpenAIProxyStreamQuarantined(nil, account))
}

func TestCONNECTQuarantineIgnoresOldStreamSuccessAndExpiresPromptly(t *testing.T) {
	circuit := newOpenAIProxyStreamCircuit(openAIProxyStreamCircuitSettings{})
	now := time.Now()
	_, until := circuit.quarantine(9, now)
	require.Equal(t, now.Add(5*time.Second), until)
	require.False(t, circuit.recordSuccess(9))
	require.True(t, circuit.isBlocked(9, now.Add(time.Second)))
	require.False(t, circuit.isBlocked(9, now.Add(5*time.Second)))
}

func TestExpiredCONNECTQuarantineDoesNotContaminateStreamFailureHistory(t *testing.T) {
	circuit := newOpenAIProxyStreamCircuit(openAIProxyStreamCircuitSettings{})
	now := time.Now()
	circuit.quarantine(9, now)
	tripped, _ := circuit.recordFailure(9, now.Add(6*time.Second))
	require.False(t, tripped)
	require.True(t, circuit.recordSuccess(9))
	require.False(t, circuit.isBlocked(9, now.Add(7*time.Second)))
}
