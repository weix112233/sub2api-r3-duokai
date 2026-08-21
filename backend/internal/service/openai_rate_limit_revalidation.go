package service

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"sync"
	"time"
)

const (
	openAIRateLimitRevalidationInterval = 5 * time.Minute
	openAIRateLimitRevalidationTimeout  = 20 * time.Second
	openAIRateLimitRevalidationWorkers  = 3
)

type openAIRateLimitCandidateRepository interface {
	ListRateLimitedOpenAIOAuth(ctx context.Context) ([]Account, error)
}

type openAIRateLimitRevalidationCandidateRepository interface {
	ListOpenAIRateLimitRevalidationCandidates(ctx context.Context) ([]Account, error)
}

type openAIRateLimitRecoveryRepository interface {
	ClearOpenAIRateLimitIfObserved(ctx context.Context, id int64, observedLimitedAt, observedResetAt time.Time) (bool, error)
}

type openAIRateLimitProbe interface {
	RevalidateOpenAIRateLimit(ctx context.Context, accountID int64) (bool, error)
}

// OpenAIRateLimitRevalidationService periodically rechecks accounts with either
// a local rate-limit generation or an explicit exhausted 7-day quota snapshot.
// A provider-confirmed success can clear that exact local generation; ordinary
// network/upstream failures cannot.
type OpenAIRateLimitRevalidationService struct {
	candidates openAIRateLimitCandidateRepository
	probe      openAIRateLimitProbe
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	mu         sync.Mutex
}

func NewOpenAIRateLimitRevalidationService(
	candidates openAIRateLimitCandidateRepository,
	probe openAIRateLimitProbe,
) *OpenAIRateLimitRevalidationService {
	if candidates == nil || probe == nil {
		return nil
	}
	return &OpenAIRateLimitRevalidationService{
		candidates: candidates,
		probe:      probe,
	}
}

func (s *OpenAIRateLimitRevalidationService) Start() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cancel != nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.run(ctx)
	}()
}

func (s *OpenAIRateLimitRevalidationService) run(ctx context.Context) {
	s.revalidateOnce(ctx)
	ticker := time.NewTicker(openAIRateLimitRevalidationInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.revalidateOnce(ctx)
		}
	}
}

func (s *OpenAIRateLimitRevalidationService) revalidateOnce(ctx context.Context) {
	var (
		accounts []Account
		err      error
	)
	if candidates, ok := s.candidates.(openAIRateLimitRevalidationCandidateRepository); ok {
		accounts, err = candidates.ListOpenAIRateLimitRevalidationCandidates(ctx)
	} else {
		accounts, err = s.candidates.ListRateLimitedOpenAIOAuth(ctx)
	}
	if err != nil {
		slog.Warn("openai_rate_limit_revalidation_list_failed", "error", err)
		return
	}
	if len(accounts) == 0 {
		return
	}

	sem := make(chan struct{}, openAIRateLimitRevalidationWorkers)
	var workers sync.WaitGroup
	for i := range accounts {
		account := accounts[i]
		if account.ID <= 0 {
			continue
		}
		select {
		case <-ctx.Done():
			workers.Wait()
			return
		case sem <- struct{}{}:
		}
		workers.Add(1)
		go func() {
			defer workers.Done()
			defer func() { <-sem }()

			probeCtx, cancel := context.WithTimeout(ctx, openAIRateLimitRevalidationTimeout)
			defer cancel()
			cleared, probeErr := s.probe.RevalidateOpenAIRateLimit(probeCtx, account.ID)
			if probeErr != nil {
				slog.Debug("openai_rate_limit_revalidation_failed", "account_id", account.ID, "error", probeErr)
				return
			}
			if cleared {
				slog.Info("openai_rate_limit_revalidated", "account_id", account.ID)
			}
		}()
	}
	workers.Wait()
}

func (s *OpenAIRateLimitRevalidationService) Stop() {
	if s == nil {
		return
	}
	s.mu.Lock()
	cancel := s.cancel
	s.cancel = nil
	s.mu.Unlock()
	if cancel == nil {
		return
	}
	cancel()
	s.wg.Wait()
}

// RevalidateOpenAIRateLimit probes the same ChatGPT/Codex provider path used by
// the account usage view. It only clears state when the probe produced an
// explicit provider-success marker and the repository supports CAS recovery.
func (s *AccountUsageService) RevalidateOpenAIRateLimit(ctx context.Context, accountID int64) (bool, error) {
	return s.revalidateOpenAIRateLimitWithProbe(ctx, accountID, s.probeOpenAICodexSnapshot)
}

type openAICodexProbeFunc func(context.Context, *Account) (map[string]any, error)

func (s *AccountUsageService) revalidateOpenAIRateLimitWithProbe(
	ctx context.Context,
	accountID int64,
	probe openAICodexProbeFunc,
) (bool, error) {
	if s == nil || s.accountRepo == nil || accountID <= 0 {
		return false, fmt.Errorf("OpenAI rate-limit revalidation is unavailable")
	}
	if probe == nil {
		return false, fmt.Errorf("OpenAI rate-limit provider probe is unavailable")
	}
	account, err := s.accountRepo.GetByID(ctx, accountID)
	if err != nil {
		return false, err
	}
	if account == nil || !account.IsOpenAIOAuth() {
		return false, nil
	}

	var (
		observedLimitedAt time.Time
		observedResetAt   time.Time
		canClearCAS       bool
	)
	if account.RateLimitedAt != nil && account.RateLimitResetAt != nil {
		observedLimitedAt = *account.RateLimitedAt
		observedResetAt = *account.RateLimitResetAt
		canClearCAS = true
	} else if !openAIQuotaOnlyRevalidationCandidate(account, time.Now()) {
		return false, nil
	}

	updates, err := probe(ctx, account)
	if err != nil {
		return false, err
	}
	if len(updates) == 0 {
		return false, nil
	}
	if err := s.accountRepo.UpdateExtra(ctx, accountID, updates); err != nil {
		return false, err
	}
	if !providerProbeSucceeded(updates) {
		return false, nil
	}

	// Quota-only candidates have no account-level rate-limit generation to CAS
	// clear. The authoritative provider snapshot was persisted above; the
	// scheduler snapshot is refreshed by UpdateExtra, so the next selection
	// observes the new quota without guessing or deleting unrelated state.
	if !canClearCAS {
		return true, nil
	}

	recoveryRepo, ok := s.accountRepo.(openAIRateLimitRecoveryRepository)
	if !ok {
		return false, fmt.Errorf("OpenAI rate-limit recovery repository is unavailable")
	}
	return recoveryRepo.ClearOpenAIRateLimitIfObserved(ctx, accountID, observedLimitedAt, observedResetAt)
}

func openAIQuotaOnlyRevalidationCandidate(account *Account, now time.Time) bool {
	if account == nil || !account.IsOpenAIOAuth() {
		return false
	}
	return openAICodex7dQuotaResetActive(account.Extra, now)
}

func providerProbeSucceeded(updates map[string]any) bool {
	if len(updates) == 0 {
		return false
	}
	if marker, ok := updates["codex_provider_probe_succeeded_at"].(string); !ok || marker == "" {
		return false
	}
	return providerProbeQuotaAvailable(updates)
}

func providerProbeQuotaAvailable(updates map[string]any) bool {
	updatedAt, ok := updates["codex_usage_updated_at"].(string)
	if !ok || updatedAt == "" {
		return false
	}
	if _, err := parseTime(updatedAt); err != nil {
		return false
	}

	for _, window := range []struct {
		name          string
		minWindowMins int
		maxWindowMins int
	}{
		{name: "5h", minWindowMins: 1, maxWindowMins: 360},
		{name: "7d", minWindowMins: 361, maxWindowMins: 10080},
	} {
		usedPercent, ok := updates["codex_"+window.name+"_used_percent"].(float64)
		if !ok || math.IsNaN(usedPercent) || math.IsInf(usedPercent, 0) || usedPercent < 0 || usedPercent >= 100 {
			return false
		}
		resetAfter, ok := updates["codex_"+window.name+"_reset_after_seconds"].(int)
		if !ok || resetAfter < 0 {
			return false
		}
		windowMinutes, ok := updates["codex_"+window.name+"_window_minutes"].(int)
		if !ok || windowMinutes < window.minWindowMins || windowMinutes > window.maxWindowMins {
			return false
		}
		if resetAfter > windowMinutes*60 {
			return false
		}
	}
	return true
}
