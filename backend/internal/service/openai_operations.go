package service

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"
)

type ReasoningTokenBucket struct {
	Model               string `json:"model"`
	ReasoningTokens     int    `json:"reasoning_tokens"`
	Hits                int    `json:"hits"`
	SuspectedTruncation bool   `json:"suspected_truncation"`
}

type OpenAIRecoveryRecord struct {
	AccountID           int64     `json:"account_id"`
	Attempts            int       `json:"attempts"`
	ConsecutiveFailures int       `json:"consecutive_failures"`
	LastAttemptAt       time.Time `json:"last_attempt_at"`
	NextAttemptAt       time.Time `json:"next_attempt_at"`
	Classification      string    `json:"classification"`
	Outcome             string    `json:"outcome"`
	Permanent           bool      `json:"permanent"`
}

type OpenAIRecoveryEvent struct {
	ID             int64     `json:"id"`
	AccountID      int64     `json:"account_id"`
	Attempt        int       `json:"attempt"`
	Classification string    `json:"classification"`
	Action         string    `json:"action"`
	Outcome        string    `json:"outcome"`
	CreatedAt      time.Time `json:"created_at"`
}

type OpenAIOperationsRepository interface {
	ReasoningDistribution(context.Context, time.Time, int, int64) ([]ReasoningTokenBucket, error)
	RecoveryCandidates(context.Context, time.Time, int) ([]int64, error)
	ClaimRecovery(context.Context, *Account, time.Time) (*OpenAIRecoveryRecord, error)
	CompleteRecovery(context.Context, OpenAIRecoveryRecord, string) error
	RecoveryEvents(context.Context, int64, int) ([]OpenAIRecoveryEvent, error)
	RecoveryRecords(context.Context, []int64) ([]OpenAIRecoveryRecord, error)
}

type OpenAIRecoveryCredentialRepository interface {
	SaveRecoveredOpenAIAccount(context.Context, *Account, map[string]any) (bool, error)
}

type openAIRecoveryCooldownRepository interface {
	SetOpenAIRecoveryCooldown(context.Context, *Account, time.Time) (bool, error)
}

type AccountCooldown struct {
	Reason           string    `json:"reason"`
	Until            time.Time `json:"until"`
	RemainingSeconds int64     `json:"remaining_seconds"`
}

type OpenAIAccountOperationalState struct {
	AccountID          int64             `json:"account_id"`
	Name               string            `json:"name"`
	Status             string            `json:"status"`
	Schedulable        bool              `json:"schedulable"`
	Cooldowns          []AccountCooldown `json:"cooldowns"`
	StickyEscapeReason string            `json:"sticky_escape_reason,omitempty"`
	TLSProxyFallback   bool              `json:"tls_proxy_fallback"`
}

type OpenAIAccountPoolState struct {
	ObservedAt  time.Time                       `json:"observed_at"`
	Total       int                             `json:"total"`
	Schedulable int                             `json:"schedulable"`
	Cooling     int                             `json:"cooling"`
	Error       int                             `json:"error"`
	Accounts    []OpenAIAccountOperationalState `json:"accounts"`
	Recovery    []OpenAIRecoveryRecord          `json:"recovery"`
}

type OpenAIOperationsService struct {
	repo      OpenAIOperationsRepository
	accounts  AccountRepository
	settings  *SettingService
	profiles  *TLSFingerprintProfileService
	proxies   ProxyRepository
	gateway   *OpenAIGatewayService
	refresh   *OAuthRefreshAPI
	executor  OAuthRefreshExecutor
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	startOnce sync.Once
	stopOnce  sync.Once
}

func NewOpenAIOperationsService(repo OpenAIOperationsRepository, accounts AccountRepository,
	settings *SettingService, profiles *TLSFingerprintProfileService, proxies ProxyRepository,
	gateway *OpenAIGatewayService, refresh *OAuthRefreshAPI, oauth *OpenAIOAuthService) *OpenAIOperationsService {
	return &OpenAIOperationsService{repo: repo, accounts: accounts, settings: settings, profiles: profiles,
		proxies: proxies, gateway: gateway, refresh: refresh, executor: NewOpenAITokenRefresher(oauth, accounts)}
}

func (s *OpenAIOperationsService) GetSettings(ctx context.Context) (OpenAIOperationsSettings, error) {
	return s.settings.GetOpenAIOperationsSettings(ctx)
}

func (s *OpenAIOperationsService) SetSettings(ctx context.Context, value OpenAIOperationsSettings) error {
	if err := value.Validate(); err != nil {
		return err
	}
	if d := value.NewAccountDefaults; d != nil {
		if d.ProxyID != nil && *d.ProxyID > 0 {
			if s.proxies == nil {
				return fmt.Errorf("proxy repository unavailable")
			}
			if p, err := s.proxies.GetByID(ctx, *d.ProxyID); err != nil || p == nil {
				return fmt.Errorf("default proxy not found")
			}
		}
		if d.TLSFingerprintProfileID != nil && *d.TLSFingerprintProfileID > 0 {
			if s.profiles == nil {
				return fmt.Errorf("TLS profile service unavailable")
			}
			if p, err := s.profiles.GetByID(ctx, *d.TLSFingerprintProfileID); err != nil || p == nil {
				return fmt.Errorf("default TLS profile not found")
			}
		}
	}
	return s.settings.SetOpenAIOperationsSettings(ctx, value)
}

func (s *OpenAIOperationsService) Reasoning(ctx context.Context, accountID int64) ([]ReasoningTokenBucket, error) {
	cfg, err := s.GetSettings(ctx)
	if err != nil {
		return nil, err
	}
	buckets, err := s.repo.ReasoningDistribution(ctx, time.Now().Add(-time.Duration(cfg.Reasoning.WindowHours)*time.Hour), cfg.Reasoning.SampleLimit, accountID)
	if err != nil {
		return nil, err
	}
	for i := range buckets {
		buckets[i].SuspectedTruncation = buckets[i].ReasoningTokens > 0 && buckets[i].Hits >= cfg.Reasoning.Threshold
	}
	return buckets, nil
}

func (s *OpenAIOperationsService) Events(ctx context.Context, accountID int64) ([]OpenAIRecoveryEvent, error) {
	return s.repo.RecoveryEvents(ctx, accountID, 200)
}

func accountOperationalState(account *Account, now time.Time) OpenAIAccountOperationalState {
	state := OpenAIAccountOperationalState{AccountID: account.ID, Name: account.Name, Status: account.Status,
		Schedulable: account.IsSchedulable(), Cooldowns: make([]AccountCooldown, 0)}
	add := func(reason string, until *time.Time) {
		if until != nil && now.Before(*until) {
			state.Cooldowns = append(state.Cooldowns, AccountCooldown{Reason: reason, Until: *until,
				RemainingSeconds: int64(until.Sub(now).Seconds()) + 1})
		}
	}
	add("429", account.RateLimitResetAt)
	add("overload", account.OverloadUntil)
	reason := "temporary"
	for _, label := range []string{"429", "ttft", "error_rate", "token_refresh", "upstream_transport", "401"} {
		if strings.Contains(strings.ToLower(account.TempUnschedulableReason), label) {
			reason = label
			break
		}
	}
	add(reason, account.TempUnschedulableUntil)
	state.TLSProxyFallback = account.IsTLSFingerprintEnabled() && account.Proxy != nil &&
		strings.HasPrefix(strings.ToLower(account.Proxy.URL()), "https://")
	return state
}

func (s *OpenAIOperationsService) Pool(ctx context.Context, groupID int64) (*OpenAIAccountPoolState, error) {
	accounts, err := s.accounts.ListAllWithFilters(ctx, PlatformOpenAI, "", "", "", groupID, "")
	if err != nil {
		return nil, err
	}
	now := time.Now()
	out := &OpenAIAccountPoolState{ObservedAt: now, Total: len(accounts), Accounts: make([]OpenAIAccountOperationalState, 0, len(accounts))}
	ids := make([]int64, 0, len(accounts))
	var scheduler *defaultOpenAIAccountScheduler
	if s.gateway != nil {
		scheduler, _ = s.gateway.getOpenAIAccountScheduler(ctx).(*defaultOpenAIAccountScheduler)
	}
	for i := range accounts {
		a := &accounts[i]
		state := accountOperationalState(a, now)
		if scheduler != nil {
			cfg := s.gateway.openAIStickyEscapeConfig()
			cfg.preserveCacheAffinity = a.IsOpenAIOAuthLike()
			state.StickyEscapeReason, _, _, _ = scheduler.shouldEscapeStickyAccount(a.ID, cfg)
		}
		if state.Schedulable {
			out.Schedulable++
		}
		if len(state.Cooldowns) > 0 {
			out.Cooling++
		}
		if a.Status == StatusError {
			out.Error++
		}
		out.Accounts = append(out.Accounts, state)
		ids = append(ids, a.ID)
	}
	out.Recovery, err = s.repo.RecoveryRecords(ctx, ids)
	return out, err
}

func (s *OpenAIOperationsService) Start() {
	s.startOnce.Do(func() {
		ctx, cancel := context.WithCancel(context.Background())
		s.cancel = cancel
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			for {
				delay := time.Minute
				cfg, err := s.GetSettings(ctx)
				if err == nil && cfg.Recovery.Enabled {
					runCtx, stop := context.WithTimeout(ctx, 5*time.Minute)
					err = s.runRecovery(runCtx, cfg.Recovery)
					stop()
					delay = time.Duration(cfg.Recovery.IntervalMinutes) * time.Minute
				}
				if err != nil && ctx.Err() == nil {
					slog.Warn("openai_recovery_cycle_failed")
				}
				timer := time.NewTimer(delay)
				select {
				case <-ctx.Done():
					timer.Stop()
					return
				case <-timer.C:
				}
			}
		}()
	})
}

func (s *OpenAIOperationsService) Stop() {
	s.stopOnce.Do(func() {
		if s.cancel != nil {
			s.cancel()
		}
		s.wg.Wait()
	})
}

func classifyOpenAIRecovery(message string) string {
	value := strings.ToLower(message)
	for _, permanent := range []string{"account_deactivated", "invalid_grant", "refresh_token_revoked", "refresh token revoked", "token has been revoked"} {
		if strings.Contains(value, permanent) {
			return "permanent"
		}
	}
	if strings.Contains(value, "429") || strings.Contains(value, "rate_limit") || strings.Contains(value, "too many requests") {
		return "rate_limit"
	}
	return "recoverable"
}

func (s *OpenAIOperationsService) runRecovery(ctx context.Context, cfg OpenAIRecoverySettings) error {
	if !cfg.Enabled {
		return nil
	}
	ids, err := s.repo.RecoveryCandidates(ctx, time.Now(), 100)
	if err != nil {
		return err
	}
	for _, id := range ids {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		account, err := s.accounts.GetByID(ctx, id)
		if err != nil {
			return err
		}
		if account == nil || account.Platform != PlatformOpenAI || account.Type != AccountTypeOAuth ||
			account.Status != StatusError || account.IsCredentialShadow() {
			continue
		}
		now := time.Now()
		record, err := s.repo.ClaimRecovery(ctx, account, now)
		if err != nil {
			return err
		}
		if record == nil {
			continue
		}
		record.Classification = classifyOpenAIRecovery(account.ErrorMessage)
		record.Outcome = "skipped"
		action := "skip"
		if record.Classification == "permanent" {
			record.Permanent = true
		} else if strings.TrimSpace(account.GetOpenAIRefreshToken()) == "" || account.IsOpenAIPersonalAccessToken() {
			record.Classification, record.Outcome = "authorization_required", "skipped"
			record.Permanent = true
		} else if account.IsRateLimited() {
			record.Classification, record.Outcome = "rate_limit", "cooling"
			record.NextAttemptAt = *account.RateLimitResetAt
		} else {
			action = "oauth_refresh"
			attemptCtx, stop := context.WithTimeout(ctx, 45*time.Second)
			result, refreshErr := s.refresh.RecoverOpenAIError(attemptCtx, account, s.executor)
			stop()
			switch {
			case refreshErr != nil:
				record.Classification = classifyOpenAIRecovery(refreshErr.Error())
				record.Permanent = record.Classification == "permanent"
				record.ConsecutiveFailures++
				record.Outcome = "failed"
				if record.Classification == "rate_limit" {
					until := time.Now().Add(time.Duration(cfg.CooldownMinutes) * time.Minute)
					cooldowns, ok := s.accounts.(openAIRecoveryCooldownRepository)
					if !ok {
						return fmt.Errorf("recovery cooldown repository unavailable")
					}
					applied, err := cooldowns.SetOpenAIRecoveryCooldown(ctx, account, until)
					if err != nil {
						return err
					}
					if applied {
						record.NextAttemptAt = until
						record.Outcome = "cooling"
					} else {
						record.Outcome = "state_changed"
					}
				}
			case result != nil && result.Refreshed:
				record.Outcome = "recovered"
				record.ConsecutiveFailures = 0
			case result != nil && result.LockHeld:
				record.Outcome = "lock_busy"
			default:
				record.Outcome = "state_changed"
			}
		}
		delay := cfg.IntervalMinutes
		if record.ConsecutiveFailures >= cfg.FailureThreshold {
			delay = cfg.BackoffMinutes
		}
		if minimumNext := time.Now().Add(time.Duration(delay) * time.Minute); record.NextAttemptAt.Before(minimumNext) {
			record.NextAttemptAt = minimumNext
		}
		// Persist only bounded categories, never upstream error bodies or credentials.
		completeCtx, completeCancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		err = s.repo.CompleteRecovery(completeCtx, *record, action)
		completeCancel()
		if err != nil {
			return err
		}
		slog.Info("openai_account_recovery", "account_id", id, "classification", record.Classification,
			"action", action, "outcome", record.Outcome, "attempt", record.Attempts)
	}
	return nil
}
