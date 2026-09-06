package service

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
)

const (
	// A pool-wide temporary cooldown must not be turned into an immediate 503.
	// The budget is deliberately finite so a genuinely exhausted pool still
	// fails closed instead of holding an HTTP request forever.
	openAITransientAvailabilityWaitBudget = 5 * time.Minute
	openAITransientAvailabilityPoll       = 2 * time.Second
)

// waitForOpenAITransientAvailability waits only when the configured OpenAI
// pool contains a request-compatible account that is temporarily blocked by a
// recoverable runtime window. Persistent quota exhaustion, model mismatch,
// capability mismatch, and profit/channel gates are intentionally excluded.
func (s *OpenAIGatewayService) waitForOpenAITransientAvailability(
	ctx context.Context,
	groupID *int64,
	requestedModel string,
	requiredTransport OpenAIUpstreamTransport,
	requiredCapability OpenAIEndpointCapability,
	requiredImageCapability OpenAIImagesCapability,
	requireCompact bool,
) (bool, error) {
	if s == nil || s.accountRepo == nil {
		return false, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}

	deadline := time.Now().Add(openAITransientAvailabilityWaitBudget)
	waited := false
	for {
		if err := ctx.Err(); err != nil {
			return waited, err
		}

		nextAt, found, err := s.nextOpenAITransientAvailability(
			ctx,
			groupID,
			requestedModel,
			requiredTransport,
			requiredCapability,
			requiredImageCapability,
			requireCompact,
		)
		if err != nil {
			// The original selection error remains the authoritative response.
			// A diagnostic lookup failure must not turn it into a different error.
			slog.Warn("openai.transient_availability_lookup_failed", "error", err)
			return waited, nil
		}
		if !found {
			return waited, nil
		}

		now := time.Now()
		remaining := nextAt.Sub(now)
		if remaining <= 0 {
			return waited, nil
		}
		budget := deadline.Sub(now)
		if budget <= 0 || remaining > budget {
			slog.Warn(
				"openai.transient_availability_wait_budget_exhausted",
				"next_available_at", nextAt,
				"remaining", remaining,
				"budget", openAITransientAvailabilityWaitBudget,
			)
			return waited, nil
		}

		delay := remaining
		if delay > openAITransientAvailabilityPoll {
			delay = openAITransientAvailabilityPoll
		}
		if !waited {
			slog.Warn(
				"openai.transient_availability_wait",
				"next_available_at", nextAt,
				"wait_for", remaining,
				"budget", openAITransientAvailabilityWaitBudget,
			)
		}

		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return waited, ctx.Err()
		case <-timer.C:
			waited = true
		}
	}
}

func (s *OpenAIGatewayService) nextOpenAITransientAvailability(
	ctx context.Context,
	groupID *int64,
	requestedModel string,
	requiredTransport OpenAIUpstreamTransport,
	requiredCapability OpenAIEndpointCapability,
	requiredImageCapability OpenAIImagesCapability,
	requireCompact bool,
) (time.Time, bool, error) {
	if s == nil || s.accountRepo == nil {
		return time.Time{}, false, nil
	}
	candidateRepo, ok := s.accountRepo.(ModelAvailabilityCandidateRepository)
	if !ok {
		return time.Time{}, false, nil
	}

	requestedModel = strings.TrimSpace(requestedModel)
	currentGroupID := groupID
	visited := make(map[int64]struct{})
	if currentGroupID != nil {
		visited[*currentGroupID] = struct{}{}
	}

	var earliest time.Time
	for {
		queryGroupID := currentGroupID
		includeGrouped := false
		if queryGroupID == nil && s.cfg != nil && s.cfg.RunMode == config.RunModeSimple {
			includeGrouped = true
		}

		candidateCtx := s.withOpenAIProfitControlGate(ctx, currentGroupID)
		if !s.checkChannelPricingRestriction(candidateCtx, currentGroupID, requestedModel) {
			accounts, err := candidateRepo.ListModelAvailabilityCandidates(
				candidateCtx,
				queryGroupID,
				[]string{PlatformOpenAI},
				includeGrouped,
			)
			if err != nil {
				return time.Time{}, false, err
			}

			needsUpstreamCheck := currentGroupID != nil &&
				s.needsUpstreamChannelRestrictionCheck(candidateCtx, currentGroupID)
			for i := range accounts {
				account := &accounts[i]
				if !s.isOpenAIPersistentAvailabilityCandidate(
					candidateCtx,
					account,
					requestedModel,
					requiredTransport,
					requiredCapability,
					requiredImageCapability,
					requireCompact,
				) {
					continue
				}
				if needsUpstreamCheck &&
					s.isUpstreamModelRestrictedByChannel(
						candidateCtx,
						*currentGroupID,
						account,
						requestedModel,
						requireCompact,
					) {
					continue
				}

				if releaseAt, ok := s.openAIAccountTransientReleaseAt(
					candidateCtx,
					account,
					requestedModel,
				); ok && (earliest.IsZero() || releaseAt.Before(earliest)) {
					earliest = releaseAt
				}
			}
		}

		nextGroupID, err := s.nextOpenAIAccountPoolFallbackGroupID(
			ctx,
			currentGroupID,
			PlatformOpenAI,
		)
		if err != nil {
			return time.Time{}, false, err
		}
		if nextGroupID == nil {
			break
		}
		if _, seen := visited[*nextGroupID]; seen {
			return time.Time{}, false, nil
		}
		visited[*nextGroupID] = struct{}{}
		currentGroupID = nextGroupID
	}

	return earliest, !earliest.IsZero(), nil
}

func (s *OpenAIGatewayService) isOpenAIPersistentAvailabilityCandidate(
	ctx context.Context,
	account *Account,
	requestedModel string,
	requiredTransport OpenAIUpstreamTransport,
	requiredCapability OpenAIEndpointCapability,
	requiredImageCapability OpenAIImagesCapability,
	requireCompact bool,
) bool {
	if account == nil ||
		account.Platform != PlatformOpenAI ||
		!account.IsOpenAICompatible() ||
		!account.IsActive() ||
		!account.Schedulable {
		return false
	}
	now := time.Now()
	if account.AutoPauseOnExpired && account.ExpiresAt != nil &&
		!now.Before(*account.ExpiresAt) {
		return false
	}
	if account.IsAPIKeyOrBedrock() && account.IsQuotaExceeded() {
		return false
	}
	if paused, _ := shouldAutoPauseOpenAIAccountByQuota(ctx, account); paused {
		return false
	}
	if requestedModel != "" && !account.IsModelSupported(requestedModel) {
		return false
	}
	if !s.isOpenAIAccountTransportCompatible(account, requiredTransport) ||
		!account.SupportsOpenAIEndpointCapability(requiredCapability) ||
		!account.SupportsOpenAIImageCapability(requiredImageCapability) {
		return false
	}
	if requireCompact && openAICompactSupportTier(account) == 0 {
		return false
	}
	if !parentHealthyForShadow(account, s.parentAccountLookup(ctx)) {
		return false
	}
	if vetoed, _ := openAIProfitControlVetoReason(ctx, account); vetoed {
		return false
	}
	return true
}

func (s *OpenAIGatewayService) openAIAccountTransientReleaseAt(
	ctx context.Context,
	account *Account,
	requestedModel string,
) (time.Time, bool) {
	if account == nil {
		return time.Time{}, false
	}
	now := time.Now()
	var earliest time.Time
	consider := func(candidate time.Time) {
		if candidate.After(now) && (earliest.IsZero() || candidate.Before(earliest)) {
			earliest = candidate
		}
	}
	if account.RateLimitResetAt != nil {
		consider(*account.RateLimitResetAt)
	}
	if account.OverloadUntil != nil {
		consider(*account.OverloadUntil)
	}
	if account.TempUnschedulableUntil != nil {
		consider(*account.TempUnschedulableUntil)
	}
	if remaining := account.GetModelRateLimitRemainingTimeWithContext(ctx, requestedModel); remaining > 0 {
		consider(now.Add(remaining))
	}
	if runtimeUntil, ok := s.openAIAccountRuntimeBlockUntil(account.ID, now); ok {
		consider(runtimeUntil)
	}
	if modelUntil, ok := s.openAIAccountModelRuntimeBlockUntil(account.ID, requestedModel, now); ok {
		consider(modelUntil)
	}
	return earliest, !earliest.IsZero()
}
