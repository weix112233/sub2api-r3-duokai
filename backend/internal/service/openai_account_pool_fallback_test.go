//go:build unit

package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/stretchr/testify/require"
)

type openAIAccountPoolFallbackGroupRepo struct {
	GroupRepository
	groups map[int64]*Group
	err    error
}

func (r openAIAccountPoolFallbackGroupRepo) GetByIDLite(_ context.Context, id int64) (*Group, error) {
	if r.err != nil {
		return nil, r.err
	}
	return r.groups[id], nil
}

func (r openAIAccountPoolFallbackGroupRepo) GetByID(ctx context.Context, id int64) (*Group, error) {
	return r.GetByIDLite(ctx, id)
}

type openAIAccountPoolFallbackAccountRepo struct {
	AccountRepository
	accountsByGroup map[int64][]Account
	errByGroup      map[int64]error
}

func (r openAIAccountPoolFallbackAccountRepo) GetByID(_ context.Context, id int64) (*Account, error) {
	for _, accounts := range r.accountsByGroup {
		for i := range accounts {
			if accounts[i].ID == id {
				account := accounts[i]
				return &account, nil
			}
		}
	}
	return nil, errors.New("account not found")
}

func (r openAIAccountPoolFallbackAccountRepo) ListSchedulableByGroupIDAndPlatform(
	_ context.Context,
	groupID int64,
	platform string,
) ([]Account, error) {
	if err := r.errByGroup[groupID]; err != nil {
		return nil, err
	}
	accounts := r.accountsByGroup[groupID]
	result := make([]Account, 0, len(accounts))
	for _, account := range accounts {
		if account.Platform == platform && account.IsSchedulable() {
			result = append(result, account)
		}
	}
	return result, nil
}

func (r openAIAccountPoolFallbackAccountRepo) ListModelAvailabilityCandidates(
	_ context.Context,
	groupID *int64,
	platforms []string,
	_ bool,
) ([]Account, error) {
	if groupID == nil {
		return nil, nil
	}
	allowedPlatforms := make(map[string]struct{}, len(platforms))
	for _, platform := range platforms {
		allowedPlatforms[platform] = struct{}{}
	}
	accounts := r.accountsByGroup[*groupID]
	result := make([]Account, 0, len(accounts))
	for _, account := range accounts {
		if _, allowed := allowedPlatforms[account.Platform]; allowed {
			result = append(result, account)
		}
	}
	return result, nil
}

func newOpenAIAccountPoolFallbackService(
	groups map[int64]*Group,
	accounts map[int64][]Account,
	errByGroup map[int64]error,
) *OpenAIGatewayService {
	accountRepo := openAIAccountPoolFallbackAccountRepo{
		accountsByGroup: accounts,
		errByGroup:      errByGroup,
	}
	cfg := &config.Config{}
	cfg.Gateway.Scheduling.LoadBatchEnabled = false
	return &OpenAIGatewayService{
		accountRepo: accountRepo,
		cfg:         cfg,
		schedulerSnapshot: &SchedulerSnapshotService{
			accountRepo: accountRepo,
			groupRepo: openAIAccountPoolFallbackGroupRepo{
				groups: groups,
			},
		},
	}
}

func openAIAccountPoolTestAccount(id int64, groupID int64) Account {
	return Account{
		ID:          id,
		Platform:    PlatformOpenAI,
		Type:        AccountTypeOAuth,
		Status:      StatusActive,
		Schedulable: true,
		Concurrency: 0,
		Priority:    1,
		GroupIDs:    []int64{groupID},
	}
}

func TestOpenAIAccountPoolFallbackTraversesK12TeamPlus(t *testing.T) {
	const (
		k12ID  int64 = 8
		teamID int64 = 71
		plusID int64 = 134
	)
	groups := map[int64]*Group{
		k12ID: {
			ID: k12ID, Name: "K12", Platform: PlatformOpenAI,
			Status: StatusActive, FallbackGroupID: ptrInt64(teamID),
		},
		teamID: {
			ID: teamID, Name: "Team", Platform: PlatformOpenAI,
			Status: StatusActive, FallbackGroupID: ptrInt64(plusID),
		},
		plusID: {
			ID: plusID, Name: "Plus", Platform: PlatformOpenAI,
			Status: StatusActive,
		},
	}
	svc := newOpenAIAccountPoolFallbackService(
		groups,
		map[int64][]Account{
			plusID: {openAIAccountPoolTestAccount(9001, plusID)},
		},
		nil,
	)

	selection, _, err := svc.SelectAccountWithSchedulerForCapability(
		context.Background(),
		ptrInt64(k12ID),
		"",
		"",
		"gpt-5.6-sol",
		nil,
		OpenAIUpstreamTransportAny,
		OpenAIEndpointCapabilityChatCompletions,
		false,
		false,
		true,
	)
	require.NoError(t, err)
	require.NotNil(t, selection)
	require.NotNil(t, selection.Account)
	require.Equal(t, int64(9001), selection.Account.ID)
}

func TestOpenAIAccountPoolFallbackRestartsHopBudgetAfterTransientWait(t *testing.T) {
	const groupCount = 16
	groups := make(map[int64]*Group, groupCount)
	for index := 0; index < groupCount; index++ {
		groupID := int64(1000 + index)
		group := &Group{
			ID:       groupID,
			Name:     "pool",
			Platform: PlatformOpenAI,
			Status:   StatusActive,
		}
		if index+1 < groupCount {
			group.FallbackGroupID = ptrInt64(groupID + 1)
		}
		groups[groupID] = group
	}

	lastGroupID := int64(1000 + groupCount - 1)
	account := openAIAccountPoolTestAccount(9016, lastGroupID)
	resetAt := time.Now().Add(40 * time.Millisecond)
	account.RateLimitResetAt = &resetAt
	svc := newOpenAIAccountPoolFallbackService(
		groups,
		map[int64][]Account{lastGroupID: {account}},
		nil,
	)

	selection, _, err := svc.SelectAccountWithSchedulerForCapability(
		context.Background(),
		ptrInt64(1000),
		"",
		"",
		"gpt-5.6-sol",
		nil,
		OpenAIUpstreamTransportAny,
		OpenAIEndpointCapabilityChatCompletions,
		false,
		false,
		true,
	)

	require.NoError(t, err)
	require.NotNil(t, selection)
	require.NotNil(t, selection.Account)
	require.Equal(t, account.ID, selection.Account.ID)
}

func TestOpenAIAccountPoolFallbackDoesNotHideRepositoryErrors(t *testing.T) {
	const (
		k12ID  int64 = 8
		teamID int64 = 71
	)
	groups := map[int64]*Group{
		k12ID: {
			ID: k12ID, Name: "K12", Platform: PlatformOpenAI,
			Status: StatusActive, FallbackGroupID: ptrInt64(teamID),
		},
		teamID: {
			ID: teamID, Name: "Team", Platform: PlatformOpenAI,
			Status: StatusActive,
		},
	}
	repoErr := errors.New("database unavailable")
	svc := newOpenAIAccountPoolFallbackService(
		groups,
		map[int64][]Account{
			teamID: {openAIAccountPoolTestAccount(9002, teamID)},
		},
		map[int64]error{k12ID: repoErr},
	)

	selection, _, err := svc.SelectAccountWithSchedulerForCapability(
		context.Background(),
		ptrInt64(k12ID),
		"",
		"",
		"gpt-5.6-sol",
		nil,
		OpenAIUpstreamTransportAny,
		OpenAIEndpointCapabilityChatCompletions,
		false,
		false,
		true,
	)
	require.ErrorIs(t, err, repoErr)
	require.Nil(t, selection)
}

func TestOpenAIAccountPoolFallbackRejectsCycles(t *testing.T) {
	const (
		k12ID  int64 = 8
		teamID int64 = 71
	)
	groups := map[int64]*Group{
		k12ID: {
			ID: k12ID, Name: "K12", Platform: PlatformOpenAI,
			Status: StatusActive, FallbackGroupID: ptrInt64(teamID),
		},
		teamID: {
			ID: teamID, Name: "Team", Platform: PlatformOpenAI,
			Status: StatusActive, FallbackGroupID: ptrInt64(k12ID),
		},
	}
	svc := newOpenAIAccountPoolFallbackService(groups, nil, nil)

	selection, _, err := svc.SelectAccountWithSchedulerForCapability(
		context.Background(),
		ptrInt64(k12ID),
		"",
		"",
		"gpt-5.6-sol",
		nil,
		OpenAIUpstreamTransportAny,
		OpenAIEndpointCapabilityChatCompletions,
		false,
		false,
		true,
	)
	require.ErrorContains(t, err, "fallback group cycle")
	require.Nil(t, selection)
}

func ptrInt64(value int64) *int64 {
	return &value
}
