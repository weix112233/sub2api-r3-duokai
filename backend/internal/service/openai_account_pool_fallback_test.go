//go:build unit

package service

import (
	"context"
	"errors"
	"testing"

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
		if account.Platform == platform {
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
