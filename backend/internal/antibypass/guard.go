package antibypass

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	keyPrefix                 = "sub2api:anti-bypass:v3"
	defaultWindow             = 5 * time.Minute
	defaultRateWindow         = time.Minute
	defaultLease              = 15 * time.Minute
	defaultReplayWindow       = 30 * time.Second
	defaultRPMLimit           = 120
	defaultMaxConcurrent      = 32
	defaultMaxDistinctKeys    = 8
	defaultMaxDistinctIPs     = 8
	defaultMaxDistinctFPs     = 8
	defaultMaxRequestAttempts = 3
	defaultMaxBodyInspection  = 2 << 20
)

// Reason is a machine-readable admission result. It is safe to expose in
// metrics and logs because it never contains request content or credentials.
type Reason string

const (
	ReasonNone                  Reason = ""
	ReasonRPM                   Reason = "rpm_limit"
	ReasonConcurrency           Reason = "concurrency_limit"
	ReasonDistinctKeys          Reason = "distinct_api_keys"
	ReasonDistinctIPs           Reason = "distinct_client_ips"
	ReasonDistinctFingerprints  Reason = "distinct_client_fingerprints"
	ReasonReplay                Reason = "replay_across_identity"
	ReasonDuplicateRequest      Reason = "duplicate_request_id"
	ReasonPromptJailbreak       Reason = "prompt_jailbreak"
	ReasonPromptEncodingLimit   Reason = "prompt_encoding_limit"
	ReasonPromptInspectionLimit Reason = "prompt_inspection_limit"
	ReasonHeaderConflict        Reason = "credential_header_conflict"
	ReasonBodyTooLarge          Reason = "body_inspection_limit"
	ReasonStorageUnavailable    Reason = "storage_unavailable"
	ReasonInvalidSubject        Reason = "invalid_subject"
)

// Config contains the safety budgets for the guard. The feature's only
// production switch is the system setting anti_bypass_enabled; these bounded
// defaults are intentionally not coupled to billing settings.
type Config struct {
	Window                   time.Duration
	RateWindow               time.Duration
	Lease                    time.Duration
	ReplayWindow             time.Duration
	RPMLimit                 int
	MaxConcurrent            int
	MaxDistinctKeys          int
	MaxDistinctIPs           int
	MaxDistinctFingerprints  int
	MaxClientRequestAttempts int
	MaxBodyInspectionBytes   int
}

func DefaultConfig() Config {
	return Config{
		Window:                   defaultWindow,
		RateWindow:               defaultRateWindow,
		Lease:                    defaultLease,
		ReplayWindow:             defaultReplayWindow,
		RPMLimit:                 defaultRPMLimit,
		MaxConcurrent:            defaultMaxConcurrent,
		MaxDistinctKeys:          defaultMaxDistinctKeys,
		MaxDistinctIPs:           defaultMaxDistinctIPs,
		MaxDistinctFingerprints:  defaultMaxDistinctFPs,
		MaxClientRequestAttempts: defaultMaxRequestAttempts,
		MaxBodyInspectionBytes:   defaultMaxBodyInspection,
	}
}

func (c Config) normalized() Config {
	defaults := DefaultConfig()
	if c.Window <= 0 {
		c.Window = defaults.Window
	}
	if c.RateWindow <= 0 {
		c.RateWindow = defaults.RateWindow
	}
	if c.Lease <= 0 {
		c.Lease = defaults.Lease
	}
	if c.ReplayWindow <= 0 {
		c.ReplayWindow = defaults.ReplayWindow
	}
	if c.RPMLimit <= 0 {
		c.RPMLimit = defaults.RPMLimit
	}
	if c.MaxConcurrent <= 0 {
		c.MaxConcurrent = defaults.MaxConcurrent
	}
	if c.MaxDistinctKeys <= 0 {
		c.MaxDistinctKeys = defaults.MaxDistinctKeys
	}
	if c.MaxDistinctIPs <= 0 {
		c.MaxDistinctIPs = defaults.MaxDistinctIPs
	}
	if c.MaxDistinctFingerprints <= 0 {
		c.MaxDistinctFingerprints = defaults.MaxDistinctFingerprints
	}
	if c.MaxClientRequestAttempts <= 0 {
		c.MaxClientRequestAttempts = defaults.MaxClientRequestAttempts
	}
	if c.MaxBodyInspectionBytes <= 0 {
		c.MaxBodyInspectionBytes = defaults.MaxBodyInspectionBytes
	}
	return c
}

type Request struct {
	UserID            int64
	APIKeyID          int64
	ClientIP          string
	ClientFingerprint string
	IdempotencyKey    string
	// ClientRequestID is a protocol operation ID, such as a WS event_id.
	// HTTP tracing headers must not populate this field.
	ClientRequestID string
	Method          string
	Path            string
	Body            []byte
}

type Decision struct {
	Allowed    bool
	Reason     Reason
	Current    int64
	Limit      int64
	RetryAfter time.Duration
	leaseKey   string
	leaseToken string
	lease      time.Duration
}

type Guard struct {
	client        *redis.Client
	now           func() time.Time
	admitScript   *redis.Script
	renewScript   *redis.Script
	releaseScript *redis.Script
}

func NewGuard(client *redis.Client) *Guard {
	return &Guard{
		client: client,
		now:    time.Now,
		admitScript: redis.NewScript(`
local now_ms = tonumber(ARGV[14])
local rate_start_ms = now_ms - tonumber(ARGV[16])
local identity_start_ms = now_ms - tonumber(ARGV[1])
local active_rate_start = "(" .. rate_start_ms
local active_identity_start = "(" .. identity_start_ms
local active_lease_start = "(" .. now_ms

local inflight = tonumber(redis.call("ZCOUNT", KEYS[1], active_lease_start, "+inf") or "0")
local rpm = tonumber(redis.call("ZCOUNT", KEYS[2], active_rate_start, "+inf") or "0")
local distinct_ips = tonumber(redis.call("ZCOUNT", KEYS[3], active_identity_start, "+inf") or "0")
local distinct_keys = tonumber(redis.call("ZCOUNT", KEYS[4], active_identity_start, "+inf") or "0")
local distinct_fingerprints = tonumber(redis.call("ZCOUNT", KEYS[5], active_identity_start, "+inf") or "0")

if rpm >= tonumber(ARGV[8]) then
  return {0, "rpm_limit", rpm, tonumber(ARGV[8]), rpm, distinct_keys, distinct_ips, distinct_fingerprints}
end

local ip_score = tonumber(redis.call("ZSCORE", KEYS[3], ARGV[2]))
local key_score = tonumber(redis.call("ZSCORE", KEYS[4], ARGV[3]))
local fingerprint_score = tonumber(redis.call("ZSCORE", KEYS[5], ARGV[4]))
local ip_exists = ip_score ~= nil and ip_score > identity_start_ms
local key_exists = key_score ~= nil and key_score > identity_start_ms
local fingerprint_exists = fingerprint_score ~= nil and fingerprint_score > identity_start_ms

if not key_exists and distinct_keys >= tonumber(ARGV[10]) then
  return {0, "distinct_api_keys", distinct_keys + 1, tonumber(ARGV[10]), rpm, distinct_keys, distinct_ips, distinct_fingerprints}
end
if not ip_exists and distinct_ips >= tonumber(ARGV[11]) then
  return {0, "distinct_client_ips", distinct_ips + 1, tonumber(ARGV[11]), rpm, distinct_keys, distinct_ips, distinct_fingerprints}
end
if not fingerprint_exists and distinct_fingerprints >= tonumber(ARGV[12]) then
  return {0, "distinct_client_fingerprints", distinct_fingerprints + 1, tonumber(ARGV[12]), rpm, distinct_keys, distinct_ips, distinct_fingerprints}
end

if inflight >= tonumber(ARGV[9]) then
  return {0, "concurrency_limit", inflight, tonumber(ARGV[9]), rpm, distinct_keys, distinct_ips, distinct_fingerprints}
end

if ARGV[7] ~= "" and ARGV[18] ~= "" then
  local prior_idempotency_signature = redis.call("GET", KEYS[7])
  if prior_idempotency_signature and prior_idempotency_signature ~= ARGV[18] then
    return {0, "duplicate_request_id", 1, 0, rpm, distinct_keys, distinct_ips, distinct_fingerprints}
  end
end

if ARGV[17] ~= "" and ARGV[18] ~= "" then
  local prior_request_signature = redis.call("HGET", KEYS[8], "signature")
  if prior_request_signature and prior_request_signature ~= ARGV[18] then
    return {0, "duplicate_request_id", 1, 0, rpm, distinct_keys, distinct_ips, distinct_fingerprints}
  end
  local request_attempts = tonumber(redis.call("HGET", KEYS[8], "attempts") or "0")
  if request_attempts >= tonumber(ARGV[19]) then
    return {0, "duplicate_request_id", request_attempts + 1, tonumber(ARGV[19]), rpm, distinct_keys, distinct_ips, distinct_fingerprints}
  end
end

if ARGV[5] ~= "" then
  local previous_identity = redis.call("GET", KEYS[6])
  local previous_key = previous_identity and (string.match(previous_identity, "^(%d+):") or previous_identity)
  if previous_key and previous_key ~= ARGV[5] then
    return {0, "replay_across_identity", 1, 0, rpm, distinct_keys, distinct_ips, distinct_fingerprints}
  end
end

redis.call("ZREMRANGEBYSCORE", KEYS[1], "-inf", now_ms)
redis.call("ZREMRANGEBYSCORE", KEYS[2], "-inf", rate_start_ms)
for index = 3, 5 do
  redis.call("ZREMRANGEBYSCORE", KEYS[index], "-inf", identity_start_ms)
end

redis.call("ZADD", KEYS[2], now_ms, ARGV[15])
redis.call("PEXPIRE", KEYS[2], ARGV[16])
rpm = rpm + 1

redis.call("ZADD", KEYS[3], now_ms, ARGV[2])
redis.call("ZADD", KEYS[4], now_ms, ARGV[3])
redis.call("ZADD", KEYS[5], now_ms, ARGV[4])
for index = 3, 5 do
  redis.call("PEXPIRE", KEYS[index], ARGV[1])
end
distinct_ips = tonumber(redis.call("ZCARD", KEYS[3]) or "0")
distinct_keys = tonumber(redis.call("ZCARD", KEYS[4]) or "0")
distinct_fingerprints = tonumber(redis.call("ZCARD", KEYS[5]) or "0")

if ARGV[7] ~= "" and ARGV[18] ~= "" and redis.call("EXISTS", KEYS[7]) == 0 then
  redis.call("SET", KEYS[7], ARGV[18], "PX", ARGV[6])
end
if ARGV[5] ~= "" and redis.call("EXISTS", KEYS[6]) == 0 then
  redis.call("SET", KEYS[6], ARGV[5], "PX", ARGV[6])
end
if ARGV[17] ~= "" and ARGV[18] ~= "" then
  if redis.call("EXISTS", KEYS[8]) == 0 then
    redis.call("HSET", KEYS[8], "signature", ARGV[18], "attempts", 1)
  else
    redis.call("HINCRBY", KEYS[8], "attempts", 1)
  end
  redis.call("PEXPIRE", KEYS[8], ARGV[6])
end

local lease_until = now_ms + tonumber(ARGV[13])
redis.call("ZADD", KEYS[1], lease_until, ARGV[15])
redis.call("PEXPIRE", KEYS[1], ARGV[13])
local next_inflight = redis.call("ZCARD", KEYS[1])
return {1, "", next_inflight, 0, rpm, distinct_keys, distinct_ips, distinct_fingerprints}
`),
		renewScript: redis.NewScript(`
if redis.call("ZSCORE", KEYS[1], ARGV[1]) == false then
  return 0
end
redis.call("ZADD", KEYS[1], ARGV[2], ARGV[1])
redis.call("PEXPIRE", KEYS[1], ARGV[3])
return 1
`),
		releaseScript: redis.NewScript(`
local removed = redis.call("ZREM", KEYS[1], ARGV[1])
if removed == 1 and redis.call("ZCARD", KEYS[1]) == 0 then
  redis.call("DEL", KEYS[1])
end
return removed
`),
	}
}

func (g *Guard) Check(ctx context.Context, cfg Config, req Request) (Decision, error) {
	if g == nil || g.client == nil {
		return Decision{Reason: ReasonStorageUnavailable}, errors.New("anti-bypass redis client is nil")
	}
	if req.UserID <= 0 || req.APIKeyID <= 0 {
		return Decision{Reason: ReasonInvalidSubject}, nil
	}
	cfg = cfg.normalized()
	now := g.now().UTC()
	userPrefix := fmt.Sprintf("%s:{user:%d}", keyPrefix, req.UserID)

	clientIP := digest(normalize(req.ClientIP))
	clientFingerprint := digest(normalize(req.ClientFingerprint))
	// Negotiation headers and network changes do not change the authenticated key.
	identity := strconv.FormatInt(req.APIKeyID, 10)
	requestHash := requestDigest(req)
	leaseToken, err := newLeaseToken()
	if err != nil {
		return Decision{Reason: ReasonStorageUnavailable}, fmt.Errorf("anti-bypass lease token: %w", err)
	}
	idempotencyKey := normalizeOpaqueID(req.IdempotencyKey)
	if len(idempotencyKey) > 256 {
		idempotencyKey = idempotencyKey[:256]
	}
	clientRequestID := normalizeOpaqueID(req.ClientRequestID)
	if len(clientRequestID) > 256 {
		clientRequestID = clientRequestID[:256]
	}
	requestSignature := requestSignature(req)

	keys := []string{
		fmt.Sprintf("%s:inflight", userPrefix),
		fmt.Sprintf("%s:rpm", userPrefix),
		fmt.Sprintf("%s:ips", userPrefix),
		fmt.Sprintf("%s:keys", userPrefix),
		fmt.Sprintf("%s:fingerprints:v2", userPrefix),
		fmt.Sprintf("%s:payload:%s", userPrefix, requestHash),
		fmt.Sprintf("%s:idempotency:%s", userPrefix, digest(idempotencyKey)),
		fmt.Sprintf("%s:request:%s", userPrefix, digest(clientRequestID)),
	}
	args := []any{
		cfg.Window.Milliseconds(),
		clientIP,
		strconv.FormatInt(req.APIKeyID, 10),
		clientFingerprint,
		identityForReplay(identity, requestHash),
		cfg.ReplayWindow.Milliseconds(),
		idempotencyKey,
		cfg.RPMLimit,
		cfg.MaxConcurrent,
		cfg.MaxDistinctKeys,
		cfg.MaxDistinctIPs,
		cfg.MaxDistinctFingerprints,
		cfg.Lease.Milliseconds(),
		now.UnixMilli(),
		leaseToken,
		cfg.RateWindow.Milliseconds(),
		clientRequestID,
		requestSignature,
		cfg.MaxClientRequestAttempts,
	}

	raw, err := g.admitScript.Run(ctx, g.client, keys, args...).Result()
	if err != nil {
		return Decision{Reason: ReasonStorageUnavailable}, fmt.Errorf("anti-bypass admission: %w", err)
	}
	values, ok := raw.([]any)
	if !ok || len(values) < 4 {
		return Decision{Reason: ReasonStorageUnavailable}, errors.New("anti-bypass admission returned malformed result")
	}
	allowed := redisInt64(values[0]) == 1
	decision := Decision{
		Allowed:    allowed,
		Reason:     Reason(redisString(values[1])),
		Current:    redisInt64(values[2]),
		Limit:      redisInt64(values[3]),
		leaseKey:   keys[0],
		leaseToken: leaseToken,
		lease:      cfg.Lease,
	}
	if !allowed {
		decision.RetryAfter = retryAfterFor(decision.Reason, cfg)
	}
	return decision, nil
}

// MaintainDecision renews an admitted request's concurrency lease until the
// request completes. Renewal failure is returned so the caller can fail the
// in-flight request closed instead of silently undercounting long streams.
func (g *Guard) MaintainDecision(ctx context.Context, decision Decision, done <-chan struct{}) error {
	if g == nil || g.client == nil || decision.leaseKey == "" || decision.leaseToken == "" {
		return errors.New("anti-bypass lease is unavailable")
	}
	lease := decision.lease
	if lease <= 0 {
		lease = defaultLease
	}
	interval := lease / 3
	if interval < 10*time.Millisecond {
		interval = 10 * time.Millisecond
	}
	timer := time.NewTimer(interval)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-done:
			return nil
		case <-timer.C:
			refreshCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
			err := g.refreshDecision(refreshCtx, decision, lease)
			cancel()
			if err != nil {
				select {
				case <-done:
					return nil
				default:
					return err
				}
			}
			timer.Reset(interval)
		}
	}
}

func (g *Guard) refreshDecision(ctx context.Context, decision Decision, lease time.Duration) error {
	leaseUntil := g.now().UTC().Add(lease).UnixMilli()
	updated, err := g.renewScript.Run(
		ctx,
		g.client,
		[]string{decision.leaseKey},
		decision.leaseToken,
		leaseUntil,
		lease.Milliseconds(),
	).Int64()
	if err != nil {
		return fmt.Errorf("anti-bypass lease renewal: %w", err)
	}
	if updated != 1 {
		return errors.New("anti-bypass admission lease no longer exists")
	}
	return nil
}

// ReleaseDecision releases the exact admission lease, including when a
// long-running request crosses the rolling window boundary.
func (g *Guard) ReleaseDecision(ctx context.Context, userID int64, decision Decision) {
	if g == nil || g.client == nil || userID <= 0 || decision.leaseKey == "" || decision.leaseToken == "" {
		return
	}
	g.release(ctx, decision.leaseKey, decision.leaseToken)
}

func (g *Guard) release(ctx context.Context, key, leaseToken string) {
	_, _ = g.releaseScript.Run(ctx, g.client, []string{key}, leaseToken).Result()
}

func newLeaseToken() (string, error) {
	var token [16]byte
	if _, err := rand.Read(token[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(token[:]), nil
}

func requestDigest(req Request) string {
	if !isReplayEligibleMethod(req.Method) || len(req.Body) == 0 {
		return ""
	}
	return requestSignature(req)
}

func requestSignature(req Request) string {
	if !isReplayEligibleMethod(req.Method) {
		return ""
	}
	h := sha256.New()
	_, _ = h.Write([]byte(strings.ToUpper(strings.TrimSpace(req.Method))))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(strings.TrimSpace(req.Path)))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write(req.Body)
	return hex.EncodeToString(h.Sum(nil))
}

func identityForReplay(identity, requestHash string) string {
	if requestHash == "" {
		return ""
	}
	return identity
}

func isReplayEligibleMethod(method string) bool {
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}

func retryAfterFor(reason Reason, cfg Config) time.Duration {
	switch reason {
	case ReasonReplay, ReasonDuplicateRequest:
		return cfg.ReplayWindow
	case ReasonRPM:
		return cfg.RateWindow
	case ReasonDistinctKeys, ReasonDistinctIPs, ReasonDistinctFingerprints:
		return cfg.Window
	case ReasonConcurrency:
		return time.Second
	default:
		return time.Second
	}
}

func dimensionKey(dimension string, userID int64) string {
	if dimension == "fingerprints" {
		dimension = "fingerprints:v2"
	}
	return fmt.Sprintf("%s:{user:%d}:%s", keyPrefix, userID, dimension)
}

func rateKey(userID int64) string {
	return fmt.Sprintf("%s:{user:%d}:rpm", keyPrefix, userID)
}

func digest(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func normalize(raw string) string {
	return strings.Join(strings.Fields(strings.ToLower(strings.TrimSpace(raw))), " ")
}

func normalizeOpaqueID(raw string) string {
	return strings.TrimSpace(raw)
}

func redisInt64(value any) int64 {
	switch value := value.(type) {
	case int64:
		return value
	case int:
		return int64(value)
	case string:
		parsed, _ := strconv.ParseInt(value, 10, 64)
		return parsed
	case []byte:
		parsed, _ := strconv.ParseInt(string(value), 10, 64)
		return parsed
	default:
		return 0
	}
}

func redisString(value any) string {
	switch value := value.(type) {
	case string:
		return value
	case []byte:
		return string(value)
	default:
		return ""
	}
}
