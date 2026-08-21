//go:build soak

// soak_canary_test.go — machine 模式灰度观测负载（自包含，基线/候选两树同构可移植）。
//
// 用法：
//
//	SOAK_MODE=machine|session SOAK_DURATION=10m SOAK_WINDOWS=6 SOAK_PACE_MS=150 \
//	SOAK_OUT=/path/report.json go test -tags=soak ./internal/service/ -run TestSoakCanaryMachineWindow -timeout 30m -v
//
// 观测维度（每 turn 对捕获的上游请求内联校验，只留计数不留样本）：
//  1. rawLeaks       —— 任何窗口的原始 session/thread/installation 出现在出站头或 body
//  2. pckMismatch    —— 头 session-id ≠ body prompt_cache_key（需求缺陷 #1）
//  3. v7Bad          —— 出站 session-id/thread-id/x-client-request-id/prompt_cache_key 非 UUIDv7 形态（缺陷 #2）
//  4. unstableID     —— 同一窗口跨 turn 的出站 session-id 漂移
//  5. underscoreHdr  —— 下划线 session_id / conversation_id 出站（缺陷 #3 只改不增）
//  6. latency        —— Forward 耗时分位数；吞吐；内存/GC 快照
package service

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/pkg/tlsfingerprint"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/tidwall/gjson"
)

// --- 自包含 mock 上游（实现 HTTPUpstream，两树接口一致） ---

type soakUpstream struct {
	mu      sync.Mutex
	lastReq *http.Request
	lastRaw []byte
	calls   int64
}

func (u *soakUpstream) Do(req *http.Request, _ string, _ int64, _ int) (*http.Response, error) {
	return u.record(req)
}

func (u *soakUpstream) DoWithTLS(req *http.Request, _ string, _ int64, _ int, _ *tlsfingerprint.Profile) (*http.Response, error) {
	return u.record(req)
}

// record 拷贝请求体后回放一个 200 SSE 流（透传路径对 OAuth /responses 强制 stream=true，
// 形态与 openai_oauth_passthrough_test.go 的成功 mock 一致：data 事件 + [DONE]）。
func (u *soakUpstream) record(req *http.Request) (*http.Response, error) {
	raw := []byte{}
	if req != nil && req.Body != nil {
		raw, _ = io.ReadAll(req.Body)
		_ = req.Body.Close()
		req.Body = io.NopCloser(bytes.NewReader(raw))
	}
	u.mu.Lock()
	u.lastReq = req
	u.lastRaw = raw
	u.calls++
	u.mu.Unlock()
	sse := strings.Join([]string{
		`data: {"type":"response.completed","response":{"id":"resp_soak","status":"completed","usage":{"input_tokens":1,"output_tokens":1,"input_cached_tokens":0}}}`,
		"",
		"data: [DONE]",
		"",
	}, "\n")
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"text/event-stream"}, "x-request-id": []string{"rid_soak"}},
		Body:       io.NopCloser(strings.NewReader(sse)),
	}, nil
}

func (u *soakUpstream) capture() (*http.Request, []byte) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.lastReq == nil {
		return nil, nil
	}
	hdr := u.lastReq.Header.Clone()
	req := &http.Request{Header: hdr, Host: u.lastReq.Host}
	return req, append([]byte(nil), u.lastRaw...)
}

// --- 灰度窗口 ---

type soakWindow struct {
	idx         int
	rawSession  string // 下游真实 session/thread（根窗口两者同值，UUIDv7）
	rawThread   string
	windowID    string
	parent      string // 非空 ⇒ 子 Agent 窗口
	turns       int64
	firstOut    string // 该窗口首次观测到的出站 session-id
	unstable    int64
	rawLeaks    int64
	pckMismatch int64
	v7Bad       int64
	underHdr    int64
	errs        int64
}

func (w *soakWindow) isSubagent() bool { return w.parent != "" }

func soakV7(id string) bool {
	parsed, err := uuid.Parse(strings.TrimSpace(id))
	if err != nil {
		return false
	}
	return parsed.Version() == 7 && parsed.Variant() == uuid.RFC4122
}

func soakEnvDuration(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}

func soakEnvInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		var n int
		if _, err := fmt.Sscanf(v, "%d", &n); err == nil && n > 0 {
			return n
		}
	}
	return def
}

// soakBuildTurn 构造一次真实 Codex 窗口形态的下游请求（头/body 同源，与
// openai_codex_machine_chain_test.go 的 machineChainRequest 同构，但自包含）。
// 返回 gin context 与 body 字节（Forward 需要显式接收 body）。
func soakBuildTurn(w *soakWindow) (*gin.Context, []byte) {
	tm := `{"installation_id":"real-install","session_id":"` + w.rawSession + `","thread_id":"` + w.rawThread + `","turn_id":"turn-soak-` + fmt.Sprint(w.turns+1) + `","window_id":"` + w.windowID + `","sandbox":"seccomp","sandbox_mode":"workspace-write","thread_source":"cli"`
	cmExtra := ""
	if w.isSubagent() {
		tm += `,"parent_thread_id":"` + w.parent + `"`
		cmExtra = `,"x-codex-parent-thread-id":"` + w.parent + `","x-openai-subagent":"explore"`
	}
	tm += `}`
	body := `{"model":"gpt-5.2","stream":false,"prompt_cache_key":"` + w.rawSession + `","instructions":"soak","client_metadata":{"x-codex-installation-id":"real-install","session_id":"` + w.rawSession + `","thread_id":"` + w.rawThread + `","turn_id":"turn-soak-` + fmt.Sprint(w.turns+1) + `","x-codex-window-id":"` + w.windowID + `"` + cmExtra + `,"x-codex-turn-metadata":` + soakJSONQuote(tm) + `},"input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"hi"}]}]}`

	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", bytes.NewReader([]byte(body)))
	h := c.Request.Header
	h.Set("Content-Type", "application/json")
	h.Set("User-Agent", "codex_cli_rs/0.146.0 (Mac OS 26.0.1; arm64) xterm-256color")
	h.Set("originator", "codex_cli_rs")
	h.Set("session-id", w.rawSession)
	h.Set("thread-id", w.rawThread)
	h.Set("x-client-request-id", w.rawThread)
	h.Set("x-codex-window-id", w.windowID)
	h.Set("x-codex-installation-id", "real-install")
	h.Set("x-codex-turn-metadata", tm)
	h.Set("session_id", "underscore-session")
	h.Set("conversation_id", "underscore-conversation")
	if w.isSubagent() {
		h.Set("x-codex-parent-thread-id", w.parent)
		h.Set("x-openai-subagent", "explore")
	}
	return c, []byte(body)
}

func soakJSONQuote(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// soakAnalyzeTurn 对捕获的出站请求做内联不变量校验，返回本 turn 延迟（含 Forward）。
func soakAnalyzeTurn(t *testing.T, svc *OpenAIGatewayService, account *Account, w *soakWindow) (time.Duration, error) {
	c, bodyBytes := soakBuildTurn(w)
	start := time.Now()
	_, err := svc.Forward(context.Background(), c, account, bodyBytes)
	latency := time.Since(start)
	if err != nil {
		w.errs++
		return latency, err
	}
	req, body := svc.httpUpstream.(*soakUpstream).capture()
	if req == nil {
		w.errs++
		return latency, fmt.Errorf("no upstream capture")
	}
	w.turns++

	// 1. 原始标识不得出现在任何出站头或 body
	leaked := false
	for name, values := range req.Header {
		for _, v := range values {
			if strings.Contains(v, w.rawThread) || strings.Contains(v, w.rawSession) || strings.Contains(v, "real-install") || strings.Contains(v, "underscore-") {
				leaked = true
				_ = name
			}
		}
	}
	if strings.Contains(string(body), w.rawThread) || strings.Contains(string(body), w.rawSession) || strings.Contains(string(body), "real-install") {
		leaked = true
	}
	if leaked {
		w.rawLeaks++
	}

	// 2. 头 session-id 与 body prompt_cache_key 一致
	outSession := req.Header.Get("session-id")
	pck := gjson.GetBytes(body, "prompt_cache_key").String()
	if w.turns <= 1 && w.idx == 0 {
		t.Logf("SOAKDBG raw=%s outSession=[%s] thread=[%s] pck=[%s] bodylen=%d body=%s",
			w.rawThread, outSession, req.Header.Get("thread-id"), pck, len(body), string(body))
	}
	if outSession == "" || pck == "" || outSession != pck {
		w.pckMismatch++
	}

	// 3. 出站标识必须是 UUIDv7 形态
	if !soakV7(outSession) || !soakV7(req.Header.Get("thread-id")) || !soakV7(req.Header.Get("x-client-request-id")) || !soakV7(pck) {
		w.v7Bad++
	}

	// 4. 同窗口出站 session-id 跨 turn 稳定
	if w.firstOut == "" {
		w.firstOut = outSession
	} else if outSession != w.firstOut {
		w.unstable++
	}

	// 5. 只改不增：下划线头不得出站
	if req.Header.Get("session_id") != "" || req.Header.Get("conversation_id") != "" {
		w.underHdr++
	}
	return latency, nil
}

func TestSoakCanaryMachineWindow(t *testing.T) {
	mode := os.Getenv("SOAK_MODE")
	if mode == "" {
		mode = "machine"
	}
	duration := soakEnvDuration("SOAK_DURATION", 10*time.Minute)
	windowsN := soakEnvInt("SOAK_WINDOWS", 6)
	pace := soakEnvDuration("SOAK_PACE_MS", 0)
	if pace == 0 {
		pace = time.Duration(soakEnvInt("SOAK_PACE_MS_NUM", 150)) * time.Millisecond
	}
	outPath := os.Getenv("SOAK_OUT")

	gin.SetMode(gin.TestMode)

	// 窗口 0..N-2 为根窗口（thread:n 的 :0），最后一个为子 Agent 窗口。
	base, _ := uuid.Parse("01912e2a-6f3c-7d1e-9c4a-0f1e2d3c4b5a")
	windows := make([]*soakWindow, 0, windowsN)
	for i := 0; i < windowsN; i++ {
		raw := uuid.Must(uuid.NewV7()).String()
		w := &soakWindow{idx: i, rawSession: raw, rawThread: raw, windowID: raw + ":0"}
		if i == windowsN-1 {
			parent := windows[0].rawThread
			w.parent = parent
			w.windowID = parent + ":1"
		}
		_ = base
		windows = append(windows, w)
	}

	f64v := 1.0
	extra := map[string]any{
		"codex_fingerprint_mode": mode,
		"codex_fingerprint_seed": "11111111-1111-4111-8111-111111111111",
		"openai_passthrough":     true,
	}
	account := &Account{
		ID:             9101,
		Name:           "soak-" + mode,
		Platform:       PlatformOpenAI,
		Type:           AccountTypeOAuth,
		Status:         StatusActive,
		Schedulable:    true,
		Concurrency:    windowsN,
		RateMultiplier: &f64v,
		Credentials:    map[string]any{"access_token": "oauth-token", "chatgpt_account_id": "chatgpt-acc"},
		Extra:          extra,
	}

	upstream := &soakUpstream{}
	svc := &OpenAIGatewayService{cfg: &config.Config{}, httpUpstream: upstream}

	started := time.Now()
	deadline := started.Add(duration)
	var latencies []float64
	totalTurns := 0
	for time.Now().Before(deadline) {
		for _, w := range windows {
			if time.Now().After(deadline) {
				break
			}
			lat, err := soakAnalyzeTurn(t, svc, account, w)
			if err == nil {
				latencies = append(latencies, float64(lat.Microseconds())/1000.0)
			}
			totalTurns++
			time.Sleep(pace)
		}
	}
	elapsed := time.Since(started)

	sort.Float64s(latencies)
	pct := func(p float64) float64 {
		if len(latencies) == 0 {
			return 0
		}
		idx := int(float64(len(latencies)-1) * p)
		return latencies[idx]
	}
	sum := 0.0
	for _, v := range latencies {
		sum += v
	}

	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)

	type winReport struct {
		Idx         int    `json:"idx"`
		Subagent    bool   `json:"subagent"`
		Turns       int64  `json:"turns"`
		FirstOutID  string `json:"first_out_session_id"`
		RawLeaks    int64  `json:"raw_leaks"`
		PCKMismatch int64  `json:"pck_mismatch"`
		V7Bad       int64  `json:"v7_bad"`
		Unstable    int64  `json:"unstable_id"`
		Underscore  int64  `json:"underscore_headers"`
		Errors      int64  `json:"errors"`
	}
	report := struct {
		Mode          string  `json:"mode"`
		StartedAt     string  `json:"started_at"`
		DurationS     float64 `json:"duration_s"`
		WindowCount   int     `json:"window_count"`
		TotalTurns    int     `json:"total_turns"`
		UpstreamCalls int64   `json:"upstream_calls"`
		LatencyMS     struct {
			Mean float64 `json:"mean"`
			P50  float64 `json:"p50"`
			P90  float64 `json:"p90"`
			P99  float64 `json:"p99"`
			Max  float64 `json:"max"`
		} `json:"latency_ms"`
		Violations struct {
			RawLeaks    int64 `json:"raw_leaks"`
			PCKMismatch int64 `json:"pck_mismatch"`
			V7Bad       int64 `json:"v7_bad"`
			UnstableID  int64 `json:"unstable_id"`
			Underscore  int64 `json:"underscore_headers"`
			Errors      int64 `json:"errors"`
		} `json:"violations"`
		Mem struct {
			HeapAllocMB float64 `json:"heap_alloc_mb"`
			SysMB       float64 `json:"sys_mb"`
			NumGC       uint32  `json:"num_gc"`
			Goroutines  int     `json:"goroutines"`
		} `json:"mem"`
		Windows []winReport `json:"windows"`
	}{
		Mode: mode, StartedAt: started.Format(time.RFC3339), DurationS: elapsed.Seconds(),
		WindowCount: windowsN, TotalTurns: totalTurns,
	}
	report.UpstreamCalls = upstream.calls
	if len(latencies) > 0 {
		report.LatencyMS.Mean = sum / float64(len(latencies))
		report.LatencyMS.P50 = pct(0.50)
		report.LatencyMS.P90 = pct(0.90)
		report.LatencyMS.P99 = pct(0.99)
		report.LatencyMS.Max = latencies[len(latencies)-1]
	}
	report.Mem.HeapAllocMB = float64(ms.HeapAlloc) / 1024 / 1024
	report.Mem.SysMB = float64(ms.Sys) / 1024 / 1024
	report.Mem.NumGC = ms.NumGC
	report.Mem.Goroutines = runtime.NumGoroutine()

	distinct := map[string]bool{}
	for _, w := range windows {
		report.Windows = append(report.Windows, winReport{
			w.idx, w.isSubagent(), w.turns, w.firstOut, w.rawLeaks, w.pckMismatch, w.v7Bad, w.unstable, w.underHdr, w.errs,
		})
		report.Violations.RawLeaks += w.rawLeaks
		report.Violations.PCKMismatch += w.pckMismatch
		report.Violations.V7Bad += w.v7Bad
		report.Violations.UnstableID += w.unstable
		report.Violations.Underscore += w.underHdr
		report.Violations.Errors += w.errs
		if w.firstOut != "" {
			distinct[w.firstOut] = true
		}
	}

	blob, _ := json.MarshalIndent(report, "", "  ")
	if outPath != "" {
		if err := os.WriteFile(outPath, blob, 0o644); err != nil {
			t.Fatalf("write report: %v", err)
		}
	}
	t.Logf("soak mode=%s turns=%d violations=%+v distinct_out_ids=%d/%d lat_p50=%.2fms p99=%.2fms heap=%.1fMB",
		mode, totalTurns, report.Violations, len(distinct), windowsN, report.LatencyMS.P50, report.LatencyMS.P99, report.Mem.HeapAllocMB)

	// 灰度组（machine）的硬性闸门：任何泄漏/漂移/形态违规都直接判失败；
	// 对照组（session/基线）仅产出数据，不设闸门，便于量化差异。
	if mode == "machine" {
		if report.Violations.RawLeaks > 0 || report.Violations.UnstableID > 0 || report.Violations.PCKMismatch > 0 ||
			report.Violations.V7Bad > 0 || report.Violations.Underscore > 0 || report.Violations.Errors > 0 {
			t.Fatalf("machine 灰度不变量被打破: %+v", report.Violations)
		}
		if len(distinct) != windowsN {
			t.Fatalf("窗口假名应 %d 个不同值, 实际 %d 个（跨窗口收敛/漂移）", windowsN, len(distinct))
		}
	}
}
