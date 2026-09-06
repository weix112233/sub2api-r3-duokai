package service

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	coderws "github.com/coder/websocket"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
)

// --- machine 模式：客户端 WS 入口（ProxyResponsesWebSocketFromClient）整链用例 ---
// 覆盖 ctx_pool / shared / dedicated / http_bridge / passthrough 五种入站模式：握手头（或 HTTP 出站头）
// sink + response.create 帧 body sink，且跨两个 turn 假名一致（Codex 审查 #1：入口此前对任何模式都不 stage 指纹）。

// machineWSIngressFrame 构造真实 Codex 窗口形态的 response.create 帧（client_metadata 与头同源）。
func machineWSIngressFrame(root, previousResponseID string) string {
	tm := machineChainTurnMetadata(root, root, root+":0", "")
	prev := ""
	if previousResponseID != "" {
		prev = `,"previous_response_id":"` + previousResponseID + `"`
	}
	return `{"type":"response.create","model":"gpt-5.2","stream":false,"prompt_cache_key":"` + root + `"` + prev +
		`,"client_metadata":{"x-codex-installation-id":"real-install","session_id":"` + root + `","thread_id":"` + root +
		`","turn_id":"turn-real","x-codex-window-id":"` + root + `:0","x-codex-turn-metadata":` + jsonQuote(tm) +
		`},"input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"hi"}]}]}`
}

// machineWSIngressSetClientHeaders 把真实 Codex 窗口的握手头写到入口 gin context 上。
func machineWSIngressSetClientHeaders(h http.Header, root string) {
	h.Set("User-Agent", "codex_cli_rs/0.146.0 (Mac OS 26.0.1; arm64) xterm-256color")
	h.Set("originator", "codex_cli_rs")
	h.Set("session-id", root)
	h.Set("thread-id", root)
	h.Set("x-client-request-id", root)
	h.Set("x-codex-window-id", root+":0")
	h.Set("x-codex-installation-id", "real-install")
	h.Set("x-codex-turn-metadata", machineChainTurnMetadata(root, root, root+":0", ""))
	h.Set("session_id", "underscore-session")
}

// machineWSIngressAssertHandshake 断言上游握手头：假名化、无下划线头、无真实值、sandbox 与出站 UA 一致。
func machineWSIngressAssertHandshake(t *testing.T, handshake http.Header, root, p, wantInstall string) {
	t.Helper()
	require.NotNil(t, handshake)
	assert.Equal(t, wantInstall, handshake.Get("x-codex-installation-id"))
	assert.Equal(t, p, handshake.Get("session-id"))
	assert.Equal(t, p, handshake.Get("thread-id"))
	assert.Equal(t, p, handshake.Get("x-client-request-id"))
	assert.Equal(t, p+":0", handshake.Get("x-codex-window-id"))
	assert.Empty(t, handshake.Get("session_id"))
	assert.Empty(t, handshake.Get("conversation_id"))
	for name, values := range handshake {
		for _, v := range values {
			assert.NotContains(t, v, root, "握手头 %s 不得含真实 thread", name)
			assert.NotContains(t, v, "real-install", "握手头 %s 不得含真实 installation", name)
		}
	}
	headTM := handshake.Get("x-codex-turn-metadata")
	require.NotEmpty(t, headTM)
	assert.Equal(t, wantInstall, gjson.Get(headTM, "installation_id").String())
	assert.Equal(t, p, gjson.Get(headTM, "session_id").String())
	assert.Equal(t, p, gjson.Get(headTM, "thread_id").String())
	assert.Equal(t, p+":0", gjson.Get(headTM, "window_id").String())
	assert.Equal(t, "turn-real", gjson.Get(headTM, "turn_id").String())
	assert.Equal(t, codexMachineSandboxTagFromUA(handshake.Get("User-Agent")), gjson.Get(headTM, "sandbox").String())
}

// machineWSIngressAssertPayload 断言送往上游的 response.create 帧：client_metadata / 内嵌 turn metadata / pck 假名化，无真实值。
func machineWSIngressAssertPayload(t *testing.T, payloadJSON, root, p, wantInstall string) {
	t.Helper()
	assert.NotContains(t, payloadJSON, root)
	assert.NotContains(t, payloadJSON, "real-install")
	assert.Equal(t, p, gjson.Get(payloadJSON, "prompt_cache_key").String())
	assert.Equal(t, wantInstall, gjson.Get(payloadJSON, "client_metadata.x-codex-installation-id").String())
	assert.Equal(t, p, gjson.Get(payloadJSON, "client_metadata.session_id").String())
	assert.Equal(t, p, gjson.Get(payloadJSON, "client_metadata.thread_id").String())
	assert.Equal(t, p+":0", gjson.Get(payloadJSON, "client_metadata.x-codex-window-id").String())
	assert.Equal(t, "turn-real", gjson.Get(payloadJSON, "client_metadata.turn_id").String())
	bodyTM := gjson.Get(payloadJSON, "client_metadata.x-codex-turn-metadata").String()
	require.NotEmpty(t, bodyTM)
	assert.Equal(t, wantInstall, gjson.Get(bodyTM, "installation_id").String())
	assert.Equal(t, p, gjson.Get(bodyTM, "session_id").String())
	assert.Equal(t, p, gjson.Get(bodyTM, "thread_id").String())
	assert.Equal(t, p+":0", gjson.Get(bodyTM, "window_id").String())
}

func machineWSIngressExpectations(t *testing.T, account *Account, root string) (p, wantInstall string) {
	t.Helper()
	seed, ok := codexFingerprintSeed(account.Extra)
	require.True(t, ok)
	return codexMachinePseudonym([]byte(seed), root), resolveConvergedInstallationID(account, seed)
}

// machineWSIngressServe 起一个入口 WS 服务：读取首帧后带 Codex 握手头调用 ProxyResponsesWebSocketFromClient。
func machineWSIngressServe(t *testing.T, svc *OpenAIGatewayService, account *Account, root string) (*httptest.Server, <-chan error) {
	t.Helper()
	return machineWSIngressServeWithHeaders(t, svc, account, func(h http.Header) { machineWSIngressSetClientHeaders(h, root) })
}

// machineWSIngressServeWithHeaders 同上，握手头由 setHeaders 自定义（非 Codex 下游用例）。
func machineWSIngressServeWithHeaders(t *testing.T, svc *OpenAIGatewayService, account *Account, setHeaders func(http.Header)) (*httptest.Server, <-chan error) {
	t.Helper()
	serverErrCh := make(chan error, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := coderws.Accept(w, r, &coderws.AcceptOptions{CompressionMode: coderws.CompressionContextTakeover})
		if err != nil {
			serverErrCh <- err
			return
		}
		defer func() { _ = conn.CloseNow() }()

		rec := httptest.NewRecorder()
		ginCtx, _ := gin.CreateTestContext(rec)
		req := r.Clone(r.Context())
		req.Header = req.Header.Clone()
		setHeaders(req.Header)
		ginCtx.Request = req

		readCtx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		msgType, firstMessage, readErr := conn.Read(readCtx)
		cancel()
		if readErr != nil {
			serverErrCh <- readErr
			return
		}
		if msgType != coderws.MessageText && msgType != coderws.MessageBinary {
			serverErrCh <- errors.New("unsupported websocket client message type")
			return
		}
		serverErrCh <- svc.ProxyResponsesWebSocketFromClient(r.Context(), ginCtx, conn, account, "oauth-token", firstMessage, nil)
	}))
	return server, serverErrCh
}

func machineWSIngressDial(t *testing.T, server *httptest.Server) *coderws.Conn {
	t.Helper()
	dialCtx, cancelDial := context.WithTimeout(context.Background(), 3*time.Second)
	clientConn, _, err := coderws.Dial(dialCtx, "ws"+strings.TrimPrefix(server.URL, "http"), nil)
	cancelDial()
	require.NoError(t, err)
	return clientConn
}

func machineWSIngressWrite(t *testing.T, clientConn *coderws.Conn, payload string) {
	t.Helper()
	writeCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	require.NoError(t, clientConn.Write(writeCtx, coderws.MessageText, []byte(payload)))
}

func machineWSIngressRead(t *testing.T, clientConn *coderws.Conn) []byte {
	t.Helper()
	readCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, message, err := clientConn.Read(readCtx)
	require.NoError(t, err)
	return message
}

// machineWSIngressPoolConfig 连接池类入站模式（ctx_pool / shared / dedicated）共用配置。
func machineWSIngressPoolConfig() *config.Config {
	cfg := &config.Config{}
	cfg.Security.URLAllowlist.Enabled = false
	cfg.Security.URLAllowlist.AllowInsecureHTTP = true
	cfg.Gateway.OpenAIWS.Enabled = true
	cfg.Gateway.OpenAIWS.OAuthEnabled = true
	cfg.Gateway.OpenAIWS.APIKeyEnabled = true
	cfg.Gateway.OpenAIWS.ResponsesWebsocketsV2 = true
	cfg.Gateway.OpenAIWS.MaxConnsPerAccount = 1
	cfg.Gateway.OpenAIWS.MinIdlePerAccount = 0
	cfg.Gateway.OpenAIWS.MaxIdlePerAccount = 1
	cfg.Gateway.OpenAIWS.QueueLimitPerConn = 8
	cfg.Gateway.OpenAIWS.DialTimeoutSeconds = 3
	cfg.Gateway.OpenAIWS.ReadTimeoutSeconds = 3
	cfg.Gateway.OpenAIWS.WriteTimeoutSeconds = 3
	return cfg
}

// runMachineWSIngressPoolCase 跑一遍连接池类入站模式（ingressMode 为空 ⇒ 不开 mode router，
// 走默认 ctx_pool）：两个 turn 的握手头 + payload 假名一致。
func runMachineWSIngressPoolCase(t *testing.T, accountID int64, ingressMode string) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	root := testMachineChainRoot

	cfg := machineWSIngressPoolConfig()
	if ingressMode != "" {
		cfg.Gateway.OpenAIWS.ModeRouterV2Enabled = true
		cfg.Gateway.OpenAIWS.IngressModeDefault = OpenAIWSIngressModeCtxPool
	}

	captureConn := &openAIWSCaptureConn{
		events: [][]byte{
			[]byte(`{"type":"response.completed","response":{"id":"resp_machine_ingress_1","model":"gpt-5.2","usage":{"input_tokens":1,"output_tokens":1}}}`),
			[]byte(`{"type":"response.completed","response":{"id":"resp_machine_ingress_2","model":"gpt-5.2","usage":{"input_tokens":1,"output_tokens":1}}}`),
		},
	}
	captureDialer := &openAIWSCaptureDialer{conn: captureConn}
	pool := newOpenAIWSConnPool(cfg)
	pool.setClientDialerForTest(captureDialer)
	svc := &OpenAIGatewayService{
		cfg:              cfg,
		httpUpstream:     &httpUpstreamRecorder{},
		cache:            &stubGatewayCache{},
		openaiWSResolver: NewOpenAIWSProtocolResolver(cfg),
		toolCorrector:    NewCodexToolCorrector(),
		openaiWSPool:     pool,
	}
	account := newMachineWSChainAccount(t, accountID, testCodexFingerprintSeed)
	if ingressMode != "" {
		account.Extra["openai_oauth_responses_websockets_v2_mode"] = ingressMode
	}

	server, serverErrCh := machineWSIngressServe(t, svc, account, root)
	defer server.Close()
	clientConn := machineWSIngressDial(t, server)
	defer func() { _ = clientConn.CloseNow() }()

	machineWSIngressWrite(t, clientConn, machineWSIngressFrame(root, ""))
	first := machineWSIngressRead(t, clientConn)
	require.Equal(t, "resp_machine_ingress_1", gjson.GetBytes(first, "response.id").String())
	machineWSIngressWrite(t, clientConn, machineWSIngressFrame(root, "resp_machine_ingress_1"))
	second := machineWSIngressRead(t, clientConn)
	require.Equal(t, "resp_machine_ingress_2", gjson.GetBytes(second, "response.id").String())
	_ = clientConn.Close(coderws.StatusNormalClosure, "done")

	select {
	case serverErr := <-serverErrCh:
		require.NoError(t, serverErr)
	case <-time.After(5 * time.Second):
		t.Fatal("等待 ingress websocket 结束超时")
	}

	p, wantInstall := machineWSIngressExpectations(t, account, root)
	machineWSIngressAssertHandshake(t, captureDialer.lastHeaders, root, p, wantInstall)
	require.Len(t, captureConn.writes, 2)
	firstJSON := requestToJSONString(captureConn.writes[0])
	secondJSON := requestToJSONString(captureConn.writes[1])
	machineWSIngressAssertPayload(t, firstJSON, root, p, wantInstall)
	machineWSIngressAssertPayload(t, secondJSON, root, p, wantInstall)
	// 第二 turn 与首 turn 假名一致（同一份 staged IDs 跨 turn 复用）
	assert.Equal(t, gjson.Get(firstJSON, "client_metadata.thread_id").String(), gjson.Get(secondJSON, "client_metadata.thread_id").String())
	assert.Equal(t, "resp_machine_ingress_1", gjson.Get(secondJSON, "previous_response_id").String())
}

// ctx_pool 入站模式（默认，不开 mode router）。
func TestCodexMachineChain_WSIngress_CtxPool_TwoTurns(t *testing.T) {
	runMachineWSIngressPoolCase(t, 6201, "")
}

// shared 入站模式（mode router v2）。
func TestCodexMachineChain_WSIngress_Shared_TwoTurns(t *testing.T) {
	runMachineWSIngressPoolCase(t, 6204, OpenAIWSIngressModeShared)
}

// dedicated 入站模式（mode router v2，ForceNewConn）。
func TestCodexMachineChain_WSIngress_Dedicated_TwoTurns(t *testing.T) {
	runMachineWSIngressPoolCase(t, 6205, OpenAIWSIngressModeDedicated)
}

// machineWSIngressSSEResponse 构造 http_bridge 上游的最小 SSE 终态响应。
func machineWSIngressSSEResponse(responseID string) *http.Response {
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"text/event-stream"}, "x-request-id": []string{"rid_" + responseID}},
		Body: io.NopCloser(strings.NewReader(
			"data: {\"type\":\"response.completed\",\"response\":{\"id\":\"" + responseID + "\",\"model\":\"gpt-5.2\",\"usage\":{\"input_tokens\":1,\"output_tokens\":1}}}\n\n" +
				"data: [DONE]\n\n",
		)),
	}
}

// http_bridge 入站模式：每个 turn 经 buildUpstreamRequestOpenAIPassthrough 走 HTTP 上游，
// 出站头由构造器内的 staged 头 sink 改写，body 只经入口 parseClientPayload 的 raw sink
// （构造器不再改 body）；断言两者是同一份假名 P 且不出现二次假名化 P(P(x))。
func TestCodexMachineChain_WSIngress_HTTPBridge_TwoTurns(t *testing.T) {
	gin.SetMode(gin.TestMode)
	root := testMachineChainRoot

	cfg := machineWSIngressPoolConfig()
	cfg.Gateway.OpenAIWS.ModeRouterV2Enabled = true
	cfg.Gateway.OpenAIWS.IngressModeDefault = OpenAIWSIngressModeCtxPool

	upstream := &httpUpstreamRecorder{responses: []*http.Response{
		machineWSIngressSSEResponse("resp_machine_bridge_1"),
		machineWSIngressSSEResponse("resp_machine_bridge_2"),
	}}
	svc := &OpenAIGatewayService{
		cfg:              cfg,
		httpUpstream:     upstream,
		cache:            &stubGatewayCache{},
		openaiWSResolver: NewOpenAIWSProtocolResolver(cfg),
		toolCorrector:    NewCodexToolCorrector(),
	}
	account := newMachineWSChainAccount(t, 6206, testCodexFingerprintSeed)
	account.Extra["openai_oauth_responses_websockets_v2_mode"] = OpenAIWSIngressModeHTTPBridge

	server, serverErrCh := machineWSIngressServe(t, svc, account, root)
	defer server.Close()
	clientConn := machineWSIngressDial(t, server)
	defer func() { _ = clientConn.CloseNow() }()

	machineWSIngressWrite(t, clientConn, machineWSIngressFrame(root, ""))
	first := machineWSIngressRead(t, clientConn)
	require.Equal(t, "resp_machine_bridge_1", gjson.GetBytes(first, "response.id").String())
	// 第二 turn 换一条 user 文本：让 http_bridge 的 replay 合并可观察（同文本会被 prefix 判定吸收）。
	secondFrame := strings.Replace(machineWSIngressFrame(root, "resp_machine_bridge_1"), `"text":"hi"`, `"text":"again"`, 1)
	machineWSIngressWrite(t, clientConn, secondFrame)
	second := machineWSIngressRead(t, clientConn)
	require.Equal(t, "resp_machine_bridge_2", gjson.GetBytes(second, "response.id").String())
	_ = clientConn.Close(coderws.StatusNormalClosure, "done")

	select {
	case serverErr := <-serverErrCh:
		require.NoError(t, serverErr)
	case <-time.After(5 * time.Second):
		t.Fatal("等待 http_bridge websocket 结束超时")
	}

	p, wantInstall := machineWSIngressExpectations(t, account, root)
	require.Len(t, upstream.requests, 2)
	require.Len(t, upstream.bodies, 2)
	for i := range upstream.requests {
		machineWSIngressAssertHandshake(t, upstream.requests[i].Header, root, p, wantInstall)
		machineWSIngressAssertPayload(t, string(upstream.bodies[i]), root, p, wantInstall)
	}
	// http_bridge 把 previous_response_id 转成 replay input：第二 turn 上游 body 不含
	// previous_response_id（prepareOpenAIWSHTTPBridgeBody 剥离），input 为 turn1+turn2 合并；
	// 两 turn 假名一致由上面逐 turn 断言 == p 保证。
	require.False(t, gjson.GetBytes(upstream.bodies[0], "previous_response_id").Exists())
	require.False(t, gjson.GetBytes(upstream.bodies[1], "previous_response_id").Exists(), "http_bridge 第二 turn 不得透传 previous_response_id")
	require.Len(t, gjson.GetBytes(upstream.bodies[0], "input").Array(), 1)
	replayInput := gjson.GetBytes(upstream.bodies[1], "input").Array()
	require.Len(t, replayInput, 2, "http_bridge 第二 turn input 应为 turn1+turn2 replay 合并")
	require.Equal(t, "hi", replayInput[0].Get("content.0.text").String())
	require.Equal(t, "again", replayInput[1].Get("content.0.text").String())
	assert.Equal(t, gjson.GetBytes(upstream.bodies[0], "client_metadata.thread_id").String(), gjson.GetBytes(upstream.bodies[1], "client_metadata.thread_id").String())
}

// machineWSIngressHeaderCaptureDialer 记录握手头并返回受控的 stagedPassthroughConn。
type machineWSIngressHeaderCaptureDialer struct {
	mu          sync.Mutex
	conn        openAIWSClientConn
	lastHeaders http.Header
}

func (d *machineWSIngressHeaderCaptureDialer) Dial(_ context.Context, _ string, headers http.Header, _ string) (openAIWSClientConn, int, http.Header, error) {
	d.mu.Lock()
	d.lastHeaders = cloneHeader(headers)
	d.mu.Unlock()
	return d.conn, http.StatusSwitchingProtocols, http.Header{}, nil
}

func (d *machineWSIngressHeaderCaptureDialer) headers() http.Header {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.lastHeaders
}

// passthrough 入站模式：首帧（主 goroutine）与后续帧（relay filter）都经 body sink，两 turn 假名一致。
func TestCodexMachineChain_WSIngress_Passthrough_TwoTurns(t *testing.T) {
	gin.SetMode(gin.TestMode)
	root := testMachineChainRoot

	cfg := passthroughLifecycleConfig()
	cfg.Gateway.OpenAIWS.OAuthEnabled = true
	cfg.Gateway.OpenAIFirstOutputTimeoutSeconds = 3
	cfg.Gateway.OpenAIWS.IngressInterTurnIdleTimeoutSeconds = 3
	cfg.Gateway.OpenAIWS.ReadTimeoutSeconds = 3
	upstream := newStagedPassthroughConn()
	dialer := &machineWSIngressHeaderCaptureDialer{conn: upstream}
	svc := &OpenAIGatewayService{
		cfg:                       cfg,
		httpUpstream:              &httpUpstreamRecorder{},
		cache:                     &stubGatewayCache{},
		openaiWSResolver:          NewOpenAIWSProtocolResolver(cfg),
		toolCorrector:             NewCodexToolCorrector(),
		openaiWSPassthroughDialer: dialer,
	}
	account := newMachineWSChainAccount(t, 6202, testCodexFingerprintSeed)
	account.Extra["openai_oauth_responses_websockets_v2_mode"] = OpenAIWSIngressModePassthrough

	server, serverErrCh := machineWSIngressServe(t, svc, account, root)
	defer server.Close()
	clientConn := machineWSIngressDial(t, server)
	defer func() { _ = clientConn.CloseNow() }()

	machineWSIngressWrite(t, clientConn, machineWSIngressFrame(root, ""))
	firstUpstream := requirePassthroughUpstreamWrite(t, upstream, 3*time.Second)
	upstream.Send(`{"type":"response.completed","response":{"id":"resp_machine_pt_1","model":"gpt-5.2","usage":{"input_tokens":1,"output_tokens":1}}}`)
	first := machineWSIngressRead(t, clientConn)
	require.Equal(t, "resp_machine_pt_1", gjson.GetBytes(first, "response.id").String())

	machineWSIngressWrite(t, clientConn, machineWSIngressFrame(root, "resp_machine_pt_1"))
	secondUpstream := requirePassthroughUpstreamWrite(t, upstream, 3*time.Second)
	upstream.Send(`{"type":"response.completed","response":{"id":"resp_machine_pt_2","model":"gpt-5.2","usage":{"input_tokens":1,"output_tokens":1}}}`)
	second := machineWSIngressRead(t, clientConn)
	require.Equal(t, "resp_machine_pt_2", gjson.GetBytes(second, "response.id").String())
	_ = clientConn.Close(coderws.StatusNormalClosure, "done")

	select {
	case serverErr := <-serverErrCh:
		if serverErr != nil {
			require.Contains(t, serverErr.Error(), "StatusNormalClosure")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("等待 passthrough websocket 结束超时")
	}

	p, wantInstall := machineWSIngressExpectations(t, account, root)
	machineWSIngressAssertHandshake(t, dialer.headers(), root, p, wantInstall)
	machineWSIngressAssertPayload(t, string(firstUpstream), root, p, wantInstall)
	machineWSIngressAssertPayload(t, string(secondUpstream), root, p, wantInstall)
	assert.Equal(t, gjson.GetBytes(firstUpstream, "client_metadata.thread_id").String(), gjson.GetBytes(secondUpstream, "client_metadata.thread_id").String())
	assert.Equal(t, "resp_machine_pt_1", gjson.GetBytes(secondUpstream, "previous_response_id").String())
}

// off 模式：入口不 stage，不做本地指纹收敛；官方账号 namespace 仍对握手头和
// payload 身份做凭据级隔离。
func TestCodexMachineChain_WSIngress_OffModeUsesAccountNamespace(t *testing.T) {
	gin.SetMode(gin.TestMode)
	root := testMachineChainRoot

	cfg := passthroughLifecycleConfig()
	cfg.Gateway.OpenAIWS.OAuthEnabled = true
	cfg.Gateway.OpenAIFirstOutputTimeoutSeconds = 3
	upstream := newStagedPassthroughConn()
	dialer := &machineWSIngressHeaderCaptureDialer{conn: upstream}
	svc := &OpenAIGatewayService{
		cfg:                       cfg,
		httpUpstream:              &httpUpstreamRecorder{},
		cache:                     &stubGatewayCache{},
		openaiWSResolver:          NewOpenAIWSProtocolResolver(cfg),
		toolCorrector:             NewCodexToolCorrector(),
		openaiWSPassthroughDialer: dialer,
	}
	account := newMachineWSChainAccount(t, 6203, testCodexFingerprintSeed)
	account.Extra[codexFingerprintModeExtraKey] = "off"
	account.Extra["openai_oauth_responses_websockets_v2_mode"] = OpenAIWSIngressModePassthrough

	server, serverErrCh := machineWSIngressServe(t, svc, account, root)
	defer server.Close()
	clientConn := machineWSIngressDial(t, server)
	defer func() { _ = clientConn.CloseNow() }()

	machineWSIngressWrite(t, clientConn, machineWSIngressFrame(root, ""))
	firstUpstream := requirePassthroughUpstreamWrite(t, upstream, 3*time.Second)
	upstream.Send(`{"type":"response.completed","response":{"id":"resp_off_pt_1","model":"gpt-5.2","usage":{"input_tokens":1,"output_tokens":1}}}`)
	first := machineWSIngressRead(t, clientConn)
	require.Equal(t, "resp_off_pt_1", gjson.GetBytes(first, "response.id").String())
	_ = clientConn.Close(coderws.StatusNormalClosure, "done")
	select {
	case serverErr := <-serverErrCh:
		if serverErr != nil {
			require.Contains(t, serverErr.Error(), "StatusNormalClosure")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("等待 passthrough websocket 结束超时")
	}

	handshake := dialer.headers()
	require.NotNil(t, handshake)
	assert.Equal(t, scopeCodexAccountIdentityValue(account, 0, "session", root), handshake.Get("session-id"))
	assert.Equal(t, scopeCodexAccountIdentityValue(account, 0, "thread", root), handshake.Get("thread-id"))
	assert.Equal(t, scopeCodexAccountIdentityValue(account, 0, "window", root+":0"), handshake.Get("x-codex-window-id"))
	assert.Equal(t, scopeCodexAccountIdentityValue(account, 0, "installation", "real-install"), handshake.Get("x-codex-installation-id"))
	wantSession := scopeCodexAccountIdentityValue(account, 0, "session", root)
	assert.Equal(t, wantSession, gjson.GetBytes(firstUpstream, "client_metadata.session_id").String())
	assert.Equal(t, wantSession, gjson.GetBytes(firstUpstream, "prompt_cache_key").String())
}
