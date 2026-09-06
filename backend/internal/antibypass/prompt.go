package antibypass

import (
	"bytes"
	"encoding/json"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf16"

	"golang.org/x/text/unicode/norm"
)

type Detection struct {
	Reason      Reason
	SignalCount int
}

var (
	strongJailbreakPatterns = []*regexp.Regexp{
		regexp.MustCompile(`\b(ignore|disregard|forget|override)\b.{0,80}\b(previous|prior|system|developer|safety|policy|instructions?|rules?)\b`),
		regexp.MustCompile(`\b(reveal|show|print|output|dump|repeat)\b.{0,80}\b(system|developer|hidden)\b.{0,40}\b(prompt|message|instructions?)\b`),
		regexp.MustCompile(`忽略.{0,30}(之前|以上|先前).{0,20}(指令|指示|规则)`),
		regexp.MustCompile(`输出.{0,30}(系统|开发者).{0,30}(提示词|指令|消息)`),
	}
	overridePattern     = regexp.MustCompile(`\b(ignore|disregard|forget|override|follow only)\b|忽略|无视|覆盖`)
	secretPattern       = regexp.MustCompile(`\b(system prompt|developer message|hidden instructions?|secret prompt)\b|系统提示词|开发者消息|隐藏指令`)
	rolePattern         = regexp.MustCompile(`\b(unrestricted|no safety|without restrictions?|you are now)\b|解除限制|没有安全限制`)
	analysisPattern     = regexp.MustCompile(`\b(analy[sz]e|analysis|classify|classification|detect|review|explain)\b|分析|研判|分类|检测|审查|解释`)
	activeBypassPattern = regexp.MustCompile(
		`\b(bypass|disable|remove|turn off)\b.{0,60}\b(safety|guardrails?|policy|restrictions?)\b|` +
			`绕过.{0,30}(安全|限制|护栏|策略)|解除.{0,20}(安全|限制|护栏)`,
	)
	defensiveBypassPattern = regexp.MustCompile(
		`\b(prevent|stop|block|avoid)\b.{0,80}\b(bypass(?:ing|ed)?|disabl(?:e|ing|ed)|remov(?:e|ing|ed)|jailbreak(?:ing|ed)?)\b|` +
			`\b(detect|identify|mitigate|defend against|protect against)\b.{0,80}\b(attempts?\s+to\s+bypass|bypassing|jailbreak(?:s|ing|ed| attempts?)?)\b|` +
			`(?:防止|阻止|拦截).{0,50}(?:绕过|越狱|解除限制)|` +
			`(?:检测|识别|缓解|防御).{0,50}(?:越狱|绕过行为|绕过尝试|绕过攻击)`,
	)
	activationPattern = regexp.MustCompile(
		`\b(activate|enable|enter|switch to|act as|become|you are now)\b.{0,50}\b(jailbreak mode|dan mode|unrestricted mode|unrestricted assistant|uncensored assistant)\b|` +
			`(?:启用|开启|进入|切换到|扮演|变成).{0,30}(?:越狱|dan|无限制|无审查)(?:模式)?`,
	)
	noExecutePattern = regexp.MustCompile(
		`\b(do not|don't|never|must not)\b.{0,40}\b(execute|follow|obey|comply|perform|act on)\b|` +
			`不要.{0,20}(执行|遵循|服从|照做)|不得.{0,20}(执行|遵循|服从|照做)|仅分析不执行`,
	)
	quotedSamplePattern  = regexp.MustCompile(`\b(quoted|quote|sample|example|payload|attack string|jailbreak prompt)\b|引用|样本|示例|攻击文本|越狱提示词`)
	explicitQuotePattern = regexp.MustCompile("(?s)\"[^\"\\n]+\"|“[^”\\n]+”|```.+?```")
	analysisLabelPattern = regexp.MustCompile(`\b(quoted\s+)?jailbreak\s+(sample|prompt)\b|越狱提示词(样本)?`)
)

// DetectJailbreak scans only bounded request bytes and never returns the
// original text. It intentionally blocks high-confidence combinations rather
// than treating every mention of "prompt" as malicious.
func DetectJailbreak(body []byte, maxBytes int) (bool, Detection) {
	if maxBytes <= 0 || len(body) == 0 || len(body) > maxBytes {
		return false, Detection{}
	}
	if !rawBodyMayContainJailbreak(body) {
		return false, Detection{}
	}

	text, encodingLimit := decodePromptUnicodeEscapes(norm.NFKC.String(extractPromptText(body)))
	if encodingLimit {
		return true, Detection{Reason: ReasonPromptEncodingLimit, SignalCount: 1}
	}
	text = normalizePrompt(text)
	if text == "" {
		return false, Detection{}
	}
	if isExplicitSecurityAnalysis(text) {
		return false, Detection{}
	}

	blocked, signals := containsJailbreakSignals(text)
	if blocked {
		return true, Detection{Reason: ReasonPromptJailbreak, SignalCount: signals}
	}
	return false, Detection{}
}

func rawBodyMayContainJailbreak(body []byte) bool {
	var builder strings.Builder
	builder.Grow(len(body))
	hasUnicodeEscape := false
	for index, value := range body {
		if value >= unicode.MaxASCII {
			// This fast path must over-approximate the Unicode-aware detector.
			// Compact keyword matching loses Chinese rules with intervening words.
			return true
		}
		if value == '\\' && index+1 < len(body) && body[index+1] == 'u' {
			hasUnicodeEscape = true
		}
		switch {
		case value >= 'A' && value <= 'Z':
			builder.WriteByte(value + ('a' - 'A'))
		case value >= 'a' && value <= 'z':
			builder.WriteByte(value)
		case value >= '0' && value <= '9':
			builder.WriteByte(value)
		}
	}
	return hasUnicodeEscape || rawCompactMayContainJailbreak(builder.String())
}

func extractPromptText(body []byte) string {
	var root map[string]any
	if json.Unmarshal(body, &root) != nil {
		return string(body)
	}

	var builder strings.Builder
	if messages, ok := root["messages"]; ok {
		appendRoleMessages(&builder, messages, false)
	}
	if input, ok := root["input"]; ok {
		appendResponsesInput(&builder, input)
	}
	if contents, ok := root["contents"]; ok {
		appendRoleMessages(&builder, contents, true)
	}
	if prompt, ok := root["prompt"]; ok {
		appendPromptValue(&builder, prompt, 0)
	}
	if query, ok := root["query"]; ok {
		appendPromptValue(&builder, query, 0)
	}
	return builder.String()
}

func appendResponsesInput(builder *strings.Builder, input any) {
	switch input := input.(type) {
	case string:
		appendPromptValue(builder, input, 0)
	case []any:
		for _, item := range input {
			switch item := item.(type) {
			case string:
				appendPromptValue(builder, item, 0)
			case map[string]any:
				if isUserRole(stringValue(item["role"]), false) {
					appendPromptValue(builder, item["content"], 0)
				}
			}
		}
	case map[string]any:
		if isUserRole(stringValue(input["role"]), false) {
			appendPromptValue(builder, input["content"], 0)
		}
	}
}

func appendRoleMessages(builder *strings.Builder, messages any, allowMissingUserRole bool) {
	items, ok := messages.([]any)
	if !ok {
		return
	}
	for _, item := range items {
		message, ok := item.(map[string]any)
		if !ok {
			continue
		}
		role := strings.ToLower(strings.TrimSpace(stringValue(message["role"])))
		if !isUserRole(role, allowMissingUserRole) {
			continue
		}
		if content, ok := message["content"]; ok {
			appendPromptValue(builder, content, 0)
		}
		if parts, ok := message["parts"]; ok {
			appendPromptValue(builder, parts, 0)
		}
	}
}

func isUserRole(role string, allowMissing bool) bool {
	role = strings.ToLower(strings.TrimSpace(role))
	return role == "user" || role == "human" || (allowMissing && role == "")
}

func appendPromptValue(builder *strings.Builder, value any, depth int) {
	if builder.Len() >= 2<<20 || depth > 16 {
		return
	}
	switch value := value.(type) {
	case string:
		remaining := (2 << 20) - builder.Len()
		if len(value) > remaining {
			value = value[:remaining]
		}
		builder.WriteString(value)
		builder.WriteByte('\n')
	case []any:
		for _, item := range value {
			appendPromptValue(builder, item, depth+1)
		}
	case map[string]any:
		contentType := strings.ToLower(strings.TrimSpace(stringValue(value["type"])))
		if contentType != "" {
			switch contentType {
			case "text", "input_text":
				appendPromptValue(builder, value["text"], depth+1)
			case "message":
				if isUserRole(stringValue(value["role"]), false) {
					appendPromptValue(builder, value["content"], depth+1)
				}
			}
			return
		}
		for _, key := range []string{"text", "content", "parts"} {
			if item, ok := value[key]; ok {
				appendPromptValue(builder, item, depth+1)
			}
		}
	}
}

func stringValue(value any) string {
	text, _ := value.(string)
	return text
}

func isExplicitSecurityAnalysis(text string) bool {
	spans := explicitQuotePattern.FindAllStringIndex(text, -1)
	if len(spans) == 0 {
		return false
	}

	var outside strings.Builder
	last := 0
	quotedAttack := false
	for _, span := range spans {
		outside.WriteString(text[last:span[0]])
		outside.WriteByte(' ')
		if span[1]-span[0] <= 8<<10 {
			if blocked, _ := containsJailbreakSignals(text[span[0]:span[1]]); blocked {
				quotedAttack = true
			}
		} else {
			outside.WriteString(text[span[0]:span[1]])
		}
		last = span[1]
	}
	outside.WriteString(text[last:])
	outsideText := outside.String()

	if !quotedAttack ||
		!analysisPattern.MatchString(outsideText) ||
		!noExecutePattern.MatchString(outsideText) ||
		!quotedSamplePattern.MatchString(outsideText) {
		return false
	}
	outsideSignals := analysisLabelPattern.ReplaceAllString(outsideText, " ")
	blockedOutside, _ := containsJailbreakSignals(outsideSignals)
	return !blockedOutside
}

func containsJailbreakSignals(text string) (bool, int) {
	signals := 0
	for _, pattern := range strongJailbreakPatterns {
		if pattern.MatchString(text) {
			signals++
		}
	}
	compact := compactPromptSignals(text)
	defensiveDiscussion := defensiveBypassPattern.MatchString(text)
	if activeBypassPattern.MatchString(text) && !defensiveDiscussion {
		signals++
	}
	if activationPattern.MatchString(text) {
		signals++
	}
	compactBypass := containsAny(compact, "bypass", "disable", "remove", "turnoff", "绕过", "解除") &&
		containsAny(compact, "safety", "guardrail", "policyrestriction", "安全", "限制", "护栏", "策略") &&
		!defensiveDiscussion
	return signals > 0 ||
		hasCompactJailbreakSignals(compact) ||
		compactBypass ||
		hasCompactActivationSignals(compact) ||
		(overridePattern.MatchString(text) && (secretPattern.MatchString(text) || rolePattern.MatchString(text))), signals
}

func normalizePrompt(raw string) string {
	var builder strings.Builder
	builder.Grow(len(raw))
	for _, r := range strings.ToLower(norm.NFKC.String(raw)) {
		switch {
		case unicode.Is(unicode.Cf, r):
			continue
		case unicode.IsSpace(r):
			builder.WriteByte(' ')
		default:
			builder.WriteRune(r)
		}
	}
	return strings.Join(strings.Fields(builder.String()), " ")
}

const maxPromptUnicodeDecodeLayers = 3

// Normalize an inspection copy only. Bound repeated escape decoding and reject
// text still carrying decodable escapes instead of silently skipping inspection.
func decodePromptUnicodeEscapes(text string) (string, bool) {
	for layer := 0; layer < maxPromptUnicodeDecodeLayers; layer++ {
		if !strings.Contains(text, `\u`) {
			return text, false
		}
		var builder strings.Builder
		builder.Grow(len(text))
		changed := false
		for index := 0; index < len(text); {
			value, width := promptUnicodeEscapeAt(text, index)
			if width == 0 {
				builder.WriteByte(text[index])
				index++
				continue
			}
			builder.WriteRune(value)
			index += width
			changed = true
		}
		if !changed {
			return text, false
		}
		text = builder.String()
	}
	for index := 0; index < len(text); index++ {
		if _, width := promptUnicodeEscapeAt(text, index); width > 0 {
			return text, true
		}
	}
	return text, false
}

func promptUnicodeEscapeAt(text string, index int) (rune, int) {
	if index+6 > len(text) || text[index] != '\\' || text[index+1] != 'u' {
		return 0, 0
	}
	value, err := strconv.ParseUint(text[index+2:index+6], 16, 16)
	if err != nil {
		return 0, 0
	}
	first := rune(value)
	if !utf16.IsSurrogate(first) {
		return first, 6
	}
	if first < 0xD800 || first > 0xDBFF || index+12 > len(text) ||
		text[index+6:index+8] != `\u` {
		return 0, 0
	}
	low, err := strconv.ParseUint(text[index+8:index+12], 16, 16)
	if err != nil || low < 0xDC00 || low > 0xDFFF {
		return 0, 0
	}
	return utf16.DecodeRune(first, rune(low)), 12
}

func compactPromptSignals(text string) string {
	var builder strings.Builder
	builder.Grow(len(text))
	for _, r := range text {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			builder.WriteRune(r)
		}
	}
	return builder.String()
}

func hasCompactJailbreakSignals(compact string) bool {
	override := containsAny(compact, "ignore", "disregard", "forget", "override", "followonly", "忽略", "无视", "覆盖")
	instructionTarget := containsAny(compact, "previousinstruction", "priorinstruction", "systeminstruction", "developerinstruction", "safetypolicy", "policyrule", "instructions", "rules", "之前指令", "以上指令", "先前指令", "安全策略")
	disclosure := containsAny(compact, "reveal", "show", "print", "output", "dump", "repeat", "输出", "显示", "泄露")
	secret := containsAny(compact, "systemprompt", "developermessage", "hiddeninstructions", "secretprompt", "系统提示词", "开发者消息", "隐藏指令")
	role := containsAny(compact, "unrestricted", "nosafety", "withoutrestrictions", "youarenow", "解除限制", "没有安全限制")
	negatedDisclosure := containsAny(compact, "withoutrevealing", "donotreveal", "neverreveal", "mustnotreveal", "不要泄露", "不得泄露", "不泄露")
	return (override && (instructionTarget || secret || role)) ||
		(disclosure && secret && !negatedDisclosure)
}

func rawCompactMayContainJailbreak(compact string) bool {
	bypass := containsAny(compact, "bypass", "disable", "remove", "turnoff", "绕过", "解除")
	safety := containsAny(compact, "safety", "guardrail", "policyrestriction", "安全", "限制", "护栏", "策略")
	return hasCompactJailbreakSignals(compact) ||
		(bypass && safety) ||
		hasCompactActivationSignals(compact) ||
		containsAny(compact, "jailbreak", "越狱")
}

func hasCompactActivationSignals(compact string) bool {
	return containsAny(
		compact,
		"activatejailbreakmode",
		"enablejailbreakmode",
		"enterjailbreakmode",
		"switchtojailbreakmode",
		"activatedanmode",
		"enabledanmode",
		"enterdanmode",
		"switchtodanmode",
		"actasdan",
		"becomedan",
		"youarenowdan",
		"activateunrestrictedmode",
		"enableunrestrictedmode",
		"enterunrestrictedmode",
		"switchtounrestrictedmode",
		"actasunrestrictedassistant",
		"becomeunrestrictedassistant",
		"youarenowunrestrictedassistant",
		"activateuncensoredassistant",
		"enableuncensoredassistant",
		"actasuncensoredassistant",
		"启用越狱",
		"开启越狱",
		"进入越狱",
		"切换到越狱",
		"扮演dan",
		"变成dan",
		"启用无限制模式",
		"开启无限制模式",
		"启用无审查模式",
		"开启无审查模式",
	)
}

func containsAny(text string, candidates ...string) bool {
	for _, candidate := range candidates {
		if strings.Contains(text, candidate) {
			return true
		}
	}
	return false
}

func normalizeHeaderValue(values []string) string {
	var normalized []string
	for _, value := range values {
		value = normalize(value)
		if value != "" {
			normalized = append(normalized, value)
		}
	}
	return strings.Join(normalized, ",")
}

func FingerprintFromHeaders(requestHeaders http.Header) string {
	var builder bytes.Buffer
	for _, header := range []string{
		"user-agent",
		"accept",
		"accept-language",
		"content-type",
		"sec-ch-ua",
		"sec-ch-ua-platform",
		"x-tls-fingerprint",
		"x-ja3",
		"x-ja4",
		"x-utls-fingerprint",
	} {
		builder.WriteString(header)
		builder.WriteByte('=')
		builder.WriteString(normalizeHeaderValue(requestHeaders.Values(header)))
		builder.WriteByte(0)
	}
	return digest(builder.String())
}
