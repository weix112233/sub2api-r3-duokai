package antibypass

import (
	"bytes"
	"encoding/json"
	"net/http"
	"regexp"
	"sort"
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
	// Match a verb and its instruction/security object, not unrelated words
	// anywhere in a request. Compaction still catches separated-letter attacks.
	compactJailbreakPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?:ignore|disregard|forget|override)(?:(?:all|the|any|your|my|of|these|those)){0,5}(?:previous|prior|above|earlier|existing|system|developer|safety|security|hidden|policy|all)(?:(?:all|the|any|your|of|previous|prior|system|developer|safety|security|policy)){0,5}(?:instructions?|rules?|prompts?|polic(?:y|ies)|guardrails?)`),
		regexp.MustCompile(`(?:reveal|show|print|output|dump|repeat)(?:(?:the|your|all|full|entire|hidden|original|exact|verbatim)){0,5}(?:systemprompt|systeminstructions|developermessage|developerprompt|developerinstructions|hiddeninstructions|secretprompt)`),
		regexp.MustCompile(`(?:忽略|无视|覆盖)(?:(?:之前|先前|以上|所有|全部|此前|系统|开发者|安全|的)){0,8}(?:指令|指示|规则|安全策略|系统提示词|开发者消息)`),
		regexp.MustCompile(`(?:输出|显示|泄露|展示|打印)(?:(?:完整|全部|原始|隐藏|你的|的)){0,5}(?:系统提示词|系统指令|开发者消息|开发者指令|隐藏指令)`),
	}
	analysisPattern      = regexp.MustCompile(`\b(analy[sz]e|analysis|classify|classification|detect|review|explain)\b|分析|研判|分类|检测|审查|解释`)
	compactBypassPattern = regexp.MustCompile(
		`(?:bypass|disable|remove|turnoff)(?:(?:all|the|any|your|existing|of)){0,5}(?:safety|security|guardrails?|policy|restrictions?)|` +
			`(?:绕过|解除)(?:(?:全部|所有|这些|的)){0,5}(?:安全|限制|护栏|策略)`,
	)
	compactDefensivePrefixPattern = regexp.MustCompile(
		`(?:prevent|stop|block|avoid)(?:(?:clients?|users?|attackers?|attempts?|from|to)){0,4}$|` +
			`(?:detect|identify|mitigate|defendagainst|protectagainst)(?:attemptsto)?$|` +
			`(?:防止|阻止|拦截|检测|识别|缓解|防御)$`,
	)
	compactActivationPattern = regexp.MustCompile(
		`(?:activate|enable|enter|switchto)(?:jailbreak|dan|unrestricted)mode|` +
			`(?:actas|become|youarenow)(?:dan|(?:an?)?(?:unrestricted|uncensored)assistant)|` +
			`(?:activate|enable)(?:an?)?uncensoredassistant|` +
			`(?:启用|开启|进入|切换到|扮演|变成)(?:越狱|dan|无限制模式|无审查模式)`,
	)
	noExecutePattern = regexp.MustCompile(
		`\b(do not|don't|never|must not)\b.{0,40}\b(execute|follow|obey|comply|perform|act on)\b|` +
			`不要.{0,20}(执行|遵循|服从|照做)|不得.{0,20}(执行|遵循|服从|照做)|仅分析不执行`,
	)
	quotedSamplePattern           = regexp.MustCompile(`\b(quoted|quote|sample|example|payload|attack string|jailbreak prompt)\b|引用|样本|示例|攻击文本|越狱提示词`)
	explicitQuotePattern          = regexp.MustCompile("(?s)\"[^\"\\n]+\"|“[^”\\n]+”|```.+?```")
	analysisLabelPattern          = regexp.MustCompile(`\b(quoted\s+)?jailbreak\s+(sample|prompt)\b|越狱提示词(样本)?`)
	compactNegationPrefixPattern  = regexp.MustCompile(`(?:donot|dont|never|mustnot|shouldnot|shouldnt|without|不要|不得|切勿|不能|不应|禁止|不可)(?:ever|again|underanycircumstances|再|再次|擅自|绝对){0,2}$`)
	quotedDataTaskPattern         = regexp.MustCompile(`\btranslate\b|翻译|\b(?:add|write|create)\b[^\n.!?;]{0,160}\b(?:unit test|test case)\b[^\n.!?;]{0,120}\b(?:fixture|string|literal|sample)\b|(?:编写|添加|创建).{0,60}(?:单元测试|测试用例).{0,60}(?:字符串|样本|字面量)`)
	compactQuotedExecutionPattern = regexp.MustCompile(`(?:follow|obey|execute|apply|perform)(?:all|the|these|those|this|that|quoted|sample|provided|above|below|instructions|it)|(?:执行|遵循|照做)(?:引用|引文|样本|上述|其中|它)`)
)

// DetectJailbreak scans only bounded request bytes and never returns the
// original text. It intentionally blocks high-confidence combinations rather
// than treating every mention of "prompt" as malicious.
func DetectJailbreak(body []byte, maxBytes int) (bool, Detection) {
	return DetectJailbreakWithLimits(body, maxBytes, maxBytes)
}

// Media may occupy the wire budget without consuming the text inspection budget.
func DetectJailbreakWithLimits(body []byte, maxBytes, maxTextBytes int) (bool, Detection) {
	if maxBytes <= 0 || len(body) == 0 {
		return false, Detection{}
	}
	if len(body) > maxBytes {
		return true, Detection{Reason: ReasonBodyTooLarge}
	}
	if maxTextBytes <= 0 {
		return true, Detection{Reason: ReasonPromptInspectionLimit}
	}
	messages, complete := extractPromptTexts(body, maxTextBytes)
	if !complete {
		return true, Detection{Reason: ReasonPromptInspectionLimit}
	}
	for _, message := range messages {
		if !rawBodyMayContainJailbreak([]byte(message)) {
			continue
		}
		text, encodingLimit := decodePromptUnicodeEscapes(norm.NFKC.String(message))
		if encodingLimit {
			return true, Detection{Reason: ReasonPromptEncodingLimit, SignalCount: 1}
		}
		text = normalizePrompt(text)
		if text == "" || isExplicitSecurityAnalysis(text) {
			continue
		}
		if blocked, signals := containsJailbreakSignals(text); blocked {
			return true, Detection{Reason: ReasonPromptJailbreak, SignalCount: signals}
		}
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

type promptTexts struct {
	messages []string
	bytes    int
	limit    int
}

func extractPromptTexts(body []byte, maxTextBytes int) ([]string, bool) {
	var root map[string]any
	if json.Unmarshal(body, &root) != nil {
		if len(body) > maxTextBytes {
			return nil, false
		}
		return []string{string(body)}, true
	}
	return extractPromptFields(root, maxTextBytes)
}

func extractPromptFields(root map[string]any, maxTextBytes int) ([]string, bool) {
	texts := promptTexts{limit: maxTextBytes}
	if messages, ok := root["messages"]; ok {
		if !appendRoleMessages(&texts, messages, false) {
			return nil, false
		}
	}
	if input, ok := root["input"]; ok {
		if !appendResponsesInput(&texts, input) {
			return nil, false
		}
	}
	if contents, ok := root["contents"]; ok {
		if !appendRoleMessages(&texts, contents, true) {
			return nil, false
		}
	}
	for _, key := range []string{"prompt", "query", "instructions", "system", "system_instruction", "systemInstruction"} {
		if value, ok := root[key]; ok && !appendPromptText(&texts, value) {
			return nil, false
		}
	}
	for _, envelope := range []string{"response", "session"} {
		if content, ok := root[envelope].(map[string]any); ok {
			// Realtime control frames have explicit envelopes; never recurse arbitrary data.
			for _, key := range []string{"instructions", "input"} {
				if value, ok := content[key]; ok && !appendPromptText(&texts, value) {
					return nil, false
				}
			}
		}
	}
	return texts.messages, true
}

func appendPromptText(texts *promptTexts, content any) bool {
	var builder strings.Builder
	if !appendPromptValue(&builder, content, 0, texts.limit-texts.bytes) {
		return false
	}
	if builder.Len() > 0 {
		texts.messages = append(texts.messages, builder.String())
		texts.bytes += builder.Len()
	}
	return true
}

func appendResponsesInput(texts *promptTexts, input any) bool {
	switch input := input.(type) {
	case string:
		return appendPromptText(texts, input)
	case []any:
		for _, item := range input {
			switch item := item.(type) {
			case string:
				if !appendPromptText(texts, item) {
					return false
				}
			case map[string]any:
				if isInstructionRole(stringValue(item["role"]), false) {
					if !appendPromptText(texts, item["content"]) {
						return false
					}
				}
			}
		}
	case map[string]any:
		if isInstructionRole(stringValue(input["role"]), false) {
			return appendPromptText(texts, input["content"])
		}
	}
	return true
}

func appendRoleMessages(texts *promptTexts, messages any, allowMissingUserRole bool) bool {
	items, ok := messages.([]any)
	if !ok {
		return true
	}
	for _, item := range items {
		message, ok := item.(map[string]any)
		if !ok {
			continue
		}
		role := strings.ToLower(strings.TrimSpace(stringValue(message["role"])))
		if !isInstructionRole(role, allowMissingUserRole) {
			continue
		}
		// Content blocks of one message stay together; different messages cannot
		// grant each other an analysis exception or fabricate combined signals.
		if !appendPromptText(texts, []any{message["content"], message["parts"]}) {
			return false
		}
	}
	return true
}

func isInstructionRole(role string, allowMissing bool) bool {
	role = strings.ToLower(strings.TrimSpace(role))
	return role == "user" || role == "human" || role == "system" || role == "developer" || (allowMissing && role == "")
}

func appendPromptValue(builder *strings.Builder, value any, depth, maxBytes int) bool {
	if depth > 16 {
		return false
	}
	switch value := value.(type) {
	case string:
		if len(value)+1 > maxBytes-builder.Len() {
			return false
		}
		builder.WriteString(value)
		builder.WriteByte('\n')
	case []any:
		for _, item := range value {
			if !appendPromptValue(builder, item, depth+1, maxBytes) {
				return false
			}
		}
	case map[string]any:
		contentType := strings.ToLower(strings.TrimSpace(stringValue(value["type"])))
		if contentType != "" {
			switch contentType {
			case "text", "input_text":
				return appendPromptValue(builder, value["text"], depth+1, maxBytes)
			case "message":
				if isInstructionRole(stringValue(value["role"]), false) {
					return appendPromptValue(builder, value["content"], depth+1, maxBytes)
				}
			}
			return true
		}
		for _, key := range []string{"text", "content", "parts"} {
			if item, ok := value[key]; ok {
				if !appendPromptValue(builder, item, depth+1, maxBytes) {
					return false
				}
			}
		}
	}
	return true
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

	analysisTask := analysisPattern.MatchString(outsideText) &&
		noExecutePattern.MatchString(outsideText) && quotedSamplePattern.MatchString(outsideText)
	compactOutside, boundaries := compactPromptSignals(outsideText)
	dataTask := quotedDataTaskPattern.MatchString(outsideText) &&
		!hasActivePromptMatch(compactOutside, boundaries, compactQuotedExecutionPattern, false)
	if !quotedAttack || (!analysisTask && !dataTask) {
		return false
	}
	outsideSignals := analysisLabelPattern.ReplaceAllString(outsideText, " ")
	blockedOutside, _ := containsJailbreakSignals(outsideSignals)
	return !blockedOutside
}

func containsJailbreakSignals(text string) (bool, int) {
	compact, boundaries := compactPromptSignals(text)
	signals := 0
	for _, pattern := range compactJailbreakPatterns {
		if hasActivePromptMatch(compact, boundaries, pattern, false) {
			signals++
		}
	}
	if hasActivePromptMatch(compact, boundaries, compactBypassPattern, true) {
		signals++
	}
	if hasActivePromptMatch(compact, boundaries, compactActivationPattern, false) {
		signals++
	}
	return signals > 0, signals
}

func hasActivePromptMatch(compact string, boundaries []int, pattern *regexp.Regexp, allowDefensive bool) bool {
	for offset := 0; offset < len(compact); {
		match := pattern.FindStringIndex(compact[offset:])
		if match == nil {
			break
		}
		start := offset + match[0]
		prefixStart := max(0, start-128)
		boundary := sort.Search(len(boundaries), func(i int) bool { return boundaries[i] > start })
		if boundary > 0 {
			prefixStart = max(prefixStart, boundaries[boundary-1])
		}
		prefix := compact[prefixStart:start]
		if !compactNegationPrefixPattern.MatchString(prefix) &&
			!(allowDefensive && compactDefensivePrefixPattern.MatchString(prefix)) {
			return true
		}
		// A negated action does not exempt subsequent actions in this message.
		offset += match[1]
	}
	return false
}

func normalizePrompt(raw string) string {
	var builder strings.Builder
	builder.Grow(len(raw))
	space := false
	for _, r := range strings.ToLower(norm.NFKC.String(raw)) {
		switch {
		case unicode.Is(unicode.Cf, r):
			continue
		case r == '\n' || r == '\r':
			builder.WriteByte('\n')
			space = true
		case unicode.IsSpace(r):
			if !space {
				builder.WriteByte(' ')
			}
			space = true
		default:
			builder.WriteRune(r)
			space = false
		}
	}
	return strings.TrimSpace(builder.String())
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

func compactPromptSignals(text string) (string, []int) {
	var builder strings.Builder
	builder.Grow(len(text))
	var boundaries []int
	for index, r := range text {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			builder.WriteRune(r)
		} else if strings.ContainsRune("\n\r。！？；!?;,:，：", r) ||
			(r == '.' && (index+1 == len(text) || text[index+1] == ' ' || text[index+1] == '\n')) {
			// Keep clause boundaries for negation without preventing detection of
			// a positive attack whose letters/words were split by punctuation.
			if len(boundaries) == 0 || boundaries[len(boundaries)-1] != builder.Len() {
				boundaries = append(boundaries, builder.Len())
			}
		}
	}
	return builder.String(), boundaries
}

func rawCompactMayContainJailbreak(compact string) bool {
	// Over-approximate the detector even when a verb is split across content
	// blocks. This fast path grants no exemption and makes no security decision.
	return containsAny(
		compact,
		"ignore", "disregard", "forget", "override", "reveal", "show",
		"print", "output", "dump", "repeat", "instructions", "rules",
		"prompt", "message", "safety", "security", "guardrail", "policy",
		"restriction", "jailbreak", "dan", "unrestricted", "uncensored",
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
