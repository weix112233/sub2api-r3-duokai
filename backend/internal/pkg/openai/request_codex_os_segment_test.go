package openai

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// Codex UA 形态：{originator}/{version} ({os_type} {os_version}; {arch}) {terminal}
// （codex-rs login/src/auth/default_client.rs get_codex_user_agent）。
// OS 段是首个括号组里 `;` 之前的部分，供 machine 模式推导 sandbox 标签。
func TestCodexUserAgentOSSegment(t *testing.T) {
	cases := []struct {
		name string
		ua   string
		want string
	}{
		{name: "macOS", ua: "codex-tui/0.146.0 (Mac OS 26.0.1; arm64) xterm-256color", want: "Mac OS 26.0.1"},
		{name: "Ubuntu", ua: "codex_cli_rs/0.146.0 (Ubuntu 22.4.0; x86_64) xterm-256color", want: "Ubuntu 22.4.0"},
		{name: "Windows", ua: "codex_cli_rs/0.146.0 (Windows 10.0.26100; x86_64) WindowsTerminal", want: "Windows 10.0.26100"},
		{name: "首尾空白与尾部客户端组不干扰", ua: "  cccc/0.142.0 (Ubuntu 22.4.0; x86_64) screen (codex-tui; 0.142.0)  ", want: "Ubuntu 22.4.0"},
		{name: "无括号 UA", ua: "codex_cli_rs/0.1.0", want: ""},
		{name: "空串", ua: "", want: ""},
		{name: "括号未闭合", ua: "codex_cli_rs/0.146.0 (Ubuntu 22.4.0; x86_64", want: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, CodexUserAgentOSSegment(tc.ua))
		})
	}
}
