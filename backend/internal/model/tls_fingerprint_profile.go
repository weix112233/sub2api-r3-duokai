// Package model 定义服务层使用的数据模型。
package model

import (
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/tlsfingerprint"
)

// TLSFingerprintProfile TLS 指纹配置模板
// 包含完整的 ClientHello 参数，用于模拟特定客户端的 TLS 握手特征
type TLSFingerprintProfile struct {
	ID                  int64                       `json:"id"`
	Name                string                      `json:"name"`
	Description         *string                     `json:"description"`
	EnableGREASE        bool                        `json:"enable_grease"`
	ShuffleExtensions   bool                        `json:"shuffle_extensions"`
	HTTP2               *tlsfingerprint.HTTP2Config `json:"http2"`
	CipherSuites        []uint16                    `json:"cipher_suites"`
	Curves              []uint16                    `json:"curves"`
	PointFormats        []uint16                    `json:"point_formats"`
	SignatureAlgorithms []uint16                    `json:"signature_algorithms"`
	ALPNProtocols       []string                    `json:"alpn_protocols"`
	SupportedVersions   []uint16                    `json:"supported_versions"`
	KeyShareGroups      []uint16                    `json:"key_share_groups"`
	PSKModes            []uint16                    `json:"psk_modes"`
	Extensions          []uint16                    `json:"extensions"`
	CreatedAt           time.Time                   `json:"created_at"`
	UpdatedAt           time.Time                   `json:"updated_at"`
}

// Validate 验证模板配置的有效性
func (p *TLSFingerprintProfile) Validate() error {
	if p.Name == "" {
		return &ValidationError{Field: "name", Message: "name is required"}
	}
	if err := p.ToTLSProfile().Validate(); err != nil {
		return &ValidationError{Field: "profile", Message: err.Error()}
	}
	return nil
}

// ToTLSProfile 将领域模型转换为运行时使用的 tlsfingerprint.Profile
// ALPN nil inherits the default; an explicit empty slice disables ALPN.
func (p *TLSFingerprintProfile) ToTLSProfile() *tlsfingerprint.Profile {
	return (&tlsfingerprint.Profile{
		Name:                p.Name,
		EnableGREASE:        p.EnableGREASE,
		ShuffleExtensions:   p.ShuffleExtensions,
		HTTP2:               p.HTTP2,
		CipherSuites:        p.CipherSuites,
		Curves:              p.Curves,
		PointFormats:        p.PointFormats,
		SignatureAlgorithms: p.SignatureAlgorithms,
		ALPNProtocols:       p.ALPNProtocols,
		SupportedVersions:   p.SupportedVersions,
		KeyShareGroups:      p.KeyShareGroups,
		PSKModes:            p.PSKModes,
		Extensions:          p.Extensions,
	}).Clone()
}
