package admin

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/Wei-Shaw/sub2api/internal/model"
	"github.com/Wei-Shaw/sub2api/internal/pkg/response"
	"github.com/Wei-Shaw/sub2api/internal/pkg/tlsfingerprint"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
)

// TLSFingerprintProfileHandler 处理 TLS 指纹模板的 HTTP 请求
type TLSFingerprintProfileHandler struct {
	service *service.TLSFingerprintProfileService
}

// NewTLSFingerprintProfileHandler 创建 TLS 指纹模板处理器
func NewTLSFingerprintProfileHandler(service *service.TLSFingerprintProfileService) *TLSFingerprintProfileHandler {
	return &TLSFingerprintProfileHandler{service: service}
}

// CreateTLSFingerprintProfileRequest 创建模板请求
type CreateTLSFingerprintProfileRequest struct {
	Name                string          `json:"name" binding:"required"`
	Description         *string         `json:"description"`
	EnableGREASE        *bool           `json:"enable_grease"`
	ShuffleExtensions   *bool           `json:"shuffle_extensions"`
	HTTP2               json.RawMessage `json:"http2"`
	CipherSuites        []uint16        `json:"cipher_suites"`
	Curves              []uint16        `json:"curves"`
	PointFormats        []uint16        `json:"point_formats"`
	SignatureAlgorithms []uint16        `json:"signature_algorithms"`
	ALPNProtocols       []string        `json:"alpn_protocols"`
	SupportedVersions   []uint16        `json:"supported_versions"`
	KeyShareGroups      []uint16        `json:"key_share_groups"`
	PSKModes            []uint16        `json:"psk_modes"`
	Extensions          []uint16        `json:"extensions"`
}

// UpdateTLSFingerprintProfileRequest 更新模板请求（部分更新）
type UpdateTLSFingerprintProfileRequest struct {
	Name                *string         `json:"name"`
	Description         *string         `json:"description"`
	EnableGREASE        *bool           `json:"enable_grease"`
	ShuffleExtensions   *bool           `json:"shuffle_extensions"`
	HTTP2               json.RawMessage `json:"http2"`
	CipherSuites        []uint16        `json:"cipher_suites"`
	Curves              []uint16        `json:"curves"`
	PointFormats        []uint16        `json:"point_formats"`
	SignatureAlgorithms []uint16        `json:"signature_algorithms"`
	ALPNProtocols       json.RawMessage `json:"alpn_protocols"`
	SupportedVersions   []uint16        `json:"supported_versions"`
	KeyShareGroups      []uint16        `json:"key_share_groups"`
	PSKModes            []uint16        `json:"psk_modes"`
	Extensions          []uint16        `json:"extensions"`
}

// List 获取所有模板
// GET /api/v1/admin/tls-fingerprint-profiles
func (h *TLSFingerprintProfileHandler) List(c *gin.Context) {
	profiles, err := h.service.List(c.Request.Context())
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, profiles)
}

// GetByID 根据 ID 获取模板
// GET /api/v1/admin/tls-fingerprint-profiles/:id
func (h *TLSFingerprintProfileHandler) GetByID(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		response.BadRequest(c, "Invalid profile ID")
		return
	}

	profile, err := h.service.GetByID(c.Request.Context(), id)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	if profile == nil {
		response.NotFound(c, "Profile not found")
		return
	}

	response.Success(c, profile)
}

// Create 创建模板
// POST /api/v1/admin/tls-fingerprint-profiles
func (h *TLSFingerprintProfileHandler) Create(c *gin.Context) {
	var req CreateTLSFingerprintProfileRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "Invalid request: "+err.Error())
		return
	}

	profile := &model.TLSFingerprintProfile{
		Name:                req.Name,
		Description:         req.Description,
		CipherSuites:        req.CipherSuites,
		Curves:              req.Curves,
		PointFormats:        req.PointFormats,
		SignatureAlgorithms: req.SignatureAlgorithms,
		ALPNProtocols:       req.ALPNProtocols,
		SupportedVersions:   req.SupportedVersions,
		KeyShareGroups:      req.KeyShareGroups,
		PSKModes:            req.PSKModes,
		Extensions:          req.Extensions,
	}

	if req.EnableGREASE != nil {
		profile.EnableGREASE = *req.EnableGREASE
	}
	if req.ShuffleExtensions != nil {
		profile.ShuffleExtensions = *req.ShuffleExtensions
	}
	if req.HTTP2 != nil {
		decoder := json.NewDecoder(bytes.NewReader(req.HTTP2))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&profile.HTTP2); err != nil {
			response.BadRequest(c, "Invalid http2 configuration: "+err.Error())
			return
		}
	}

	created, err := h.service.Create(c.Request.Context(), profile)
	if err != nil {
		if _, ok := err.(*model.ValidationError); ok {
			response.BadRequest(c, err.Error())
			return
		}
		response.ErrorFrom(c, err)
		return
	}

	response.Success(c, created)
}

// Update 更新模板（支持部分更新）
// PUT /api/v1/admin/tls-fingerprint-profiles/:id
func (h *TLSFingerprintProfileHandler) Update(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		response.BadRequest(c, "Invalid profile ID")
		return
	}

	var req UpdateTLSFingerprintProfileRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "Invalid request: "+err.Error())
		return
	}

	existing, err := h.service.GetByID(c.Request.Context(), id)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	if existing == nil {
		response.NotFound(c, "Profile not found")
		return
	}

	// 部分更新
	profile := &model.TLSFingerprintProfile{
		ID:                  id,
		Name:                existing.Name,
		Description:         existing.Description,
		EnableGREASE:        existing.EnableGREASE,
		ShuffleExtensions:   existing.ShuffleExtensions,
		HTTP2:               existing.HTTP2,
		CipherSuites:        existing.CipherSuites,
		Curves:              existing.Curves,
		PointFormats:        existing.PointFormats,
		SignatureAlgorithms: existing.SignatureAlgorithms,
		ALPNProtocols:       existing.ALPNProtocols,
		SupportedVersions:   existing.SupportedVersions,
		KeyShareGroups:      existing.KeyShareGroups,
		PSKModes:            existing.PSKModes,
		Extensions:          existing.Extensions,
	}

	if req.Name != nil {
		profile.Name = *req.Name
	}
	if req.Description != nil {
		profile.Description = req.Description
	}
	if req.EnableGREASE != nil {
		profile.EnableGREASE = *req.EnableGREASE
	}
	if req.ShuffleExtensions != nil {
		profile.ShuffleExtensions = *req.ShuffleExtensions
	}
	if req.HTTP2 != nil {
		var config *tlsfingerprint.HTTP2Config
		decoder := json.NewDecoder(bytes.NewReader(req.HTTP2))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&config); err != nil {
			response.BadRequest(c, "Invalid http2 configuration: "+err.Error())
			return
		}
		profile.HTTP2 = config
	}
	if req.CipherSuites != nil {
		profile.CipherSuites = req.CipherSuites
	}
	if req.Curves != nil {
		profile.Curves = req.Curves
	}
	if req.PointFormats != nil {
		profile.PointFormats = req.PointFormats
	}
	if req.SignatureAlgorithms != nil {
		profile.SignatureAlgorithms = req.SignatureAlgorithms
	}
	if req.ALPNProtocols != nil {
		var protocols []string
		if err := json.Unmarshal(req.ALPNProtocols, &protocols); err != nil {
			response.BadRequest(c, "Invalid alpn_protocols: "+err.Error())
			return
		}
		profile.ALPNProtocols = protocols
	}
	if req.SupportedVersions != nil {
		profile.SupportedVersions = req.SupportedVersions
	}
	if req.KeyShareGroups != nil {
		profile.KeyShareGroups = req.KeyShareGroups
	}
	if req.PSKModes != nil {
		profile.PSKModes = req.PSKModes
	}
	if req.Extensions != nil {
		profile.Extensions = req.Extensions
	}

	updated, err := h.service.Update(c.Request.Context(), profile)
	if err != nil {
		if _, ok := err.(*model.ValidationError); ok {
			response.BadRequest(c, err.Error())
			return
		}
		response.ErrorFrom(c, err)
		return
	}

	response.Success(c, updated)
}

// Delete 删除模板
// DELETE /api/v1/admin/tls-fingerprint-profiles/:id
func (h *TLSFingerprintProfileHandler) Delete(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		response.BadRequest(c, "Invalid profile ID")
		return
	}

	if err := h.service.Delete(c.Request.Context(), id); err != nil {
		if _, ok := err.(*model.ValidationError); ok {
			response.BadRequest(c, err.Error())
			return
		}
		response.ErrorFrom(c, err)
		return
	}

	response.Success(c, gin.H{"message": "Profile deleted successfully"})
}

func (h *TLSFingerprintProfileHandler) ParseYAML(c *gin.Context) {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 2*tlsfingerprint.MaxProfileYAMLBytes)
	var req struct {
		YAML string `json:"yaml" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "Invalid YAML request")
		return
	}
	doc, err := tlsfingerprint.ParseProfileYAML([]byte(req.YAML))
	if err != nil {
		response.BadRequest(c, err.Error())
		return
	}
	response.Success(c, doc)
}

func (h *TLSFingerprintProfileHandler) GetDefaults(c *gin.Context) {
	defaults, err := h.service.GetDefaults(c.Request.Context())
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, defaults)
}

func (h *TLSFingerprintProfileHandler) SetDefaults(c *gin.Context) {
	var req struct {
		ID *int64 `json:"openai_oauth_default_tls_profile_id" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "A nonnegative profile ID is required")
		return
	}
	defaults := service.TLSProfileDefaults{OpenAIOAuthDefaultTLSProfileID: *req.ID}
	if err := h.service.SetDefaults(c.Request.Context(), defaults); err != nil {
		if _, ok := err.(*model.ValidationError); ok {
			response.BadRequest(c, err.Error())
			return
		}
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, defaults)
}
