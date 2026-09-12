package admin

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"

	"github.com/Wei-Shaw/sub2api/internal/pkg/response"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
)

type OpenAIOperationsHandler struct {
	service *service.OpenAIOperationsService
}

func NewOpenAIOperationsHandler(s *service.OpenAIOperationsService) *OpenAIOperationsHandler {
	return &OpenAIOperationsHandler{service: s}
}

func (h *OpenAIOperationsHandler) GetSettings(c *gin.Context) {
	value, err := h.service.GetSettings(c.Request.Context())
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, value)
}

func (h *OpenAIOperationsHandler) SetSettings(c *gin.Context) {
	defaults := service.DefaultOpenAIOperationsSettings()
	value := &defaults
	decoder := json.NewDecoder(http.MaxBytesReader(c.Writer, c.Request.Body, 64<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil || value == nil {
		response.BadRequest(c, "Invalid operations settings")
		return
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		response.BadRequest(c, "Expected one settings object")
		return
	}
	if err := h.service.SetSettings(c.Request.Context(), *value); err != nil {
		response.BadRequest(c, err.Error())
		return
	}
	response.Success(c, value)
}

func optionalOperationsID(c *gin.Context, name string) (int64, bool) {
	raw := c.Query(name)
	if raw == "" {
		return 0, true
	}
	id, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || id < 0 {
		response.BadRequest(c, "Invalid "+name)
		return 0, false
	}
	return id, true
}

func (h *OpenAIOperationsHandler) Reasoning(c *gin.Context) {
	id, ok := optionalOperationsID(c, "account_id")
	if !ok {
		return
	}
	result, err := h.service.Reasoning(c.Request.Context(), id)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, result)
}

func (h *OpenAIOperationsHandler) Pool(c *gin.Context) {
	id, ok := optionalOperationsID(c, "group_id")
	if !ok {
		return
	}
	result, err := h.service.Pool(c.Request.Context(), id)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, result)
}

func (h *OpenAIOperationsHandler) Events(c *gin.Context) {
	id, ok := optionalOperationsID(c, "account_id")
	if !ok {
		return
	}
	result, err := h.service.Events(c.Request.Context(), id)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, result)
}
