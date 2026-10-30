package handler

import (
	"context"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/group-project/authentication/internal/domain"
	"github.com/rs/zerolog"
)

type MachineIssuer interface {
	Issue(context.Context, string, string) (string, error)
	TTL() time.Duration
}
type MachineHandler struct {
	issuer MachineIssuer
	logger zerolog.Logger
	slots  chan struct{}
	mu     sync.Mutex
	tokens float64
	last   time.Time
}

func NewMachineHandler(issuer MachineIssuer, logger zerolog.Logger) *MachineHandler {
	return &MachineHandler{issuer: issuer, logger: logger, slots: make(chan struct{}, 8), tokens: 20, last: time.Now()}
}
func (h *MachineHandler) admit() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	now := time.Now()
	h.tokens = min(20, h.tokens+now.Sub(h.last).Seconds()*10)
	h.last = now
	if h.tokens < 1 {
		return false
	}
	h.tokens--
	return true
}
func (h *MachineHandler) Token(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	c.Header("Pragma", "no-cache")
	requestID := uuid.NewString()
	c.Header("X-Request-ID", requestID)
	fail := func(status int, code, reason string, err error) {
		event := h.logger.Warn().Str("component", "machine_auth").Str("operation", "issue").Str("reason", reason).Str("request_id", requestID)
		var failure *domain.MachineFailure
		if errors.As(err, &failure) && failure.SQLState != "" {
			event = event.Str("sqlstate", failure.SQLState)
		}
		event.Msg("machine token request rejected")
		if status == 401 {
			c.Header("WWW-Authenticate", `Basic realm="service-token"`)
		}
		c.AbortWithStatusJSON(status, gin.H{"error": code})
	}
	if !h.admit() {
		c.Header("Retry-After", "1")
		fail(429, "temporarily_unavailable", "rate_limited", nil)
		return
	}
	select {
	case h.slots <- struct{}{}:
		defer func() { <-h.slots }()
	default:
		fail(429, "temporarily_unavailable", "capacity_limited", nil)
		return
	}
	if c.Request.TLS == nil {
		fail(400, "invalid_request", "tls_required", nil)
		return
	}
	if c.Request.URL.RawQuery != "" || len(c.Request.Header.Values("Authorization")) > 1 || len(c.Request.Header.Values("Content-Type")) != 1 {
		fail(400, "invalid_request", "ambiguous_request", nil)
		return
	}
	media, params, err := mime.ParseMediaType(c.GetHeader("Content-Type"))
	if err != nil || media != "application/x-www-form-urlencoded" || len(params) > 0 {
		fail(400, "invalid_request", "content_type", nil)
		return
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 4096)
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		fail(400, "invalid_request", "body_limit", nil)
		return
	}
	fields, err := url.ParseQuery(string(body))
	if err != nil || len(fields) != 3 {
		fail(400, "invalid_request", "form_fields", nil)
		return
	}
	for _, key := range []string{"grant_type", "audience", "scope"} {
		if len(fields[key]) != 1 {
			fail(400, "invalid_request", "form_fields", nil)
			return
		}
	}
	if fields.Get("grant_type") != "client_credentials" {
		fail(400, "unsupported_grant_type", "grant_type", nil)
		return
	}
	authority, authorityError := domain.ParseMachineAuthority(fields.Get("audience"), fields.Get("scope"))
	if authorityError != nil {
		fail(400, "invalid_request", "authority", nil)
		return
	}
	client, password, ok := c.Request.BasicAuth()
	if !ok || len(client) > 36 || len(password) > 80 {
		fail(401, "invalid_client", "client_authentication", nil)
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()
	var token string
	if authority.Audience == domain.MachineAudience {
		token, err = h.issuer.Issue(ctx, client, password)
	} else if scoped, ok := h.issuer.(interface {
		IssueFor(context.Context, string, string, domain.MachineAuthority) (string, error)
	}); ok {
		token, err = scoped.IssueFor(ctx, client, password, authority)
	} else {
		err = domain.ErrMachineUnavailable
	}
	if err != nil {
		if errors.Is(err, domain.ErrMachineClient) {
			fail(401, "invalid_client", "client_authentication", nil)
		} else {
			fail(503, "temporarily_unavailable", "issuance_unavailable", err)
		}
		return
	}
	c.JSON(200, gin.H{"access_token": token, "token_type": "Bearer", "expires_in": int64(h.issuer.TTL() / time.Second)})
}
