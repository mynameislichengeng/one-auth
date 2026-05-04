package handler

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/licheng/oneauth/server/internal/middleware"
	"github.com/licheng/oneauth/server/internal/service"
	"github.com/licheng/oneauth/server/internal/utils"
)

type AuthHandler struct {
	svc *service.AuthService
}

func NewAuthHandler(svc *service.AuthService) *AuthHandler {
	return &AuthHandler{svc: svc}
}

// POST /api/auth/register
func (h *AuthHandler) Register(c *gin.Context) {
	var req struct {
		Email    string `json:"email"    binding:"required"`
		Password string `json:"password" binding:"required"`
		Nickname string `json:"nickname"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "invalid request body")
		return
	}

	pair, err := h.svc.Register(c.Request.Context(), service.RegisterRequest{
		Email:     req.Email,
		Password:  req.Password,
		Nickname:  req.Nickname,
		IP:        c.ClientIP(),
		UserAgent: c.Request.UserAgent(),
	})
	if err != nil {
		switch {
		case errors.Is(err, service.ErrIdentifierTaken):
			utils.Conflict(c, "email already registered")
		case errors.Is(err, service.ErrPasswordTooShort):
			utils.BadRequest(c, "password too short")
		case errors.Is(err, service.ErrInvalidEmail):
			utils.BadRequest(c, "invalid email")
		default:
			utils.Internal(c, err)
		}
		return
	}
	c.JSON(http.StatusCreated, pair)
}

// POST /api/auth/login
func (h *AuthHandler) Login(c *gin.Context) {
	var req struct {
		Email    string `json:"email"    binding:"required"`
		Password string `json:"password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "invalid request body")
		return
	}

	pair, err := h.svc.Login(c.Request.Context(), service.LoginRequest{
		Email:     req.Email,
		Password:  req.Password,
		IP:        c.ClientIP(),
		UserAgent: c.Request.UserAgent(),
	})
	if err != nil {
		switch {
		case errors.Is(err, service.ErrInvalidCredential):
			utils.Unauthorized(c, "invalid credentials")
		case errors.Is(err, service.ErrUserNotActive):
			utils.Forbidden(c, "user not active")
		case errors.Is(err, service.ErrTooManyAttempts):
			utils.TooManyRequests(c, "too many failed login attempts; please try again later")
		default:
			utils.Internal(c, err)
		}
		return
	}
	c.JSON(http.StatusOK, pair)
}

// POST /api/auth/refresh
func (h *AuthHandler) Refresh(c *gin.Context) {
	var req struct {
		RefreshToken string `json:"refresh_token" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "invalid request body")
		return
	}

	pair, err := h.svc.Refresh(c.Request.Context(), req.RefreshToken,
		c.ClientIP(), c.Request.UserAgent())
	if err != nil {
		switch {
		case errors.Is(err, service.ErrTokenInvalid),
			errors.Is(err, service.ErrTokenExpired):
			utils.Unauthorized(c, "invalid refresh token")
		case errors.Is(err, service.ErrTokenReplay):
			utils.Unauthorized(c, "refresh token replay detected; all sessions in family revoked")
		case errors.Is(err, service.ErrUserNotActive):
			utils.Forbidden(c, "user not active")
		default:
			utils.Internal(c, err)
		}
		return
	}
	c.JSON(http.StatusOK, pair)
}

// POST /api/auth/logout（需要 access_token）
func (h *AuthHandler) Logout(c *gin.Context) {
	claims := middleware.ClaimsFrom(c)
	if claims == nil {
		utils.Unauthorized(c, "missing claims")
		return
	}
	if err := h.svc.Logout(c.Request.Context(), claims); err != nil {
		utils.Internal(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "logged_out"})
}

// GET /api/me（需要 access_token）
func (h *AuthHandler) Me(c *gin.Context) {
	claims := middleware.ClaimsFrom(c)
	if claims == nil {
		utils.Unauthorized(c, "missing claims")
		return
	}
	user, err := h.svc.GetUserByPublicID(c.Request.Context(), claims.Subject)
	if err != nil {
		utils.Internal(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"user_id":     user.PublicID,    // ULID（不是 BIGINT）—— 边界规则 D-A2
		"nickname":    user.Nickname,
		"avatar_url":  user.AvatarURL,
		"status":      user.Status,
		"tenant_id":   claims.TenantID,
		"client_id":   claims.ClientID,
		"permissions": claims.Permissions,
	})
}
