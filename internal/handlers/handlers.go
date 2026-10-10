package handlers

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/mohit-bhandari45/bastion/internal/auth"
	"github.com/mohit-bhandari45/bastion/internal/middleware"
)

type Handler struct {
	tokenSvc *auth.TokenService
}

func New(tokenSvc *auth.TokenService) *Handler {
	return &Handler{tokenSvc: tokenSvc}
}

// Health is a public health check
func (h *Handler) Health(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":  "ok",
		"service": "bastion-gateway",
		"time":    time.Now().UTC().Format(time.RFC3339),
	})
}

// Login issues access + refresh tokens (demo only – replace with real user store)
func (h *Handler) Login(c *gin.Context) {
	var req struct {
		Username string `json:"username" binding:"required"`
		Password string `json:"password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	// DEMO ONLY – hard-coded credentials. In real life use a proper user store + password hashing.
	if req.Username != "admin" || req.Password != "bastion-demo-2026" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	access, err := h.tokenSvc.GenerateAccessToken("user-001", "admin")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to issue token"})
		return
	}
	refresh, err := h.tokenSvc.GenerateRefreshToken("user-001")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to issue refresh token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"access_token":  access,
		"refresh_token": refresh,
		"token_type":    "Bearer",
		"expires_in":    900, // 15 minutes
	})
}

// Protected is an example protected endpoint
func (h *Handler) Protected(c *gin.Context) {
	uid, _ := c.Get(middleware.UserIDKey)
	role, _ := c.Get(middleware.UserRoleKey)

	c.JSON(http.StatusOK, gin.H{
		"message":  "You passed all security controls (JWT + RateLimit + WAF)",
		"user_id":  uid,
		"role":     role,
		"gateway":  "bastion",
	})
}

// WhoAmI returns the current authenticated identity
func (h *Handler) WhoAmI(c *gin.Context) {
	uid, _ := c.Get(middleware.UserIDKey)
	role, _ := c.Get(middleware.UserRoleKey)
	reqID, _ := c.Get(middleware.RequestIDKey)

	c.JSON(http.StatusOK, gin.H{
		"user_id":    uid,
		"role":       role,
		"request_id": reqID,
	})
}
