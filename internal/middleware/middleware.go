package middleware

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/mohit-bhandari45/bastion/internal/auth"
	"github.com/mohit-bhandari45/bastion/internal/logger"
	"github.com/mohit-bhandari45/bastion/internal/ratelimit"
	"github.com/mohit-bhandari45/bastion/internal/waf"
)

const RequestIDKey = "request_id"
const UserIDKey = "user_id"
const UserRoleKey = "user_role"

func RequestID() gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.GetHeader("X-Request-ID")
		if id == "" {
			id = uuid.New().String()
		}
		c.Set(RequestIDKey, id)
		c.Writer.Header().Set("X-Request-ID", id)
		c.Next()
	}
}

func SecurityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("Referrer-Policy", "no-referrer")
		c.Header("X-XSS-Protection", "0")
		c.Header("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		c.Next()
	}
}

func WAF(engine *waf.Engine, log *logger.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		result := engine.Inspect(c.Request)
		if result.Matched {
			reqID, _ := c.Get(RequestIDKey)
			log.Security(logger.SecurityEvent{
				EventType:  "waf_block",
				Severity:   "high",
				ClientIP:   c.ClientIP(),
				Method:     c.Request.Method,
				Path:       c.Request.URL.Path,
				UserAgent:  c.Request.UserAgent(),
				Reason:     result.Reason,
				StatusCode: http.StatusForbidden,
				RequestID:  reqID.(string),
				Extra: map[string]interface{}{
					"pattern": result.Pattern,
				},
			})

			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error":   "request blocked by security policy",
				"code":    "WAF_BLOCK",
				"request": reqID,
			})
			return
		}
		c.Next()
	}
}

func RateLimit(limiter *ratelimit.Limiter, log *logger.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Prefer authenticated user, fallback to IP
		key := c.ClientIP()
		if uid, exists := c.Get(UserIDKey); exists {
			key = "user:" + uid.(string)
		}

		allowed, remaining, retryAfter, err := limiter.Allow(c.Request.Context(), key)
		if err != nil {
			log.Warn("rate limiter redis error", map[string]interface{}{"error": err.Error()})
		}

		c.Header("X-RateLimit-Remaining", fmt.Sprintf("%d", remaining))

		if !allowed {
			reqID, _ := c.Get(RequestIDKey)
			log.Security(logger.SecurityEvent{
				EventType:  "rate_limit",
				Severity:   "medium",
				ClientIP:   c.ClientIP(),
				Method:     c.Request.Method,
				Path:       c.Request.URL.Path,
				UserAgent:  c.Request.UserAgent(),
				Reason:     "rate limit exceeded",
				StatusCode: http.StatusTooManyRequests,
				RequestID:  reqID.(string),
			})

			c.Header("Retry-After", fmt.Sprintf("%d", retryAfter))
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error":       "rate limit exceeded",
				"retry_after": retryAfter,
				"code":        "RATE_LIMIT",
			})
			return
		}
		c.Next()
	}
}

func JWTAuth(tokenSvc *auth.TokenService, log *logger.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "missing or invalid authorization header",
				"code":  "UNAUTHORIZED",
			})
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		claims, err := tokenSvc.ValidateAccessToken(tokenString)
		if err != nil {
			reqID, _ := c.Get(RequestIDKey)
			log.Security(logger.SecurityEvent{
				EventType:  "auth_failure",
				Severity:   "medium",
				ClientIP:   c.ClientIP(),
				Method:     c.Request.Method,
				Path:       c.Request.URL.Path,
				UserAgent:  c.Request.UserAgent(),
				Reason:     "invalid or expired token",
				StatusCode: http.StatusUnauthorized,
				RequestID:  reqID.(string),
			})

			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "invalid or expired token",
				"code":  "INVALID_TOKEN",
			})
			return
		}

		c.Set(UserIDKey, claims.UserID)
		c.Set(UserRoleKey, claims.Role)
		c.Next()
	}
}

func AccessLog(log *logger.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()
		latency := time.Since(start)

		reqID, _ := c.Get(RequestIDKey)
		uid, _ := c.Get(UserIDKey)

		log.Info("request", map[string]interface{}{
			"request_id":  reqID,
			"method":      c.Request.Method,
			"path":        c.Request.URL.Path,
			"status":      c.Writer.Status(),
			"latency_ms":  latency.Milliseconds(),
			"client_ip":   c.ClientIP(),
			"user_id":     uid,
			"user_agent":  c.Request.UserAgent(),
		})
	}
}
