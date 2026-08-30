package middleware

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"harbore.dev/orchestrator/models"
)

type contextKey string

const (
	CtxUserID   contextKey = "user_id"
	CtxUserRole contextKey = "user_role"
)

type Claims struct {
	UserID string `json:"user_id"`
	Role   string `json:"role"`
	jwt.RegisteredClaims
}

var jwtSecret []byte

func SetJWTSecret(secret string) {
	jwtSecret = []byte(secret)
}

// Auth validates the JWT token from the Authorization header.
func Auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var token string

		if header := r.Header.Get("Authorization"); header != "" {
			parts := strings.SplitN(header, " ", 2)
			if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
				http.Error(w, `{"error":"invalid authorization format"}`, http.StatusUnauthorized)
				return
			}
			token = parts[1]
		} else if q := r.URL.Query().Get("token"); q != "" {
			// WebSocket handshakes from the browser can't set an Authorization
			// header, so allow the JWT to be passed as a ?token= query param.
			token = q
		} else {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}

		claims, err := validateToken(token)
		if err != nil {
			http.Error(w, `{"error":"invalid or expired token"}`, http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), CtxUserID, claims.UserID)
		ctx = context.WithValue(ctx, CtxUserRole, claims.Role)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequireRole checks the user has at minimum the given role.
func RequireRole(role models.UserRole) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userRole := r.Context().Value(CtxUserRole).(string)
			if !hasPermission(models.UserRole(userRole), role) {
				http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// WorkerAuth validates the internal worker token.
func WorkerAuth(workerToken string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := r.Header.Get("X-Worker-Token")
			if token != workerToken {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func GenerateToken(userID uuid.UUID, role models.UserRole, secret string, expiryHours int) (string, error) {
	claims := Claims{
		UserID: userID.String(),
		Role:   string(role),
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Duration(expiryHours) * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "harbore",
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}

func validateToken(tokenStr string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, jwt.ErrSignatureInvalid
		}
		return jwtSecret, nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, jwt.ErrTokenInvalidClaims
	}
	return claims, nil
}

func GetUserID(ctx context.Context) (uuid.UUID, bool) {
	v, ok := ctx.Value(CtxUserID).(string)
	if !ok {
		return uuid.UUID{}, false
	}
	id, err := uuid.Parse(v)
	return id, err == nil
}

func GetUserRole(ctx context.Context) models.UserRole {
	v, _ := ctx.Value(CtxUserRole).(string)
	return models.UserRole(v)
}

// hasPermission checks role hierarchy: admin > analyst > viewer
func hasPermission(has, needs models.UserRole) bool {
	rank := map[models.UserRole]int{
		models.RoleViewer:  1,
		models.RoleAnalyst: 2,
		models.RoleAdmin:   3,
	}
	return rank[has] >= rank[needs]
}
