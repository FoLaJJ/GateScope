package auth

import (
	"context"
	"errors"
	"time"

	"github.com/AutoScan/agentscan/internal/core/config"
	"github.com/AutoScan/agentscan/internal/models"
	"github.com/AutoScan/agentscan/internal/store"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrInvalidCredentials = errors.New("invalid username or password")
	ErrInvalidToken       = errors.New("invalid or expired token")
)

type Service struct {
	store  store.Store
	cfg    config.AuthConfig
}

type TokenClaims struct {
	UserID   string `json:"user_id"`
	Username string `json:"username"`
	Role     string `json:"role"`
	jwt.RegisteredClaims
}

func NewService(s store.Store, cfg config.AuthConfig) *Service {
	return &Service{store: s, cfg: cfg}
}

func (s *Service) EnsureAdminUser(ctx context.Context) error {
	_, err := s.store.GetUserByUsername(ctx, s.cfg.Username)
	if err == nil {
		return nil
	}

	hashed, err := bcrypt.GenerateFromPassword([]byte(s.cfg.Password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	return s.store.CreateUser(ctx, &models.User{
		ID:       uuid.New().String(),
		Username: s.cfg.Username,
		Password: string(hashed),
		Role:     "admin",
	})
}

func (s *Service) Login(ctx context.Context, username, password string) (string, error) {
	user, err := s.store.GetUserByUsername(ctx, username)
	if err != nil {
		return "", ErrInvalidCredentials
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		return "", ErrInvalidCredentials
	}

	claims := TokenClaims{
		UserID:   user.ID,
		Username: user.Username,
		Role:     user.Role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(s.cfg.TokenTTL)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "agentscan",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(s.cfg.JWTSecret))
}

func (s *Service) ValidateToken(tokenStr string) (*TokenClaims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &TokenClaims{}, func(token *jwt.Token) (any, error) {
		return []byte(s.cfg.JWTSecret), nil
	})
	if err != nil {
		return nil, ErrInvalidToken
	}

	claims, ok := token.Claims.(*TokenClaims)
	if !ok || !token.Valid {
		return nil, ErrInvalidToken
	}
	return claims, nil
}
