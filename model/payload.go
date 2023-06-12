package model

import (
	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
	"time"
)

type Payload struct {
	ID       uuid.UUID `json:"id"`
	Username string    `json:"username"`
	Roles    []string  `json:"roles"`
	Extra    Extra     `json:"extra"`
	jwt.StandardClaims
}

// NewPayload creates a new token payload with a specific username and duration
func NewPayload(username string, roles []string, duration time.Duration, extra Extra) (*Payload, error) {
	tokenID := uuid.New()
	payload := &Payload{
		ID:       tokenID,
		Username: username,
		Roles:    roles,
		Extra:    extra,
	}

	payload.IssuedAt = time.Now().UTC().Unix()
	payload.ExpiresAt = time.Now().Add(duration).UTC().Unix()
	return payload, nil
}

type Extra map[string]interface{}
