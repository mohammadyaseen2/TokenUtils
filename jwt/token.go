package jwt

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"log"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/mohammadyaseen2/TokenUtils/model"
)

type JWT struct {
	privateKey    []byte
	SigningMethod jwt.SigningMethodRSA
}

type JWTValidator struct {
	publicKey []byte
}

func New(privateKey []byte, signingMethod jwt.SigningMethodRSA) *JWT {
	return &JWT{
		privateKey:    privateKey,
		SigningMethod: signingMethod,
	}
}
func NewValidator(publicKey []byte) *JWTValidator {
	return &JWTValidator{
		publicKey: publicKey,
	}
}

func (j *JWT) GenerateToken(payload *model.Payload) (string, error) {
	key, err := jwt.ParseRSAPrivateKeyFromPEM(j.privateKey)
	if err != nil {
		return "", fmt.Errorf("create: parse key: %w", err)
	}

	token, err := jwt.NewWithClaims(&j.SigningMethod, payload).SignedString(key)
	if err != nil {
		return "", fmt.Errorf("create: sign token: %w", err)
	}

	return token, nil
}

func (j *JWT) GetToken(payload string, expiryTime time.Duration) (string, error) {
	var p model.Payload

	if err := json.Unmarshal([]byte(payload), &p); err != nil {
		log.Fatal(err)
	}

	p.ID = uuid.New()
	p.IssuedAt = time.Now().UTC().Unix()
	p.ExpiresAt = time.Now().Add(expiryTime).UTC().Unix()

	return j.GenerateToken(&p)
}

func (j *JWTValidator) ValidateToken(tokenString string) (*model.Payload, error) {
	key, err := jwt.ParseRSAPublicKeyFromPEM(j.publicKey)
	if err != nil {
		return nil, fmt.Errorf("verify: parse key: %w", err)
	}

	payload := &model.Payload{}
	token, err := getTokenFromString(tokenString, payload, key)

	if err != nil {
		return nil, fmt.Errorf("verify: %w", err)
	}

	if token.Valid {
		return payload, nil
	}
	return nil, fmt.Errorf("verify: invalid")
}

func getTokenFromString(tokenString string, payload *model.Payload, key *rsa.PublicKey) (*jwt.Token, error) {
	return jwt.ParseWithClaims(tokenString, payload, func(jwtToken *jwt.Token) (interface{}, error) {
		if _, ok := jwtToken.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected method: %s", jwtToken.Header["alg"])
		}
		return key, nil
	})
}
