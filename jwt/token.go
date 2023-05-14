package jwt

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/mohammadyaseen2/TokenUtils/model"
)

type JWT struct {
	privateKey    []byte
	publicKey     []byte
	SigningMethod jwt.SigningMethodRSA
}

type JWTValidator struct {
	publicKey []byte
}

func New(privateKey []byte, publicKey []byte, signingMethod jwt.SigningMethodRSA) *JWT {
	return &JWT{
		privateKey:    privateKey,
		publicKey:     publicKey,
		SigningMethod: signingMethod,
	}
}
func NewValidator(publicKey []byte) *JWTValidator {
	return &JWTValidator{
		publicKey: publicKey,
	}
}

func (j *JWT) GenerateToken(claims *model.JwtClaims, expirationTime time.Time) (string, error) {
	key, err := jwt.ParseRSAPrivateKeyFromPEM(j.privateKey)
	if err != nil {
		return "", fmt.Errorf("create: parse key: %w", err)
	}

	claims.ExpiresAt = expirationTime.Unix()
	claims.IssuedAt = time.Now().UTC().Unix()
	token, err := jwt.NewWithClaims(&j.SigningMethod, claims).SignedString(key)
	if err != nil {
		return "", fmt.Errorf("create: sign token: %w", err)
	}

	return token, nil
}

func (j *JWT) GetToken(payload string, expiryTime time.Duration) (string, error) {
	var claims model.JwtClaims

	if err := json.Unmarshal([]byte(payload), &claims); err != nil {
		log.Fatal(err)
	}

	var tokenCreationTime = time.Now().UTC()
	return j.GenerateToken(&claims, tokenCreationTime.Add(expiryTime))
}

func (j *JWTValidator) ValidateToken(tokenString string) (*model.JwtClaims, error) {
	key, err := jwt.ParseRSAPublicKeyFromPEM(j.publicKey)
	if err != nil {
		return nil, fmt.Errorf("verify: parse key: %w", err)
	}

	claims := &model.JwtClaims{}
	token, err := getTokenFromString(tokenString, claims, key)

	if err != nil {
		return nil, fmt.Errorf("verify: %w", err)
	}

	if token.Valid {
		return claims, nil
	}
	return nil, fmt.Errorf("verify: invalid")
}

func getTokenFromString(tokenString string, claims *model.JwtClaims, key *rsa.PublicKey) (*jwt.Token, error) {
	return jwt.ParseWithClaims(tokenString, claims, func(jwtToken *jwt.Token) (interface{}, error) {
		if _, ok := jwtToken.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected method: %s", jwtToken.Header["alg"])
		}
		return key, nil
	})
}
