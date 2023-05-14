package services

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"log"
	"time"
	"token-utils/models"
)

type JWT struct {
	privateKey    []byte
	publicKey     []byte
	SigningMethod jwt.SigningMethodRSA
}

func NewJWT(privateKey []byte, publicKey []byte, signingMethod jwt.SigningMethodRSA) JWT {
	return JWT{
		privateKey:    privateKey,
		publicKey:     publicKey,
		SigningMethod: signingMethod,
	}
}

func (j *JWT) GenerateToken(claims *models.JwtClaims, expirationTime time.Time) (string, error) {
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
	var claims models.JwtClaims

	if err := json.Unmarshal([]byte(payload), &claims); err != nil {
		log.Fatal(err)
	}

	var tokenCreationTime = time.Now().UTC()
	return j.GenerateToken(&claims, tokenCreationTime.Add(expiryTime))
}

func (j *JWT) VerifyToken(tokenString string) (*models.JwtClaims, error) {
	key, err := jwt.ParseRSAPublicKeyFromPEM(j.publicKey)
	if err != nil {
		return nil, fmt.Errorf("verify: parse key: %w", err)
	}

	claims := &models.JwtClaims{}
	token, err := getTokenFromString(tokenString, claims, key)

	if err != nil {
		return nil, fmt.Errorf("verify: %w", err)
	}

	if token.Valid {
		return claims, nil
	}
	return nil, fmt.Errorf("verify: invalid")
}

func getTokenFromString(tokenString string, claims *models.JwtClaims, key *rsa.PublicKey) (*jwt.Token, error) {
	return jwt.ParseWithClaims(tokenString, claims, func(jwtToken *jwt.Token) (interface{}, error) {
		if _, ok := jwtToken.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected method: %s", jwtToken.Header["alg"])
		}
		return key, nil
	})
}
