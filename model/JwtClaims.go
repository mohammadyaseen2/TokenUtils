package model

import (
	"github.com/dgrijalva/jwt-go"
)

type JwtClaims struct {
	Payload
	jwt.StandardClaims
}

type Payload struct {
	Username string   `json:"username"`
	Roles    []string `json:"roles"`
	Extra
}

type Extra map[string]interface{}
