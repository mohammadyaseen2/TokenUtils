package main

import (
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"log"
	"time"
	"token-utils/services"
)

func main() {

	payload := `{
		"username":"adam",
		"roles":["ADMIN"],
		"extra":{
			"age":15,
			"salary":1500.0
			}
		}`

	// 1. Generate keys (private, public)
	keyPair, err := services.MakeKeyPair(2048)
	if err != nil {
		log.Fatalln(err)
	}

	// 1. Create a new JWT token.
	jwtToken := services.NewJWT(keyPair.PrivateKey, keyPair.PublicKey, *jwt.SigningMethodRS256)

	// 2. Generate Token with string Payload
	tok, err := jwtToken.GetToken(payload, time.Second)
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Println("TOKEN:", tok)

	// 3. Validate an existing JWT token.
	content, err := jwtToken.VerifyToken(tok)
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Println("CONTENT:", content.Payload)
}
