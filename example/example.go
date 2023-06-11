package example

import (
	"fmt"
	"log"
	"time"

	j "github.com/dgrijalva/jwt-go"
	"github.com/mohammadyaseen2/TokenUtils/jwt"
)

func ExampleMain() {
	payload := `{
		"username":"adam",
		"roles":["ADMIN"],
		"extra":{
			"age":15,
			"salary":1500.0
			}
		}`

	// 1. Generate keys (private, public)
	keyPair, err := jwt.MakeKeyPair(2048)
	if err != nil {
		log.Fatalln(err)
	}

	// 2. Initialize JWT.
	JWT := jwt.New(keyPair.PrivateKey, keyPair.PublicKey, *j.SigningMethodRS256)

	// 3. Generate a JWT Token with payload and expiry time.
	token, err := JWT.GetToken(payload, time.Second)
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Println("TOKEN:", token)

	// 4. Validate an existing JWT token.
	validator := jwt.NewValidator(keyPair.PublicKey)
	content, err := validator.ValidateToken(token)
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Println("CONTENT:", content)
}
