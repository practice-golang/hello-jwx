package main // import "hellojwx"

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"log"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
)

func main() {
	// 키 생성
	var payload []byte
	var keyset jwk.Set
	alg := jwa.RS512
	secret := "secret"
	log.Println("alg/key:", alg, secret)

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Printf("failed to generate private key: %s\n", err)
		return
	}

	pubKey, err := jwk.New(privKey.PublicKey)
	if err != nil {
		fmt.Printf("failed to create JWK: %s\n", err)
		return
	}

	pubKey.Set(jwk.AlgorithmKey, alg)
	pubKey.Set(jwk.KeyIDKey, secret)

	bogusKey := jwk.NewSymmetricKey()
	bogusKey.Set(jwk.AlgorithmKey, jwa.NoSignature)
	bogusKey.Set(jwk.KeyIDKey, "otherkey")

	keyset = jwk.NewSet()
	keyset.Add(pubKey)
	keyset.Add(bogusKey)

	realKey, err := jwk.New(privKey)
	if err != nil {
		log.Printf("failed to create JWK: %s\n", err)
		return
	}
	realKey.Set(jwk.KeyIDKey, secret)
	realKey.Set(jwk.AlgorithmKey, alg)

	// 토큰 생성
	token := jwt.New()
	token.Set(`foo`, `bar`)
	token.Set(`kim`, `chi`)
	signed, err := jwt.Sign(token, alg, realKey)
	if err != nil {
		log.Printf("failed to generate signed payload: %s\n", err)
		return
	}

	payload = signed

	log.Println("Signed:", string(signed))

	// 토큰 파싱
	token, err = jwt.Parse(
		payload,
		jwt.WithKeySet(keyset),
	)
	if err != nil {
		log.Printf("failed to parse payload: %s\n", err)
		return
	}

	kim, valid := token.Get("foo")
	log.Println(kim, valid)
}
