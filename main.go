package main // import "hellojwx"

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"log"
	"reflect"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
	"gopkg.in/guregu/null.v4"

	"github.com/mitchellh/mapstructure"
)

type User struct {
	Name null.String `json:"name"`
	Age  null.Int    `json:"age"`
}

// ConvertToNullTypeHookFunc - https://github.com/mitchellh/mapstructure/issues/164
func ConvertToNullTypeHookFunc(f reflect.Type, t reflect.Type, data interface{}) (interface{}, error) {
	nullTypes := []reflect.Kind{reflect.String, reflect.Int64}

	isNullTypes := false
	for _, v := range nullTypes {
		if f.Kind() != v {
			isNullTypes = true
			break
		}
	}

	if !isNullTypes {
		return data, nil
	}

	switch t {
	case reflect.TypeOf(null.String{}):
		d := null.NewString(data.(string), true)
		return d, nil
	case reflect.TypeOf(null.Int{}):
		d := null.NewInt(int64(data.(float64)), true)
		return d, nil
	case reflect.TypeOf(null.Float{}):
		d := null.NewFloat(data.(float64), true)
		return d, nil
	}

	return data, nil
}

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

	user := User{
		Name: null.NewString("John Doe", true),
		Age:  null.NewInt(22, true),
	}

	token.Set("pcm", user)
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

	pcm, valid := token.Get("pcm")
	log.Println(pcm, valid)

	u := User{}

	cfg := &mapstructure.DecoderConfig{
		Result:     &u,
		DecodeHook: ConvertToNullTypeHookFunc,
	}
	decoder, err := mapstructure.NewDecoder(cfg)
	if err != nil {
		log.Printf("failed to set decoder: %s\n", err)
		return
	}

	err = decoder.Decode(pcm)
	if err != nil {
		log.Printf("failed to decode User map: %s\n", err)
		return
	}

	log.Println(u.Name, u.Age)
}
