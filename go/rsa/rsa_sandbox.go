package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math/big"
)

//(this js.Value, inputs []js.Value) interface{}

func main() {
	rsaEncrypt([]string{"Hello"})
}

func b64Encode(data []byte) string {
	dst := make([]byte, base64.StdEncoding.EncodedLen(len(data)))
	base64.StdEncoding.Encode(dst, data)

	return string(dst)
}

func b64Decode(input string) []byte {
	str := input
	dst := make([]byte, base64.StdEncoding.DecodedLen(len(str)))
	n, err := base64.StdEncoding.Decode(dst, []byte(str))
	if err != nil {
		panic(err)
	}
	dst = dst[:n]
	return dst[:]
}

func rsaEncrypt(inputs []string) interface{} {

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	publicKey := privateKey.PublicKey

	encryptedBytes, err := rsa.EncryptOAEP(
		sha256.New(),
		rand.Reader,
		&publicKey,
		[]byte(inputs[0]),
		nil)
	if err != nil {
		panic(err)
	}

	fmt.Println(publicKey.E)

	return map[string]interface{}{
		"C": b64Encode(encryptedBytes),
		"N": b64Encode(publicKey.N.Bytes()),
		"D": b64Encode(privateKey.D.Bytes()),
	}
}

//func rsaDecrypt(c string, n *big.Int, e int, d *big.Int) string {
func rsaDecrypt(inputs []string) interface{} {

	c := b64Decode(inputs[0])
	n := new(big.Int).SetBytes(b64Decode(inputs[1]))
	e := 65537
	d := new(big.Int).SetBytes(b64Decode(inputs[2]))

	privateKey := rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			N: n,
			E: e,
		},
		D: d,
	}

	decryptedBytes, err := privateKey.Decrypt(
		nil,
		c,
		&rsa.OAEPOptions{Hash: crypto.SHA256})
	if err != nil {
		panic(err)
	}

	return string(decryptedBytes)
}
