package main

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/dsa"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
)

func main() {
	msg := "Hello"
	Signature, Y := dsaSign(msg)
	result := dsaVerify(msg, Signature, Y)
	fmt.Println(result)
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

func aesEncrypt(message string) (ciphertext string, key string) {

	keyBytes := make([]byte, 32)
	rand.Read(keyBytes)

	byteMsg := []byte(message)
	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		panic(err)
	}

	cipherText := make([]byte, aes.BlockSize+len(byteMsg))
	iv := cipherText[:aes.BlockSize]
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(cipherText[aes.BlockSize:], byteMsg)

	return b64Encode(cipherText), b64Encode(keyBytes)
}

func aesDecrypt(ciphertext string, key string) string {

	keyBytes := b64Decode(key)

	cipherText, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		panic(err)
	}

	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		panic(err)
	}

	if len(cipherText) < aes.BlockSize {
		panic(err)
	}

	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(cipherText, cipherText)

	return string(cipherText)
}

func hashMD5(input string) string {
	hash := md5.Sum([]byte(input))
	return hex.EncodeToString(hash[:])
}

func hashSha256(input string) string {
	hash := sha256.Sum256([]byte(input))
	return hex.EncodeToString(hash[:])
}

func rsaEncrypt(m string) (c string, n *big.Int, e int, d *big.Int) {

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	publicKey := privateKey.PublicKey

	encryptedBytes, err := rsa.EncryptOAEP(
		sha256.New(),
		rand.Reader,
		&publicKey,
		[]byte(m),
		nil)
	if err != nil {
		panic(err)
	}

	C := b64Encode(encryptedBytes)
	N := publicKey.N
	E := publicKey.E
	D := privateKey.D

	return C, N, E, D
}

func rsaDecrypt(c string, n *big.Int, e int, d *big.Int) string {

	privateKey := rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			N: n,
			E: e,
		},
		D: d,
	}

	decryptedBytes, err := privateKey.Decrypt(
		nil,
		[]byte(b64Decode(c)),
		&rsa.OAEPOptions{Hash: crypto.SHA256})
	if err != nil {
		panic(err)
	}

	return string(decryptedBytes)
}

func dsaSign(msg string) (signature string, y *big.Int) {

	params := new(dsa.Parameters)
	if err := dsa.GenerateParameters(params, rand.Reader, dsa.L1024N160); err != nil {
		fmt.Println(err)
	}

	privatekey := new(dsa.PrivateKey)
	privatekey.PublicKey.Parameters = *params
	dsa.GenerateKey(privatekey, rand.Reader)

	pubkey := privatekey.PublicKey

	h := sha256.New()

	io.WriteString(h, msg)
	signhash := h.Sum(nil)

	r, s, err := dsa.Sign(rand.Reader, privatekey, signhash)
	if err != nil {
		fmt.Println(err)
	}

	sig := r.Bytes()
	sig = append(sig, s.Bytes()...)
	Signature := b64Encode(sig)

	Y := pubkey.Y

	return Signature, Y
}

func dsaVerify(msg string, signature string, y *big.Int) bool {

	pubkey := dsa.PublicKey{
		Y: y,
	}

	signhash := sha256.Sum256([]byte(msg))

	sig := b64Decode(signature)
	r := big.NewInt(0).SetBytes(sig[:20])
	s := big.NewInt(0).SetBytes(sig[20:])

	verifystatus := dsa.Verify(&pubkey, signhash[:], r, s)

	return verifystatus
}
