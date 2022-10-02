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
	"syscall/js"
)

func main() {
	c := make(chan int)

	js.Global().Set("encryptAes", js.FuncOf(encryptAes))
	js.Global().Set("decryptAes", js.FuncOf(decryptAes))
	js.Global().Set("hashSha256", js.FuncOf(hashSha256))
	js.Global().Set("hashMd5", js.FuncOf(hashMd5))
	js.Global().Set("encryptRsa", js.FuncOf(encryptRsa))
	js.Global().Set("decryptRsa", js.FuncOf(decryptRsa))
	js.Global().Set("signDsa", js.FuncOf(signDsa))
	js.Global().Set("verifyDsa", js.FuncOf(verifyDsa))

	<-c
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

func encryptAes(this js.Value, inputs []js.Value) interface{} {

	keyBytes := make([]byte, 32)
	rand.Read(keyBytes)

	byteMsg := []byte(inputs[0].String())
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

	return map[string]interface{}{
		"ciphertext": b64Encode(cipherText),
		"key":        b64Encode(keyBytes),
	}
}

func decryptAes(this js.Value, inputs []js.Value) interface{} {
	ciphertext := inputs[0].String()
	key := inputs[1].String()

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

func hashSha256(this js.Value, inputs []js.Value) interface{} {
	hash := sha256.Sum256([]byte(inputs[0].String()))
	return hex.EncodeToString(hash[:])
}

func hashMd5(this js.Value, inputs []js.Value) interface{} {
	hash := md5.Sum([]byte(inputs[0].String()))
	return hex.EncodeToString(hash[:])
}

func encryptRsa(this js.Value, inputs []js.Value) interface{} {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	publicKey := privateKey.PublicKey

	encryptedBytes, err := rsa.EncryptOAEP(
		sha256.New(),
		rand.Reader,
		&publicKey,
		[]byte(inputs[0].String()),
		nil)
	if err != nil {
		panic(err)
	}

	C := b64Encode(encryptedBytes)
	N := publicKey.N
	D := privateKey.D

	return map[string]interface{}{
		"C": C,
		"N": N.String(),
		"E": "65537",
		"D": D.String(),
	}
}

func decryptRsa(this js.Value, inputs []js.Value) interface{} {
	C := inputs[0].String()
	N := new(big.Int)
	N.SetString(inputs[1].String(), 10)
	E := 65535
	D := new(big.Int)
	D.SetString(inputs[2].String(), 10)

	privateKey := rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			N: N,
			E: E,
		},
		D: D,
	}

	decryptedBytes, err := privateKey.Decrypt(
		nil,
		[]byte(b64Decode(C)),
		&rsa.OAEPOptions{Hash: crypto.SHA256})
	if err != nil {
		fmt.Println(err)
	}

	return string(decryptedBytes[:])
}

func signDsa(this js.Value, inputs []js.Value) interface{} {

	msg := inputs[0].String()

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

	return map[string]interface{}{
		"Signature": b64Encode(sig),
		"PubKey":    pubkey.Y.String(),
	}
}

//func dsaVerify(msg string, signature string, y *big.Int) bool {
func verifyDsa(this js.Value, inputs []js.Value) interface{} {
	msg := inputs[0].String()
	signature := inputs[1].String()
	y := new(big.Int)
	y.SetString(inputs[2].String(), 10)

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
