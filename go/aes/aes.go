package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"io"
	"syscall/js"
)

func main() {
	c := make(chan int)
	js.Global().Set("aesEncrypt", js.FuncOf(aesEncrypt))
	js.Global().Set("aesDecrypt", js.FuncOf(aesDecrypt))
	<-c
}

type aesValues struct {
	ciphertext string
	key        string
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

func aesEncrypt(this js.Value, inputs []js.Value) interface{} {

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

func aesDecrypt(this js.Value, inputs []js.Value) interface{} {
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
