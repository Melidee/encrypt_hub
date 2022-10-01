package main

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"syscall/js"
)

func main() {
	c := make(chan int)
	js.Global().Set("hashSha256", js.FuncOf(hashSha256))
	js.Global().Set("hashMd5", js.FuncOf(hashMd5))
	<-c
}

func hashSha256(this js.Value, inputs []js.Value) interface{} {
	hash := sha256.Sum256([]byte(inputs[0].String()))
	return hex.EncodeToString(hash[:])
}

func hashMd5(this js.Value, inputs []js.Value) interface{} {
	hash := md5.Sum([]byte(inputs[0].String()))
	return hex.EncodeToString(hash[:])
}
