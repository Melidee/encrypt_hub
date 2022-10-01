package main

import "testing"

func TestAes(t *testing.T) {

	want := "Hello World"
	encrypted, key := aesEncrypt(want)
	got := aesDecrypt(encrypted, key)

	if got != want {
		t.Errorf("got %q, wanted %q", got, want)
	}
}

func TestSha2(t *testing.T) {

	want := "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e"
	got := hashSha256("Hello World")

	if got != want {
		t.Errorf("got %q, wanted %q", got, want)
	}
}

func TestMD5(t *testing.T) {

	want := "b10a8db164e0754105b7a99be72e3fe5"
	got := hashMD5("Hello World")

	if got != want {
		t.Errorf("got %q, wanted %q", got, want)
	}
}

func TestRsa(t *testing.T) {

	want := "Hello World"
	ciphertext, keys := rsaEncrypt(want)
	got := rsaDecrypt(ciphertext, keys)

	if got != want {
		t.Errorf("got %q, wanted %q", got, want)
	}
}

func TestDsa(t *testing.T) {

	want := true
	msg := "Hello World"
	signature, key := dsaSign(msg)
	got := dsaVerify(msg, signature, key)

	if got != want {
		t.Errorf("got %t, wanted %t", got, want)
	}
}
