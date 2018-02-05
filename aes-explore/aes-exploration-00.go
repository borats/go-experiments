package main

import (
	"crypto/aes"
	"crypto/rand"
	"encoding/base64"

	"flag"
	"fmt"
	"io"
	"log"

	"github.com/pkg/errors"
)

const (
	aesKeyLen = 32 // AES-256
)

var (
	plainText = flag.String("plaintext", "hello", "Plaintext value to AES encrypt")
	//aesIV     = []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}
)

func getAESKey() ([]byte, error) {
	seed := make([]byte, aesKeyLen) // 256-bit seed
	_, err := io.ReadFull(rand.Reader, seed)
	if err != nil {
		return nil, errors.Wrap(err, "could not get 256-bit data")
	}
	aesKey := make([]byte, aesKeyLen) // 256-bit random AES key
	_, err = io.ReadFull(rand.Reader, aesKey)
	if err != nil {
		return nil, errors.Wrap(err, "could not get 256-bit data")
	}
	for i := range aesKey {
		aesKey[i] = byte(i) ^ seed[i] // Generate a random key
	}
	return aesKey, nil
}

func aesEncrypt(aesKey []byte, plainText []byte) ([]byte, error) {
	cipherBlock, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, errors.Wrapf(err, "NewCipher(%d bytes)", len(aesKey))
	}
	padSize := len(plainText) + (aesKeyLen - (len(plainText) % aesKeyLen))

	paddedPlaintext := make([]byte, padSize)
	cipherText := make([]byte, len(paddedPlaintext))
	copy(paddedPlaintext, plainText) // pad the rest of the plaintext

	for i := 0; i < len(paddedPlaintext); i += cipherBlock.BlockSize() {
		cipherBlock.Encrypt(
			cipherText[i:i+cipherBlock.BlockSize()],
			paddedPlaintext[i:i+cipherBlock.BlockSize()],
		)
	}
	return cipherText, nil
}

func aesDecrypt(aesKey []byte, cipherText []byte) ([]byte, error) {
	cipherBlock, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, errors.Wrapf(err, "NewCipher(%d bytes) = %s", len(aesKey))
	}
	plainText := make([]byte, len(cipherText))
	for i := 0; i < len(cipherText); i += cipherBlock.BlockSize() {
		cipherBlock.Decrypt(
			plainText[i:i+cipherBlock.BlockSize()],
			cipherText[i:i+cipherBlock.BlockSize()],
		)
	}
	return plainText, nil
}

func init() {
	flag.Parse()
}

func getBase64(val []byte) []byte {
	aesKeyBase64 := make([]byte, base64.StdEncoding.EncodedLen(len(val)))
	base64.StdEncoding.Encode(aesKeyBase64, []byte(val))
	return aesKeyBase64
}

func main() {
	plainText := []byte(*plainText)

	fmt.Printf("Plain text is: %s\n", plainText)
	aesKey, err := getAESKey()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("AES key (base64): %s\n", getBase64(aesKey))
	fmt.Printf("AES key: %v\n", aesKey)

	cipherText, err := aesEncrypt(aesKey, plainText)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("AES cipher text (base64): %s\n", getBase64(cipherText))
	fmt.Printf("AES cipher text: %v\n", cipherText)

	decPlainText, err := aesDecrypt(aesKey, cipherText)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("AES decrypted plain text: %s\n", decPlainText)
	fmt.Printf("AES decrypted plain text: %v\n", decPlainText)
}
