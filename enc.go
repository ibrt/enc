package enc

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

const (
	// KeySize is the required key size, in bytes.
	KeySize = 32
)

var (
	_ Encoding = base64.StdEncoding
	_ Encoding = base32.StdEncoding
)

// Encoding describes a []byte <-> string encoding algorithm, such as base64.StdEncoding and others.
type Encoding interface {
	EncodeToString(src []byte) string
	DecodeString(s string) ([]byte, error)
}

// Encrypt encrypts the given plaintext using symmetric AES, GCM mode.
func Encrypt(key [KeySize]byte, plaintext []byte) ([]byte, error) {
	c, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	nonceBuf := make([]byte, gcm.NonceSize())

	if _, err = io.ReadFull(rand.Reader, nonceBuf); err != nil {
		fmt.Println(err)
	}

	return gcm.Seal(nonceBuf, nonceBuf, plaintext, nil), nil
}

// Decrypt decrypts a ciphertext encrypted by Encrypt.
func Decrypt(key [KeySize]byte, ciphertext []byte) ([]byte, error) {
	c, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < gcm.NonceSize() {
		return nil, errors.New("invalid ciphertext")
	}

	return gcm.Open(nil, ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():], nil)
}

// EncryptWithEncoding is like Encrypt, but also encodes the ciphertext to string using the given Encoding.
func EncryptWithEncoding(key [KeySize]byte, encoding Encoding, plaintext []byte) (string, error) {
	ciphertext, err := Encrypt(key, plaintext)
	if err != nil {
		return "", nil
	}

	return encoding.EncodeToString(ciphertext), nil
}

// DecryptWithEncoding is like Decrypt, but first decodes the ciphertext from string using the given Encoding.
func DecryptWithEncoding(key [KeySize]byte, encoding Encoding, encodedCiphertext string) ([]byte, error) {
	ciphertext, err := encoding.DecodeString(encodedCiphertext)
	if err != nil {
		return nil, err
	}

	return Decrypt(key, ciphertext)
}
