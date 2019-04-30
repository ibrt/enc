package enc_test

import (
	"encoding/base64"
	"testing"

	"github.com/ibrt/enc"
	"github.com/stretchr/testify/require"
)

var (
	key = [enc.KeySize]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31}
)

func TestEnc_Empty(t *testing.T) {
	ciphertext, err := enc.Encrypt(key, []byte(""))
	require.NoError(t, err)

	plaintext, err := enc.Decrypt(key, ciphertext)
	require.NoError(t, err)
	require.Nil(t, plaintext)
}

func TestEnc_NotEmpty(t *testing.T) {
	ciphertext, err := enc.Encrypt(key, []byte("plaintext"))
	require.NoError(t, err)

	plaintext, err := enc.Decrypt(key, ciphertext)
	require.NoError(t, err)
	require.Equal(t, []byte("plaintext"), plaintext)
}

func TestEnc_EmptyCiphertext(t *testing.T) {
	plaintext, err := enc.Decrypt(key, []byte(""))
	require.Error(t, err, "invalid ciphertext")
	require.Nil(t, plaintext)
}

func TestEnc_InvalidCiphertext(t *testing.T) {
	plaintext, err := enc.Decrypt(key, []byte("bad"))
	require.Error(t, err, "invalid ciphertext")
	require.Nil(t, plaintext)
}

func TestEnc_WithEncoding_Empty(t *testing.T) {
	ciphertext, err := enc.EncryptWithEncoding(key, base64.StdEncoding, []byte(""))
	require.NoError(t, err)

	plaintext, err := enc.DecryptWithEncoding(key, base64.StdEncoding, ciphertext)
	require.NoError(t, err)
	require.Nil(t, plaintext)
}

func TestEnc_WithEncoding_NotEmpty(t *testing.T) {
	ciphertext, err := enc.EncryptWithEncoding(key, base64.StdEncoding, []byte("plaintext"))
	require.NoError(t, err)

	plaintext, err := enc.DecryptWithEncoding(key, base64.StdEncoding, ciphertext)
	require.NoError(t, err)
	require.Equal(t, []byte("plaintext"), plaintext)
}

func TestEnc_WithEncoding_EmptyCiphertext(t *testing.T) {
	plaintext, err := enc.DecryptWithEncoding(key, base64.StdEncoding, "")
	require.Error(t, err, "invalid ciphertext")
	require.Nil(t, plaintext)
}

func TestEnc_WithEncoding_InvalidCiphertext(t *testing.T) {
	plaintext, err := enc.DecryptWithEncoding(key, base64.StdEncoding, "bad")
	require.Error(t, err, "invalid ciphertext")
	require.Nil(t, plaintext)
}
