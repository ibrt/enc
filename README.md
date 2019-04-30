# enc [![Build Status](https://travis-ci.org/ibrt/enc.svg?branch=master)](https://travis-ci.org/ibrt/enc) [![Go Report Card](https://goreportcard.com/badge/github.com/ibrt/enc)](https://goreportcard.com/report/github.com/ibrt/enc) [![Test Coverage](https://codecov.io/gh/ibrt/enc/branch/master/graph/badge.svg)](https://codecov.io/gh/ibrt/enc) [![Go Docs](https://godoc.org/github.com/ibrt/enc?status.svg)](http://godoc.org/github.com/ibrt/enc)
Small utility library to perform symmetric AES encryption in Go. Mini example:

```go
ciphertext, err := enc.Encrypt(key, plaintext)
if err != nil {
  ...
}

plaintext, err := enc.Decrypt(key, ciphertext)
if err != nil {
  ...
}
```

It is also possible to automatically encode/decode the plaintext and ciphertext using a known `[]byte <-> string` encoding such as `base64.StdEncoding`:

```go
encodedCiphertext, err := enc.EncryptWithEncoding(key, base64.StdEncoding, plaintext)
if err != nil {
  ...
}

plaintext, err := enc.DecryptWithEncoding(key, base64.StdEncoding, ciphertext)
if err != nil {
  ...
}
```
