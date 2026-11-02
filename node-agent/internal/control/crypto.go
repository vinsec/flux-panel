package control

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"
)

type envelope struct {
	Encrypted bool   `json:"encrypted"`
	Data      string `json:"data"`
	Timestamp int64  `json:"timestamp"`
}

func gcm(secret string) (cipher.AEAD, error) {
	k := sha256.Sum256([]byte(secret))
	b, e := aes.NewCipher(k[:])
	if e != nil {
		return nil, e
	}
	return cipher.NewGCM(b)
}
func Encrypt(data []byte, secret string) ([]byte, error) {
	g, e := gcm(secret)
	if e != nil {
		return nil, e
	}
	nonce := make([]byte, g.NonceSize())
	if _, e = rand.Read(nonce); e != nil {
		return nil, e
	}
	c := g.Seal(nonce, nonce, data, nil)
	return json.Marshal(envelope{true, base64.StdEncoding.EncodeToString(c), time.Now().Unix()})
}
func Decrypt(data []byte, secret string) ([]byte, error) {
	var v envelope
	if e := json.Unmarshal(data, &v); e != nil {
		return nil, e
	}
	if !v.Encrypted {
		return data, nil
	}
	b, e := base64.StdEncoding.DecodeString(v.Data)
	if e != nil {
		return nil, e
	}
	g, e := gcm(secret)
	if e != nil {
		return nil, e
	}
	if len(b) < g.NonceSize() {
		return nil, fmt.Errorf("invalid encrypted frame")
	}
	return g.Open(nil, b[:g.NonceSize()], b[g.NonceSize():], nil)
}
