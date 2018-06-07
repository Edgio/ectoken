package ectoken

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"math/rand"
	"strings"
	"time"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

/*
 * DecryptV3 decrypts the given token using the supplied key. On success,
 * returns the decrypted content and a nil error. If the token is invalid or
 * can not be decrypted, returns an empty string and a non-nil error.
 */
func DecryptV3(key, token string) (string, error) {
	token = strings.TrimRight(token, "=")
	enc, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return "", err
	}
	keyHash := sha256.Sum256([]byte(key))
	block, _ := aes.NewCipher(keyHash[:])
	gcm, _ := cipher.NewGCM(block)
	s := gcm.NonceSize()
	if len(enc) < s {
		return "", errors.New("invalid data length")
	}
	dec, err := gcm.Open(nil, enc[:s], enc[s:], nil)
	if err != nil {
		return "", err
	}
	return string(dec), nil
}

/*
 * EncryptV3 encrypts the given content using the supplied key.
 */
func EncryptV3(key, token string) string {
	keyHash := sha256.Sum256([]byte(key))
	block, _ := aes.NewCipher(keyHash[:])
	gcm, _ := cipher.NewGCM(block)
	iv := make([]byte, gcm.NonceSize())
	rand.Read(iv)
	return base64.RawURLEncoding.EncodeToString(
		gcm.Seal(iv, iv, []byte(token), nil),
	)
}
