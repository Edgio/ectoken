package ectoken

import (
	"testing"
)

const (
	key   = "somekey"
	token = "ec_expire=1257642471&ec_secure=33"
	ermsg = "expected string hash recieved nothing."
)

func TestEncryptV3(t *testing.T) {
	// should always get a hash back greater than 0
	if result := len(EncryptV3(key, "")); result <= 0 {
		t.Error(ermsg)
	}

	if result := len(EncryptV3(key, token)); result <= 0 {
		t.Error(ermsg)
	}
}

func TestDecryptV3(t *testing.T) {
	tokenHash := EncryptV3(key, token)

	result, err := DecryptV3(key, tokenHash)
	if err != nil {
		t.Error(err)
	}

	// the decrypted token value should equal the string used to encrypt
	if result != token {
		t.Errorf("expected decrypted value to be %s, got %s\n", token, tokenHash)
	}
}
