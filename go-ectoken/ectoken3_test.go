package ectoken

import (
	"testing"
)

const (
	key   = "somekey"
	token = "ec_expire=1257642471&ec_secure=33"
)

func TestEncryptV3(t *testing.T) {
	if result := len(EncryptV3("somekey", "")); result <= 0 {
		t.Error("expected string hash recieved nothing.")
	}

	if result := len(EncryptV3("some", "sometoken")); result <= 0 {
		t.Error("expected string hash recieved nothing.")
	}
}

func TestDecryptV3(t *testing.T) {
	tokenHash := EncryptV3(key, token)

	result, err := DecryptV3(key, tokenHash)
	if err != nil {
		t.Error(err)
	}

	if result != token {
		t.Errorf("expected decrypted value to be %s, got %s\n", token, tokenHash)
	}
}
