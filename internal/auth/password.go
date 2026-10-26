// Package auth validates the one supported bounded Argon2id password profile.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"golang.org/x/crypto/argon2"
	"strings"
)

const prefix = "$argon2id$v=19$m=65536,t=3,p=1$"

func Parse(hash string) ([]byte, []byte, error) {
	if !strings.HasPrefix(hash, prefix) || len(hash) > 200 {
		return nil, nil, errors.New("invalid_password_hash")
	}
	parts := strings.Split(strings.TrimPrefix(hash, prefix), "$")
	if len(parts) != 2 {
		return nil, nil, errors.New("invalid_password_hash")
	}
	salt, e := base64.RawStdEncoding.Strict().DecodeString(parts[0])
	if e != nil || len(salt) != 16 {
		return nil, nil, errors.New("invalid_password_hash")
	}
	digest, e := base64.RawStdEncoding.Strict().DecodeString(parts[1])
	if e != nil || len(digest) != 32 {
		return nil, nil, errors.New("invalid_password_hash")
	}
	return salt, digest, nil
}
func Verify(hash, password string) bool {
	salt, want, e := Parse(hash)
	if e != nil || len(password) < 32 || len(password) > 256 {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, 3, 65536, 1, 32)
	return subtle.ConstantTimeCompare(got, want) == 1
}
func Hash(password string) (string, error) {
	if len(password) < 32 || len(password) > 256 {
		return "", errors.New("invalid_password")
	}
	salt := make([]byte, 16)
	if _, e := rand.Read(salt); e != nil {
		return "", e
	}
	digest := argon2.IDKey([]byte(password), salt, 3, 65536, 1, 32)
	return prefix + base64.RawStdEncoding.EncodeToString(salt) + "$" + base64.RawStdEncoding.EncodeToString(digest), nil
}
