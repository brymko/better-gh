package auth

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func GenerateSecret(path string) (string, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", fmt.Errorf("creating directory: %w", err)
	}

	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating random bytes: %w", err)
	}
	secret := hex.EncodeToString(b)

	if err := os.WriteFile(path, []byte(secret), 0o600); err != nil {
		return "", fmt.Errorf("writing secret: %w", err)
	}

	return secret, nil
}

func ExtractToken(header string) string {
	header = strings.TrimSpace(header)
	for _, prefix := range []string{"token ", "Token ", "Bearer ", "bearer "} {
		if strings.HasPrefix(header, prefix) {
			return strings.TrimSpace(header[len(prefix):])
		}
	}
	return ""
}
