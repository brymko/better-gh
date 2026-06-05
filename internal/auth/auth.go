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

// LoadOrCreateSecret returns the secret stored at path, generating and persisting a new one ONLY if
// the file does not yet exist. This keeps a distributed admin secret stable across restarts instead of
// invalidating it every time the server starts. It distinguishes "absent" (os.IsNotExist → generate)
// from "unreadable" (EACCES/EISDIR/EIO/empty → return an error): a transiently unreadable existing
// secret must NOT be silently rotated, which would discard the operator's distributed secret and
// overwrite it on disk, locking admins out and masking whether a compromise occurred (round-20).
func LoadOrCreateSecret(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		if s := strings.TrimSpace(string(data)); s != "" {
			return s, nil
		}
		return "", fmt.Errorf("admin secret file %s is present but empty; remove it to regenerate", path)
	}
	if !os.IsNotExist(err) {
		return "", fmt.Errorf("reading admin secret %s (refusing to rotate an unreadable secret): %w", path, err)
	}
	return GenerateSecret(path)
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
