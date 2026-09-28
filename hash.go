// hash.go — bcrypt hash generation for the local passwords.
package main

import (
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

// HashPassword computes the bcrypt hash (default cost) of a password.
// Used by the `--hash` subcommand.
func HashPassword(password string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("bcrypt hash generation: %w", err)
	}
	return string(h), nil
}
