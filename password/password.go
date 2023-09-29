package password

import (
	"golang.org/x/crypto/bcrypt"
)

// HashString is used to represent a string containing a password hash
type HashString string

func HashPassword(password string) (HashString, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return HashString(bytes), err
}

func CheckPasswordHash(hash HashString, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}
