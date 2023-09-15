package password

import "crypto/rand"

func GenerateApiSecret(length int) (string, error) {
	const secretChars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_."
	var _ = secretChars[63] // compiler check: ensure there is at least 64 chars here

	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}

	for i := range b {
		b[i] = secretChars[b[i]&0x3f] // only use the lower 6 bits
	}
	return string(b), nil
}
