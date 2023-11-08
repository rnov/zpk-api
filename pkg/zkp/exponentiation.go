//go:build expo

package zkp

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
)

func generateNonce(p int64) (int64, error) {
	maxN := big.NewInt(p - 1)
	n, err := rand.Int(rand.Reader, maxN)
	if err != nil {
		return 0, err
	}
	return n.Int64() + 1, nil
}
func modExp(base, exponent, modulus int64) int64 {
	result := int64(1)
	base = base % modulus
	for exponent > 0 {
		if exponent%2 == 1 {
			result = (result * base) % modulus
		}
		exponent = exponent >> 1
		base = (base * base) % modulus
	}
	return result
}

const (
	p int64 = 23 // A small prime number for demonstration purposes
	g int64 = 5  // A small generator for the group
	h int64 = 2  // Another element of the group
)

func oneStepCHNonEllipticZQ(secret int64) bool {
	// GeneratePublicCommitments
	y1 := modExp(g, secret, p)
	y2 := modExp(h, secret, p)

	// ProverCommitment
	r, err := generateNonce(p)
	if err != nil {
		fmt.Println("Error generating nonce:", err)
		return false
	}

	r1 := modExp(g, secret, p)
	r2 := modExp(h, secret, p)

	// GenerateChallenge
	hash := sha256.New()
	hash.Write(big.NewInt(r1).Bytes())
	hash.Write(big.NewInt(r2).Bytes())
	hashed := hash.Sum(nil)

	// Convert the hash to a big.Int, then reduce modulo p
	bigC := new(big.Int).SetBytes(hashed)
	bigC.Mod(bigC, big.NewInt(p))
	c := bigC.Int64()
	if c == 0 {
		return false // Challenge cannot be zero after modulo operation
	}

	// SolveChallenge
	s := (c*secret + r) % p

	// Verify
	gs := modExp(g, s, p)        // g^s mod p
	y1c := modExp(y1, c, p)      // y1^c mod p
	r1Computed := (r1 * y1c) % p // (r1 * y1^c) mod p

	hs := modExp(h, s, p)        // h^s mod p
	y2c := modExp(y2, c, p)      // y2^c mod p
	r2Computed := (r2 * y2c) % p // (r2 * y2^c) mod p

	// Compare the computed values with g^s and h^s
	return gs == r1Computed && hs == r2Computed
}
