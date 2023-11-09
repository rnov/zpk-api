//go:build expo

package zkp

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
)

// Assuming p, g, and h are defined globally
var (
	p = big.NewInt(23) // prime number
	g = big.NewInt(4)  // generator g
	h = big.NewInt(9)  // generator h
)

// modExp calculates (base^exp) % mod using big.Int for large numbers.
// This function is a fundamental operation in many cryptographic protocols,
// including the Chaum–Pedersen protocol, where it is used to compute modular
// exponentiations securely.
func modExp(base, exp, mod *big.Int) *big.Int {
	return new(big.Int).Exp(base, exp, mod)
}

// generateNonce generates a random nonce less than max.
// In the context of the Chaum–Pedersen protocol, a nonce is a secret random
// number used once to ensure that the outputs of the protocol are not reusable,
// preserving the security properties of the protocol.
func generateNonce(max *big.Int) (*big.Int, error) {
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return nil, err
	}
	return n, nil
}

// GeneratePublicCommitments generates public commitments y1 and y2 from a secret
// within the Chaum–Pedersen protocol. These commitments are used to publicly
// demonstrate knowledge of a secret while keeping the secret hidden.
func GeneratePublicCommitments(secret *big.Int) (y1, y2 []byte, err error) {
	y1I := modExp(g, secret, p)
	y2I := modExp(h, secret, p)
	// note: error being return for compatibility with elliptic curve implementation
	return y1I.Bytes(), y2I.Bytes(), nil
}

// ProverCommitment generates random commitments r1 and r2 for the prover
// within the Chaum–Pedersen protocol. These commitments are used to create
// a proof of knowledge of the secret that corresponds to the public commitments.
func ProverCommitment() (r1, r2 []byte, r *big.Int, err error) {
	r, err = generateNonce(new(big.Int).Sub(p, big.NewInt(1))) // nonce should be less than p
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error generating nonce: %s", err.Error())
	}

	r1I := modExp(g, r, p)
	r2I := modExp(h, r, p)

	return r1I.Bytes(), r2I.Bytes(), r, nil
}

// GenerateChallenge generates a challenge for the Chaum–Pedersen protocol.
// The challenge is derived from the prover's random commitments and is used
// by the verifier to ensure the prover's knowledge of the secret without
// revealing the secret itself.
func GenerateChallenge(r1b, r2b []byte) *big.Int {
	hash := sha256.New()
	hash.Write(r1b)
	hash.Write(r2b)
	hashed := hash.Sum(nil)

	// Convert the hash to a big.Int, then reduce modulo p
	c := new(big.Int).SetBytes(hashed)
	c.Mod(c, p)
	if c.Sign() == 0 {
		return nil // Challenge cannot be zero after modulo operation
	}
	return c
}

// SolveChallenge computes the solution to a given challenge in the Chaum–Pedersen protocol.
// The solution is a value that, when combined with the public commitments and the prover's
// random commitments, will satisfy the verification equation without revealing the secret.
func SolveChallenge(secret, r, c *big.Int) (*big.Int, error) {
	s := new(big.Int).Sub(r, new(big.Int).Mul(c, secret))
	s.Mod(s, new(big.Int).Sub(p, big.NewInt(1))) // Adjusted to ensure s is within Z_q

	// note returns error for due elliptic curve implementation does
	return s, nil
}

// Verify checks if the prover's response to a challenge in the Chaum–Pedersen protocol is correct.
// It ensures that the commitments and the solution satisfy the verification equation,
// confirming the prover's knowledge of the secret associated with the public commitments.
func Verify(y1b, y2b, r1b, r2b []byte, s, c *big.Int) bool {
	y1 := new(big.Int).SetBytes(y1b)
	y2 := new(big.Int).SetBytes(y2b)
	r1 := new(big.Int).SetBytes(r1b)
	r2 := new(big.Int).SetBytes(r2b)

	// Verify
	gs := modExp(g, s, p)   // g^s mod p
	y1c := modExp(y1, c, p) // y1^c mod p
	r1Computed := new(big.Int).Mul(gs, y1c)
	r1Computed.Mod(r1Computed, p) // (g^s * y1^c) mod p

	hs := modExp(h, s, p)   // h^s mod p
	y2c := modExp(y2, c, p) // y2^c mod p
	r2Computed := new(big.Int).Mul(hs, y2c)
	r2Computed.Mod(r2Computed, p) // (h^s * y2^c) mod p

	// Compare the computed values with the prover's commitments
	return r1.Cmp(r1Computed) == 0 && r2.Cmp(r2Computed) == 0
}

// oneStepCHExponentiation performs the Chaum-Pedersen protocol in one step
func oneStepCHExponentiation(secret *big.Int) bool {
	// GeneratePublicCommitments
	y1 := modExp(g, secret, p)
	y2 := modExp(h, secret, p)

	// ProverCommitment
	r, err := generateNonce(new(big.Int).Sub(p, big.NewInt(1))) // nonce should be less than p
	if err != nil {
		fmt.Println("Error generating nonce:", err)
		return false
	}

	r1 := modExp(g, r, p)
	r2 := modExp(h, r, p)

	// GenerateChallenge
	hash := sha256.New()
	hash.Write(r1.Bytes())
	hash.Write(r2.Bytes())
	hashed := hash.Sum(nil)

	// Convert the hash to a big.Int, then reduce modulo p
	bigC := new(big.Int).SetBytes(hashed)
	bigC.Mod(bigC, p)
	if bigC.Sign() == 0 {
		return false // Challenge cannot be zero after modulo operation
	}

	// SolveChallenge
	s := new(big.Int).Sub(r, new(big.Int).Mul(bigC, secret))
	s.Mod(s, new(big.Int).Sub(p, big.NewInt(1))) // Adjusted to ensure s is within Z_q

	// Verify
	gs := modExp(g, s, p)      // g^s mod p
	y1c := modExp(y1, bigC, p) // y1^c mod p
	r1Computed := new(big.Int).Mul(gs, y1c)
	r1Computed.Mod(r1Computed, p) // (g^s * y1^c) mod p

	hs := modExp(h, s, p)      // h^s mod p
	y2c := modExp(y2, bigC, p) // y2^c mod p
	r2Computed := new(big.Int).Mul(hs, y2c)
	r2Computed.Mod(r2Computed, p) // (h^s * y2^c) mod p

	// Compare the computed values with the prover's commitments
	return r1.Cmp(r1Computed) == 0 && r2.Cmp(r2Computed) == 0
}
