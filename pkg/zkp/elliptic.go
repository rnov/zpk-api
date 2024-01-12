//go:build curve

package zkp

import (
	"crypto/sha256"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/group/edwards25519"
	"go.dedis.ch/kyber/v3/util/random"
	"math/big"
)

var suite = edwards25519.NewBlakeSHA256Ed25519()
var rng = random.New()

// GeneratePublicCommitments2 generates the public commitments out of secret within the curve's. returns a byte
func GeneratePublicCommitments(secret *big.Int) ([]byte, error) {
	// Initialize the cryptographic suite
	//suite := edwards25519.NewBlakeSHA256Ed25519()

	// Default secret value
	secretB := secret.Bytes()
	// Hash the secret to generate a scalar
	scal := sha256.Sum256(secretB[:])
	// Convert the hash to a scalar value
	x := suite.Scalar().SetBytes(scal[:32])

	return x, nil
}

// ProverCommitment generates random commitments
func ProverCommitment(x kyber.Point) (kyber.Point, kyber.Point, kyber.Point, kyber.Point) {
	// Randomly pick two points G and H from the group
	G := suite.Point().Pick(rng)
	H := suite.Point().Pick(rng)
	// Compute xG and xH
	xG := suite.Point().Mul(x, G)
	xH := suite.Point().Mul(x, H)

	return G, H, xG, xH
}

// GenerateChallenge creates a challenge for the prover by hashing their commitments.
func GenerateChallenge(G, H kyber.Point) kyber.Scalar {
	// Begin Chaum-Pedersen proof
	// Randomly pick a scalar k
	k := suite.Scalar().Pick(rng)
	// Compute kG and kH
	kG := suite.Point().Mul(k, G)
	kH := suite.Point().Mul(k, H)

	kGb, _ := kG.MarshalBinary()
	kHb, _ := kH.MarshalBinary()
	// Create a challenge c by hashing kG and kH
	c := sha256.Sum256(append(kGb, kHb...))
	// Convert hash to a scalar
	cScalar := suite.Scalar().SetBytes(c[:32])

	return cScalar
}

// SolveChallenge generates the prover's response s to the verifier's challenge c.
func SolveChallenge(cScalar, x, k kyber.Scalar) kyber.Scalar {
	// Compute the response r = k - cx
	r := suite.Scalar()
	r.Mul(x, cScalar).Sub(k, r)

	return r
}

func Verify(cScalar, r, G, H kyber.Scalar, xG, xH, kG, kH kyber.Point) bool {
	// Verification step
	// Compute rG and rH
	rG := suite.Point().Mul(r, G)
	rH := suite.Point().Mul(r, H)
	// Compute cxG and cxH
	cxG := suite.Point().Mul(cScalar, xG)
	cxH := suite.Point().Mul(cScalar, xH)
	// Check if kG == rG + cxG and kH == rH + cxH
	a := suite.Point().Add(rG, cxG)
	b := suite.Point().Add(rH, cxH)

	return kG.Equal(a) && kH.Equal(b)
}
