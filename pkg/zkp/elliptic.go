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

// GeneratePublicCommitments generates public commitments for a given secret value
func GeneratePublicCommitments(secret *big.Int) (g kyber.Point, h kyber.Point, xG kyber.Point, xH kyber.Point, x kyber.Scalar) {
	// Initialize the cryptographic suite
	//suite := edwards25519.NewBlakeSHA256Ed25519()

	// Default secret value
	secretB := secret.Bytes()
	// Hash the secret to generate a scalar
	scal := sha256.Sum256(secretB[:])
	// Convert the hash to a scalar value
	x = suite.Scalar().SetBytes(scal[:32])

	// Randomly pick two points G and H from the group
	g = suite.Point().Pick(rng)
	h = suite.Point().Pick(rng)
	// Compute xG and xH
	xG = suite.Point().Mul(x, g)
	xH = suite.Point().Mul(x, h)

	return g, h, xG, xH, x
}

// ProverCommitment generates a Chaum-Pedersen proof commitment given two points g and h
func ProverCommitment(g, h kyber.Point) (kyber.Point, kyber.Point, kyber.Scalar) {
	// Begin Chaum-Pedersen proof
	// Randomly pick a scalar k
	k := suite.Scalar().Pick(rng)
	// Compute kG and kH
	kG := suite.Point().Mul(k, g)
	kH := suite.Point().Mul(k, h)

	return kG, kH, k
}

// GenerateChallenge generates a random scalar to act as a challenge
func GenerateChallenge() kyber.Scalar {
	// Randomly pick a scalar to act as a challenge
	return suite.Scalar().Pick(rng) //cScalar
}

// SolveChallenge computes the response to a challenge in an elliptic curve cryptographic system.
// It takes three parameters:
//   - cScalar: the scalar value representing the challenge c
//   - x: the scalar value representing x
//   - k: the scalar value representing the prover's commitment k
//
// It computes the response r as r = k - cx and returns it as a scalar value.
func SolveChallenge(cScalar, x, k kyber.Scalar) kyber.Scalar {
	// Compute the response r = k - cx
	r := suite.Scalar()
	r.Mul(x, cScalar).Sub(k, r)

	return r
}

// Verify performs a verification step and returns a boolean value indicating whether the verification is successful or not.
func Verify(cScalar, r kyber.Scalar, g, h, xG, xH, kG, kH kyber.Point) bool {
	// Compute rG and rH
	rG := suite.Point().Mul(r, g)
	rH := suite.Point().Mul(r, h)
	// Compute cxG and cxH
	cxG := suite.Point().Mul(cScalar, xG)
	cxH := suite.Point().Mul(cScalar, xH)
	// Check if kG == rG + cxG and kH == rH + cxH
	a := suite.Point().Add(rG, cxG)
	b := suite.Point().Add(rH, cxH)

	return kG.Equal(a) && kH.Equal(b)
}

// oneStepEllipticCurveCP performs one step semi-interactive (way of generating challenge) a Chaum-Pedersen proof using
// elliptic curve cryptography.
func oneStepEllipticCurveCP(secret *big.Int) bool {
	var rng = random.New()

	// Initialize the cryptographic suite
	suite := edwards25519.NewBlakeSHA256Ed25519()

	// Default secret value
	secretB := secret.Bytes()
	// Hash the secret to generate a scalar
	scal := sha256.Sum256(secretB[:])
	// Convert the hash to a scalar value
	x := suite.Scalar().SetBytes(scal[:32])

	// Randomly pick two points G and H from the group
	G := suite.Point().Pick(rng)
	H := suite.Point().Pick(rng)
	// Compute xG and xH
	xG := suite.Point().Mul(x, G)
	xH := suite.Point().Mul(x, H)

	// Begin Chaum-Pedersen proof
	// Randomly pick a scalar k
	k := suite.Scalar().Pick(rng)
	// Compute kG and kH
	kG := suite.Point().Mul(k, G)
	kH := suite.Point().Mul(k, H)

	// Alice sends challenge - Randomly pick a scalar to act as a challenge
	cScalar := suite.Scalar().Pick(rng)

	// Bob computes response - Compute the response r = k - cx
	r := suite.Scalar()
	r.Mul(x, cScalar).Sub(k, r)

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
