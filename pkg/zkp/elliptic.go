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

// ProverCommitment takes a point `x` and returns the commitment to the Chaum-Pedersen proof
// It randomly chooses a scalar `k`, computes `kG` and `kH`, and returns them along with `k`
//
// Example usage:
//
//	x := suite.Point().SetBytes([]byte{...})
//	kG, kH, k := ProverCommitment(x)
//	// kG, kH, and k now contain the commitment values
//	// for the Chaum-Pedersen proof
//
// Note: The variables `suite` and `rng` are assumed to be globally defined and initialized.
// `suite` is a constant representing the cryptographic suite.
// `rng` is a random number generator used to pick the scalar `k`.
func ProverCommitment(g, h kyber.Point) (kyber.Point, kyber.Point, kyber.Scalar) {
	// Begin Chaum-Pedersen proof
	// Randomly pick a scalar k
	k := suite.Scalar().Pick(rng)
	// Compute kG and kH
	kG := suite.Point().Mul(k, g)
	kH := suite.Point().Mul(k, h)

	return kG, kH, k
}

// GenerateChallenge generates a challenge scalar based on two given points kg and kh.
// It first marshals kg and kh into byte slices, then concatenates them.
// Next, it computes the SHA256 hash of the concatenated byte slice.
// Finally, it converts the hash into a scalar using the suite's scalar function.
// The resulting scalar is returned.
func GenerateChallenge(kg, kh kyber.Point) kyber.Scalar {
	kGb, _ := kg.MarshalBinary()
	kHb, _ := kh.MarshalBinary()
	// Create a challenge c by hashing kG and kH
	c := sha256.Sum256(append(kGb, kHb...))
	// Convert hash to a scalar
	cScalar := suite.Scalar().SetBytes(c[:32])

	return cScalar
}

// SolveChallenge computes the response 'r' by subtracting 'cx' from 'k'.
// It takes three kyber.Scalar parameters 'cScalar', 'x', and 'k'.
// The value of 'cScalar' is multiplied by 'x' and then subtracted from 'k' to
// produce the final response 'r'.
//
// Example:
//
//	cScalar := suite.Scalar().SetInt64(10)
//	x := suite.Scalar().SetInt64(5)
//	k := suite.Scalar().SetInt64(50)
//	response := SolveChallenge(cScalar, x, k)
//
// The response value will be 0, as 50 - (10 * 5) equals 0.
func SolveChallenge(cScalar, x, k kyber.Scalar) kyber.Scalar {
	// Compute the response r = k - cx
	r := suite.Scalar()
	r.Mul(x, cScalar).Sub(k, r)

	return r
}

// Verify performs a verification step and returns a boolean value indicating whether the verification is successful or not.
func Verify(cScalar, r kyber.Scalar, g, h, xG, xH, kG, kH kyber.Point) bool {
	// Verification step
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

	kGb, _ := kG.MarshalBinary()
	kHb, _ := kH.MarshalBinary()
	//Create a challenge c by hashing kG and kH
	c := sha256.Sum256(append(kGb, kHb...))
	// Convert hash to a scalar
	cScalar := suite.Scalar().SetBytes(c[:32])

	// Compute the response r = k - cx
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
