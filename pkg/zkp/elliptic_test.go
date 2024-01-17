//go:build curve

package zkp

import (
	"crypto/sha256"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/group/edwards25519"
	"math/big"
	"testing"
)

var (
	secret = new(big.Int)
)

func TestOneStepElliptic(t *testing.T) {
	secret.SetString("929283747463652525354647586969473", 10)

	tests := []struct {
		name  string
		input *big.Int
	}{
		{
			name:  "verify - very big.Int set by String ",
			input: secret,
		},
		{
			name:  "verify - big.Int set by int64",
			input: new(big.Int).SetInt64(12345),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if !oneStepEllipticCurveCP(test.input) {
				t.Fatalf("unable to verify")
			}
		})
	}
}

func TestEllipticCurveFlow(t *testing.T) {
	secret.SetString("929283747463652525354647586969473", 10)

	tests := []struct {
		name  string
		input *big.Int
	}{
		{
			name:  "verify - very big.Int set by String ",
			input: secret,
		},
		{
			name:  "verify - big.Int set by int64",
			input: new(big.Int).SetInt64(12345),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			g, h, xg, xh, x := GeneratePublicCommitments(test.input)

			kg, kh, k := ProverCommitment(g, h)

			cScalar := GenerateChallenge()

			r := SolveChallenge(cScalar, x, k)

			if valid := Verify(cScalar, r, g, h, xg, xh, kg, kh); !valid {
				t.Fatalf("unable to verify")
			}

		})
	}
}

func TestEllipticFailProveCommitmentCurveFlow(t *testing.T) {
	secret.SetString("929283747463652525354647586969473", 10)

	tests := []struct {
		name  string
		input *big.Int
	}{
		{
			name:  "verify - very big.Int set by String ",
			input: secret,
		},
		{
			name:  "verify - big.Int set by int64",
			input: new(big.Int).SetInt64(12345),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			g, h, xg, xh, x := GeneratePublicCommitments(test.input)

			//pick random values for ProverCommitment(g, h) in order to fail the test
			kg, kh, k := func() (kyber.Point, kyber.Point, kyber.Scalar) {
				NotValidSuite := edwards25519.NewBlakeSHA256Ed25519()
				return NotValidSuite.Point().Pick(rng), NotValidSuite.Point().Pick(rng), NotValidSuite.Scalar().Pick(rng)
			}()

			cScalar := GenerateChallenge()

			r := SolveChallenge(cScalar, x, k)

			if valid := Verify(cScalar, r, g, h, xg, xh, kg, kh); valid {
				t.Fatalf("test should fail")
			}
		})
	}
}

func TestEllipticFailVerificationBySolveChallengeCurveFlow(t *testing.T) {
	secret.SetString("929283747463652525354647586969473", 10)

	tests := []struct {
		name  string
		input *big.Int
	}{
		{
			name:  "verify - very big.Int set by String ",
			input: secret,
		},
		{
			name:  "verify - big.Int set by int64",
			input: new(big.Int).SetInt64(12345),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			g, h, xg, xh, _ := GeneratePublicCommitments(test.input)

			kg, kh, k := ProverCommitment(g, h)

			cScalar := GenerateChallenge()

			// GenerateChallenge fake challenge
			// Generate fake values of x or k based on unrelated or invalid data
			fakeX := suite.Scalar().SetInt64(1)
			//fakeK := suite.Scalar().SetInt64(1)

			r := SolveChallenge(cScalar, fakeX, k)

			if valid := Verify(cScalar, r, g, h, xg, xh, kg, kh); valid {
				t.Fatalf("test should fail")
			}
		})
	}
}

func TestEllipticFailVerifyCurveFlow(t *testing.T) {
	secret.SetString("929283747463652525354647586969473", 10)

	tests := []struct {
		name  string
		input *big.Int
	}{
		{
			name:  "verify - very big.Int set by String ",
			input: secret,
		},
		{
			name:  "verify - big.Int set by int64",
			input: new(big.Int).SetInt64(12345),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			g, h, xg, xh, x := GeneratePublicCommitments(test.input)

			kg, kh, k := ProverCommitment(g, h)

			cScalar := GenerateChallenge()

			r := SolveChallenge(cScalar, x, k)

			// change params to fail verification step
			zz := sha256.Sum256([]byte("intentional mismatch"))
			cScalar = suite.Scalar().SetBytes(zz[:32]) // fails the test #1
			//r = cScalar // fails the test #2
			//cScalar = r // fails the test #3

			// Verification step
			// Compute rG and rH
			rG := suite.Point().Mul(r, g)
			rH := suite.Point().Mul(r, h)
			// Compute cxG and cxH
			cxG := suite.Point().Mul(cScalar, xg)
			cxH := suite.Point().Mul(cScalar, xh)
			// Check if kG == rG + cxG and kH == rH + cxH
			a := suite.Point().Add(rG, cxG)
			b := suite.Point().Add(rH, cxH)

			if kg.Equal(a) && kh.Equal(b) {
				t.Fatalf("test should fail")
			}
		})
	}
}
