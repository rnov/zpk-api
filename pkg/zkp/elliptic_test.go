//go:build curve

package zkp

import (
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
			if !oneStepCH(test.input) {
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
			y1, y2, err := GeneratePublicCommitments(test.input)
			if err != nil {
				t.Fatalf("error generating public commitments: %s", err.Error())
			}
			r1, r2, r, err := ProverCommitment()
			if err != nil {
				t.Fatalf("error generating random commitments: %s", err.Error())
			}
			c := GenerateChallenge(r1, r2)

			s, err := SolveChallenge(test.input, r, c)
			if err != nil {
				t.Fatalf("error solving challenge: %s", err.Error())
			}

			if valid := Verify(y1, y2, r1, r2, s, c); !valid {
				t.Fatalf("unable to verify")
			}

		})
	}
}
