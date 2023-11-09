//go:build expo

package zkp

import (
	"math/big"
	"testing"
)

var (
	secret = new(big.Int)
)

func TestOneStepCHExponentiation(t *testing.T) {
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
			if valid := oneStepCHExponentiation(test.input); !valid {
				t.Fatalf("unable to verify")
			}
		})
	}
}

func TestExponentiationFlow(t *testing.T) {
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

func TestVerifyWithIncorrectChallenge(t *testing.T) {
	// Set up the initial conditions
	secret.SetString("929283747463652525354647586969473", 10)

	y1, y2, err := GeneratePublicCommitments(secret)
	if err != nil {
		t.Fatalf("error generating public commitments: %s", err.Error())
	}
	r1, r2, r, err := ProverCommitment()
	if err != nil {
		t.Fatalf("error generating prover commitments: %s", err.Error())
	}
	c := GenerateChallenge(r1, r2)

	// Solve the challenge correctly
	s, err := SolveChallenge(secret, r, c)
	if err != nil {
		t.Fatalf("error solving challenge: %s", err.Error())
	}

	// Intentionally use an incorrect challenge for verification
	incorrectChallenge := new(big.Int).SetInt64(111999)

	// Perform the verification with the incorrect challenge
	valid := Verify(y1, y2, r1, r2, s, incorrectChallenge)
	if valid {
		t.Fatalf("Verification should fail with incorrect challenge")
	}
}

func TestTamperedCommitments(t *testing.T) {
	// Set up the initial conditions
	secret.SetString("929283747463652525354647586969473", 10)

	y1, y2, err := GeneratePublicCommitments(secret)
	if err != nil {
		t.Fatalf("error generating public commitments: %s", err.Error())
	}
	r1, r2, r, err := ProverCommitment()
	if err != nil {
		t.Fatalf("error generating prover commitments: %s", err.Error())
	}
	c := GenerateChallenge(r1, r2)

	// Tamper with the commitments
	tamperedR1 := make([]byte, len(r1))
	copy(tamperedR1, r1)
	tamperedR1[0] ^= 0xFF // Flip some bits to tamper the data

	tamperedR2 := make([]byte, len(r2))
	copy(tamperedR2, r2)
	tamperedR2[0] ^= 0xFF // Flip some bits to tamper the data

	s, err := SolveChallenge(secret, r, c)
	if err != nil {
		t.Fatalf("error solving challenge: %s", err.Error())
	}

	// Perform the verification with the tampered commitments
	valid := Verify(y1, y2, tamperedR1, tamperedR2, s, c)
	if valid {
		t.Fatalf("Verification should fail with tampered commitments")
	}
}
