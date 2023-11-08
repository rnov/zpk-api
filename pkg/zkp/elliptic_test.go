//go:build curve

package zkp

import (
	"math/big"
	"testing"
)

var (
	input = new(big.Int)
)

func TestOneStepElliptic(t *testing.T) {
	input.SetString("929283747463652525354647586969473", 10)
	// Your secret key
	secret := new(big.Int).SetInt64(12345) // Example secret, replace with actual
	tests := []struct {
		name  string
		input *big.Int
	}{
		{
			name:  "verify",
			input: secret, //input
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			//y1, y2, err := GeneratePublicCommitments(test.input)
			//if err != nil {
			//	t.Fatalf("error generating public commitments: %s", err.Error())
			//}
			//r1, r2, r, err := ProverCommitment()
			//if err != nil {
			//	t.Fatalf("error generating random commitments: %s", err.Error())
			//}
			//c := GenerateChallenge(r1, r2)
			//
			//s, err := SolveChallenge(input, r, c)
			//if err != nil {
			//	t.Fatalf("error solving challenge: %s", err.Error())
			//}
			//
			//if valid := Verify(y1, y2, r1, r2, s, c); !valid {
			//	//if valid := Verify2(y1, y2, r1, r2, s, c); !valid {
			//	t.Fatalf("unable to verify")
			//}

			if !oneStepCH(test.input) {
				//if !oneStepCHBTC(test.input) {
				t.Fatalf("unable to verify")
			}
		})
	}
}