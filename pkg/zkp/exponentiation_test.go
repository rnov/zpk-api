//go:build expo

package zkp

import (
	"math/big"
	"testing"
)

var (
	input = new(big.Int)
)

func TestOneStepNonElliptic(t *testing.T) {
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

			if valid := oneStepCHNonEllipticZQ(int64(4)); !valid {
				t.Fatalf("unable to verify")
			}
		})
	}
}
