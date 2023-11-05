package zkp

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"math/big"
)

// note ideally we should be using the non-deprecated crypto/ecdh (by NIST) however it does make a bit more complex way of
// managing data.

var curve = elliptic.P256()

// Example values for H (secondary base point)
var (
	Hx, Hy *big.Int
)

func init() {
	// Initialize Hx and Hy with example values.
	Hx = big.NewInt(48439561293906451759052585252797914202762949526041747995844080717082404635286)
	Hy = big.NewInt(36134250956749795798585127919587881956611106672985015071877198253568414405109)

	// Check if H is on the curve
	if !curve.IsOnCurve(Hx, Hy) {
		panic("H is not on the curve")
	}
}

// note wrapped as *ecdsa.PublicKey
//// GeneratePublicCommitments generates the public commitments y1 and y2 using secret and the curve's base point G and a secondary point H.
//func GeneratePublicCommitments(secret *big.Int) (*ecdsa.PublicKey, *ecdsa.PublicKey, error) {
//	// Calculate y1 using the secret and the base point G.
//	gx, gy := curve.ScalarBaseMult(secret.Bytes())
//	y1 := &ecdsa.PublicKey{Curve: curve, X: gx, Y: gy}
//
//	// Calculate y2 using the secret and the point H.
//	hx, hy := curve.ScalarMult(Hx, Hy, secret.Bytes())
//	y2 := &ecdsa.PublicKey{Curve: curve, X: hx, Y: hy}
//
//	return y1, y2, nil
//}

// GeneratePublicCommitments generates the public commitments y1 and y2 using secret and the curve's base point G and a secondary point H.
// It returns the X and Y coordinates directly as big.Ints.
func GeneratePublicCommitments(secret *big.Int) (gx, gy, hx, hy *big.Int, err error) {
	gx, gy = curve.ScalarBaseMult(secret.Bytes())
	hx, hy = curve.ScalarMult(Hx, Hy, secret.Bytes())

	// The caller should verify that gx, gy, hx, and hy are not nil and are on the curve.
	return gx, gy, hx, hy, nil
}

// note wrapped as *ecdsa.PublicKey
// ProverCommitment generates random commitments r1 and r2 for the prover.
//func ProverCommitment() (*ecdsa.PublicKey, *ecdsa.PublicKey, *big.Int, error) {
//	// Generate a random scalar value r in the range [1, n-1], where n is the order of the curve.
//	n := curve.Params().N
//	r, err := rand.Int(rand.Reader, n)
//	if err != nil {
//		return nil, nil, nil, err
//	}
//
//	// Calculate r1 = g^r (g to the power of r)
//	rx1, ry1 := curve.ScalarBaseMult(r.Bytes())
//	r1 := &ecdsa.PublicKey{Curve: curve, X: rx1, Y: ry1}
//
//	// Calculate r2 = h^r (h to the power of r)
//	rx2, ry2 := curve.ScalarMult(Hx, Hy, r.Bytes())
//	r2 := &ecdsa.PublicKey{Curve: curve, X: rx2, Y: ry2}
//
//	return r1, r2, r, nil
//}

// ProverCommitment generates random commitments r1 and r2 for the prover.
// It returns the X and Y coordinates directly as big.Ints along with the random value r.
func ProverCommitment() (rx1, ry1, rx2, ry2, r *big.Int, err error) {
	n := curve.Params().N
	r, err = rand.Int(rand.Reader, n)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}

	rx1, ry1 = curve.ScalarBaseMult(r.Bytes())
	rx2, ry2 = curve.ScalarMult(Hx, Hy, r.Bytes())

	// No need for on-curve checks here because they are handled by the ScalarBaseMult and ScalarMult functions.
	return rx1, ry1, rx2, ry2, r, nil
}

// GenerateChallenge creates a challenge for the prover by hashing their commitments.
func GenerateChallenge(rx1, ry1, rx2, ry2 *big.Int) *big.Int {
	// A simple challenge generation using hash of r1 and r2 (This is just an example)
	hash := sha256.New()
	hash.Write(rx1.Bytes())
	hash.Write(ry1.Bytes())
	hash.Write(rx2.Bytes())
	hash.Write(ry2.Bytes())
	hashed := hash.Sum(nil)

	c := new(big.Int).SetBytes(hashed)
	// Ensure that the challenge c is within the order of the curve
	c.Mod(c, elliptic.P256().Params().N)
	return c
}

// note wrapped as *ecdsa.PublicKey
// verify checks if the prover's response (s, c) to the challenge matches the commitments (r1, r2).
//func verify(y1, y2, r1, r2 *ecdsa.PublicKey, s, c *big.Int) bool {
//	// Recompute g^s * y1^c and check if it matches r1.
//	gsx, gsy := curve.ScalarBaseMult(s.Bytes())
//	ycx, ycy := curve.ScalarMult(y1.X, y1.Y, c.Bytes())
//	r1ComputedX, r1ComputedY := curve.Add(gsx, gsy, ycx, ycy)
//
//	// Recompute h^s * y2^c and check if it matches r2.
//	hsx, hsy := curve.ScalarMult(y2.X, y2.Y, s.Bytes())
//	ycx, ycy = curve.ScalarMult(y2.X, y2.Y, c.Bytes())
//	r2ComputedX, r2ComputedY := curve.Add(hsx, hsy, ycx, ycy)
//
//	// Check if the computed values match the commitments.
//	return r1ComputedX.Cmp(r1.X) == 0 && r1ComputedY.Cmp(r1.Y) == 0 &&
//		r2ComputedX.Cmp(r2.X) == 0 && r2ComputedY.Cmp(r2.Y) == 0
//}

// Verify checks if the prover's response (s, c) to the challenge matches the commitments (rx1, ry1, rx2, ry2).
// It accepts the X and Y coordinates directly as big.Ints.
func Verify(gx1, gy1, gx2, gy2, rx1, ry1, rx2, ry2, s, c *big.Int) bool {
	// Check if provided points are on the curve
	if !curve.IsOnCurve(gx1, gy1) || !curve.IsOnCurve(gx2, gy2) {
		return false // Invalid public key points
	}

	gsx, gsy := curve.ScalarBaseMult(s.Bytes())
	ycx, ycy := curve.ScalarMult(gx1, gy1, c.Bytes())
	r1ComputedX, r1ComputedY := curve.Add(gsx, gsy, ycx, ycy)

	hsx, hsy := curve.ScalarMult(gx2, gy2, s.Bytes())
	ycx, ycy = curve.ScalarMult(gx2, gy2, c.Bytes())
	r2ComputedX, r2ComputedY := curve.Add(hsx, hsy, ycx, ycy)

	return r1ComputedX.Cmp(rx1) == 0 && r1ComputedY.Cmp(ry1) == 0 &&
		r2ComputedX.Cmp(rx2) == 0 && r2ComputedY.Cmp(ry2) == 0
}

// ResponseStep generates the prover's response s to the verifier's challenge c.
func ResponseStep(secret, r, c *big.Int) (*big.Int, error) {
	n := elliptic.P256().Params().N // Order of the curve

	// Check that 0 < r, secret < n
	if secret.Cmp(big.NewInt(0)) <= 0 || secret.Cmp(n) >= 0 ||
		r.Cmp(big.NewInt(0)) <= 0 || r.Cmp(n) >= 0 {
		return nil, errors.New("invalid input: secret or r are out of valid range")
	}

	// s = r + cx (mod n), where x is the secret, r is the random value from commitment,
	// and c is the challenge from the verifier.
	s := new(big.Int).Mul(c, secret) // cx
	s.Add(s, r)                      // r + cx
	s.Mod(s, n)                      // mod n

	return s, nil
}
