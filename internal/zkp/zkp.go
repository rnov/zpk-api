package zkp

import (
	"bytes"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/gob"
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
	//Hx = big.NewInt(48439561293906451759052585252797914202762949526041747995844080717082404635286)
	//Hy = big.NewInt(36134250956749795798585127919587881956611106672985015071877198253568414405109)
	Hx = new(big.Int)
	Hx.SetString("48439561293906451759052585252797914202762949526041747995844080717082404635286", 10)

	Hy = new(big.Int)
	Hy.SetString("36134250956749795798585127919587881956611106672985015071877198253568414405109", 10)

	// Check if H is on the curve
	if !curve.IsOnCurve(Hx, Hy) {
		panic("H is not on the curve")
	}
}

// note Elliptic curve points returned as bytes other non point as *big.Int

// eCPoint represents elliptic curve points.
type eCPoint struct {
	X *big.Int
	Y *big.Int
}

func (p *eCPoint) toBytes() ([]byte, error) {
	var buf bytes.Buffer
	encoder := gob.NewEncoder(&buf)
	if err := encoder.Encode(p); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func fromBytes(data []byte) (*eCPoint, error) {
	var p eCPoint
	buf := bytes.NewBuffer(data)
	decoder := gob.NewDecoder(buf)
	if err := decoder.Decode(&p); err != nil {
		return nil, err
	}
	return &p, nil
}

// GeneratePublicCommitments generates the public commitments y1 and y2 using secret and the curve's base point G and a secondary point H.
// It returns the X and Y coordinates directly as big.Ints.
// func GeneratePublicCommitments(secret *big.Int) (gx, gy, hx, hy *big.Int, err error)
func GeneratePublicCommitments(secret *big.Int) (y1, y2 []byte, err error) {
	gx, gy := curve.ScalarBaseMult(secret.Bytes())
	hx, hy := curve.ScalarMult(Hx, Hy, secret.Bytes())

	// The caller should verify that gx, gy, hx, and hy are not nil and are on the curve.
	pc1 := &eCPoint{X: gx, Y: gy}
	pc2 := &eCPoint{X: hx, Y: hy}
	y1, _ = pc1.toBytes()
	y2, _ = pc2.toBytes()
	return y1, y2, nil
}

// ProverCommitment generates random commitments r1 and r2 for the prover.
// func aProverCommitment() (rx1, ry1, rx2, ry2, r *big.Int, err error)
// It returns the X and Y coordinates directly as big.Ints along with the random value r.
func ProverCommitment() (r1, r2 []byte, r *big.Int, err error) {
	n := curve.Params().N
	r, err = rand.Int(rand.Reader, n)
	if err != nil {
		return nil, nil, nil, err
	}

	rx1, ry1 := curve.ScalarBaseMult(r.Bytes())
	rx2, ry2 := curve.ScalarMult(Hx, Hy, r.Bytes())

	rc1 := &eCPoint{X: rx1, Y: ry1}
	rc2 := &eCPoint{X: rx2, Y: ry2}
	r1, _ = rc1.toBytes()
	r2, _ = rc2.toBytes()
	// No need for on-curve checks here because they are handled by the ScalarBaseMult and ScalarMult functions.
	return r1, r2, r, nil
}

// GenerateChallenge creates a challenge for the prover by hashing their commitments.
// func GenerateChallenge(rx1, ry1, rx2, ry2 *big.Int) *big.Int {
func GenerateChallenge(r1b, r2b []byte) *big.Int {
	rc1, _ := fromBytes(r1b)
	rc2, _ := fromBytes(r2b)
	rx1 := rc1.X
	ry1 := rc1.Y
	rx2 := rc2.X
	ry2 := rc2.Y
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

// SolveChallenge generates the prover's response s to the verifier's challenge c. (response Step)
func SolveChallenge(secret, r, c *big.Int) (*big.Int, error) {
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

// Verify checks if the prover's response (s, c) to the challenge matches the commitments (rx1, ry1, rx2, ry2).
// It accepts the X and Y coordinates directly as big.Ints.
// func Verify(gx1, gy1, gx2, gy2, rx1, ry1, rx2, ry2, s, c *big.Int) bool {
func Verify(y1b, y2b, r1b, r2b []byte, s, c *big.Int) bool {

	y1, _ := fromBytes(y1b)
	y2, _ := fromBytes(y2b)
	rc1, _ := fromBytes(r1b)
	rc2, _ := fromBytes(r2b)
	// Check if provided points are on the curve
	if !curve.IsOnCurve(y1.X, y1.Y) || !curve.IsOnCurve(y2.X, y2.Y) {
		return false // Invalid public key points
	}

	gsx, gsy := curve.ScalarBaseMult(s.Bytes())
	ycx, ycy := curve.ScalarMult(y1.X, y1.Y, c.Bytes())
	r1ComputedX, r1ComputedY := curve.Add(gsx, gsy, ycx, ycy)

	hsx, hsy := curve.ScalarMult(y2.X, y2.Y, s.Bytes())
	ycx, ycy = curve.ScalarMult(y2.X, y2.Y, c.Bytes())
	r2ComputedX, r2ComputedY := curve.Add(hsx, hsy, ycx, ycy)

	return r1ComputedX.Cmp(rc1.X) == 0 && r1ComputedY.Cmp(rc1.Y) == 0 &&
		r2ComputedX.Cmp(rc2.X) == 0 && r2ComputedY.Cmp(rc2.Y) == 0
}
