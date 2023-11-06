package zkp

import (
	"bytes"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/gob"
	"errors"
	"fmt"
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

var validate = make(map[string]*eCPoint)
var bigIntValidator = make(map[string]*big.Int)

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
func GeneratePublicCommitments(secret *big.Int) (y1, y2 []byte, err error) {
	gx, gy := curve.ScalarBaseMult(secret.Bytes())
	hx, hy := curve.ScalarMult(Hx, Hy, secret.Bytes())

	// Perform on-curve checks for additional safety
	if !curve.IsOnCurve(gx, gy) || !curve.IsOnCurve(hx, hy) {
		return nil, nil, errors.New("generated points are not on the curve")
	}

	pc1 := &eCPoint{X: gx, Y: gy}
	pc2 := &eCPoint{X: hx, Y: hy}

	// Storing the points for validation (make sure this is safe and synchronized if needed)
	validate["y1"] = pc1
	validate["y2"] = pc2

	y1, err = pc1.toBytes()
	if err != nil {
		return nil, nil, err
	}

	y2, err = pc2.toBytes()
	if err != nil {
		return nil, nil, err
	}

	return y1, y2, nil
}

// ProverCommitment generates random commitments r1 and r2 for the prover.
// It returns the X and Y coordinates directly as big.Ints along with the random value r.
func ProverCommitment() (r1, r2 []byte, r *big.Int, err error) {
	n := curve.Params().N
	r, err = rand.Int(rand.Reader, n)
	if err != nil {
		return nil, nil, nil, err
	}

	rx1, ry1 := curve.ScalarBaseMult(r.Bytes())
	rx2, ry2 := curve.ScalarMult(Hx, Hy, r.Bytes())

	// Check if the points are on the curve
	if !curve.IsOnCurve(rx1, ry1) || !curve.IsOnCurve(rx2, ry2) {
		return nil, nil, nil, errors.New("generated points are not on the curve")
	}

	rc1 := &eCPoint{X: rx1, Y: ry1}
	rc2 := &eCPoint{X: rx2, Y: ry2}
	validate["rc1"] = rc1
	validate["rc2"] = rc2
	bigIntValidator["r"] = r
	r1, _ = rc1.toBytes()
	r2, _ = rc2.toBytes()
	// No need for on-curve checks here because they are handled by the ScalarBaseMult and ScalarMult functions.
	return r1, r2, r, nil
}

// GenerateChallenge creates a challenge for the prover by hashing their commitments.
func GenerateChallenge(r1b, r2b []byte) *big.Int {
	rc1, _ := fromBytes(r1b)
	rc2, _ := fromBytes(r2b)
	rx1 := rc1.X
	ry1 := rc1.Y
	rx2 := rc2.X
	ry2 := rc2.Y

	rc1check := validate["rc1"]
	rc2check := validate["rc2"]
	if rc1check.X.Cmp(rc1.X) != 0 || rc1check.Y.Cmp(rc1.Y) != 0 || rc2check.X.Cmp(rc2.X) != 0 || rc2check.Y.Cmp(rc2.Y) != 0 {
		fmt.Println("GenerateChallenge rc check failed")
	}
	// A simple challenge generation using hash of r1 and r2 (This is just an example)
	hash := sha256.New()
	hash.Write(rx1.Bytes())
	hash.Write(ry1.Bytes())
	hash.Write(rx2.Bytes())
	hash.Write(ry2.Bytes())
	hashed := hash.Sum(nil)

	c := new(big.Int).SetBytes(hashed)
	// Ensure that the challenge c is within the order of the curve
	c.Mod(c, curve.Params().N)
	bigIntValidator["c"] = c
	return c
}

// SolveChallenge generates the prover's response s to the verifier's challenge c. (response Step)
func SolveChallenge(secret, r, c *big.Int) (*big.Int, error) {
	n := curve.Params().N // Order of the curve

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

	bigIntValidator["s"] = s
	return s, nil
}

func Verify(y1b, y2b, r1b, r2b []byte, s, c *big.Int) bool {
	y1, _ := fromBytes(y1b)  // Deserializes to point y1 on the curve
	y2, _ := fromBytes(y2b)  // Deserializes to point y2 on the curve
	rc1, _ := fromBytes(r1b) // Deserializes to point rc1 on the curve
	rc2, _ := fromBytes(r2b) // Deserializes to point rc2 on the curve

	y1v := validate["y1"]
	y2v := validate["y2"]
	rc1v := validate["rc1"]
	rc2v := validate["rc2"]
	if y1.X.Cmp(y1v.X) != 0 || y1.Y.Cmp(y1v.Y) != 0 || y2.X.Cmp(y2v.X) != 0 || y2.Y.Cmp(y2v.Y) != 0 {
		fmt.Println("Verify y check failed")
	}
	if rc1.X.Cmp(rc1v.X) != 0 || rc1.Y.Cmp(rc1v.Y) != 0 || rc2.X.Cmp(rc2v.X) != 0 || rc2.Y.Cmp(rc2v.Y) != 0 {
		fmt.Println("Verify rc check failed")
	}

	sv := bigIntValidator["s"]
	cv := bigIntValidator["c"]
	if s.Cmp(sv) != 0 || c.Cmp(cv) != 0 {
		fmt.Println("Verify s and c failed")
	}

	// Check if provided points are on the curve
	if !curve.IsOnCurve(y1.X, y1.Y) || !curve.IsOnCurve(y2.X, y2.Y) ||
		!curve.IsOnCurve(rc1.X, rc1.Y) || !curve.IsOnCurve(rc2.X, rc2.Y) {
		return false // If any point is not on the curve, verification fails
	}

	// Compute g^s
	gsx, gsy := curve.ScalarBaseMult(s.Bytes())

	// Compute y1^c
	y1cx, y1cy := curve.ScalarMult(y1.X, y1.Y, c.Bytes())

	// Compute r1 = g^s * y1^c (Addition on the elliptic curve)
	r1ComputedX, r1ComputedY := curve.Add(gsx, gsy, y1cx, y1cy)

	// Compute h^s using y2's X and Y coordinates (since y2 is the commitment of H)
	hsx, hsy := curve.ScalarMult(y2.X, y2.Y, s.Bytes())

	// Compute y2^c
	y2cx, y2cy := curve.ScalarMult(y2.X, y2.Y, c.Bytes())

	// Compute r2 = h^s * y2^c (Addition on the elliptic curve)
	r2ComputedX, r2ComputedY := curve.Add(hsx, hsy, y2cx, y2cy)

	// Compare the computed r1 and r2 with the provided commitments rc1 and rc2
	z1 := r1ComputedX.Cmp(rc1.X)
	z2 := r1ComputedY.Cmp(rc1.Y)
	z3 := r2ComputedX.Cmp(rc2.X)
	z4 := r2ComputedY.Cmp(rc2.Y)

	return z1 == 0 && z2 == 0 && z3 == 0 && z4 == 0
	//return r1ComputedX.Cmp(rc1.X) == 0 && r1ComputedY.Cmp(rc1.Y) == 0 &&
	//	r2ComputedX.Cmp(rc2.X) == 0 && r2ComputedY.Cmp(rc2.Y) == 0
}

func Verify2(y1b, y2b, r1b, r2b []byte, s, c *big.Int) bool {
	y1, _ := fromBytes(y1b)  // Deserializes to point y1 on the curve
	y2, _ := fromBytes(y2b)  // Deserializes to point y2 on the curve
	rc1, _ := fromBytes(r1b) // Deserializes to point rc1 on the curve
	rc2, _ := fromBytes(r2b) // Deserializes to point rc2 on the curve

	// Check if provided points are on the curve
	if !curve.IsOnCurve(y1.X, y1.Y) || !curve.IsOnCurve(y2.X, y2.Y) ||
		!curve.IsOnCurve(rc1.X, rc1.Y) || !curve.IsOnCurve(rc2.X, rc2.Y) {
		return false // If any point is not on the curve, verification fails
	}

	// Compute g^s
	gsx, gsy := curve.ScalarBaseMult(s.Bytes())

	// Compute y1^c
	y1cx, y1cy := curve.ScalarMult(y1.X, y1.Y, c.Bytes())

	// Compute the point (g^s) * (y1^c)
	r1ComputedX, r1ComputedY := curve.Add(gsx, gsy, y1cx, y1cy)

	// Compute h^s using the y2's X and Y coordinates
	hsx, hsy := curve.ScalarMult(y2.X, y2.Y, s.Bytes())

	// Compute y2^c
	y2cx, y2cy := curve.ScalarMult(y2.X, y2.Y, c.Bytes())

	// Compute the point (h^s) * (y2^c)
	r2ComputedX, r2ComputedY := curve.Add(hsx, hsy, y2cx, y2cy)

	//
	//// Compute g^s
	//gsx, gsy := curve.ScalarBaseMult(s.Bytes())
	//
	//// Compute y1^-c (i.e., y1 to the power of -c mod n)
	//n := curve.Params().N
	//minusC := new(big.Int).Neg(c)
	//minusC.Mod(minusC, n)
	//y1cx, y1cy := curve.ScalarMult(y1.X, y1.Y, minusC.Bytes())
	//
	//// Compute r1 = g^s * y1^-c
	//r1ComputedX, r1ComputedY := curve.Add(gsx, gsy, y1cx, y1cy)
	//
	//// Similarly for r2, h^s * y2^-c
	//hsx, hsy := curve.ScalarMult(Hx, Hy, s.Bytes()) // Corrected to use H instead of y2
	//y2cx, y2cy := curve.ScalarMult(y2.X, y2.Y, minusC.Bytes())
	//
	//// Compute r2 = h^s * y2^-c
	//r2ComputedX, r2ComputedY := curve.Add(hsx, hsy, y2cx, y2cy)

	// Compare the computed r1 and r2 with the provided commitments rc1 and rc2
	return r1ComputedX.Cmp(rc1.X) == 0 && r1ComputedY.Cmp(rc1.Y) == 0 &&
		r2ComputedX.Cmp(rc2.X) == 0 && r2ComputedY.Cmp(rc2.Y) == 0
}
