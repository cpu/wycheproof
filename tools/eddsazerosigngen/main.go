// eddsazerosigngen generates EdDSA verification test vectors where R is the
// encoding of the point with x = 0 and y = 1 with the sign bit of x set.
// RFC 8032 point decoding must reject this encoding. S is computed with the
// private key so that a verifier whose decoder ignores the sign of x accepts
// the signature.
//
// The vectors are appended to testvectors_v1/ed25519_test.json and
// testvectors_v1/ed448_test.json as a new test group via the vectorgen
// library. Run from the repository root with GOEXPERIMENT=jsonv2.
package main

import (
	"bytes"
	"crypto/sha3"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"

	"github.com/c2sp/wycheproof/vectorgen"
)

func main() {
	for _, c := range []*curve{ed25519(), ed448()} {
		a, pk := c.deriveKey()
		if !bytes.Equal(pk, c.rfcPub) {
			log.Fatalf("%s: derived public key does not match RFC 8032", c.name)
		}
		msg := []byte("123400")

		r := make([]byte, c.encLen)
		r[0] = 1
		r[c.encLen-1] = 0x80

		k := c.hash(r, pk, msg)
		s := new(big.Int).Mul(k, a)
		s.Mod(s, c.order)
		sig := append(append([]byte{}, r...), c.encodeScalar(s)...)

		c.selfCheck(r, s, k, a)

		env := vectorgen.AddEnvelope{
			GroupTemplate: c.groupTemplate(pk),
			Tests:         []jsontext.Value{c.testObject(msg, sig)},
		}
		if err := vectorgen.Add(c.vectorFile, env, vectorgen.Options{}); err != nil {
			log.Fatalf("%s: %v", c.name, err)
		}
		log.Printf("%s: added 1 vector to %s", c.name, c.vectorFile)
	}
}

func (c *curve) testObject(msg, sig []byte) jsontext.Value {
	comment := fmt.Sprintf("R encodes y = 1 with the sign bit of x set. The only "+
		"point with y = 1 has x = 0, so decoding must fail (RFC 8032, Section "+
		"%s). Accepted only by verifiers that ignore the sign of x.", c.rfcSection)
	obj := vectorgen.RawObject{
		member("comment", comment),
		member("flags", []string{"InvalidEncoding"}),
		member("msg", hex.EncodeToString(msg)),
		member("sig", hex.EncodeToString(sig)),
		member("result", "invalid"),
	}
	return mustMarshal(&obj)
}

func (c *curve) groupTemplate(pk []byte) jsontext.Value {
	der := append(hexBytes(c.spkiPrefix), pk...)
	pubKey := vectorgen.RawObject{
		member("type", "EDDSAPublicKey"),
		member("curve", c.curveName),
		member("keySize", c.keySize),
		member("pk", hex.EncodeToString(pk)),
	}
	source := vectorgen.RawObject{
		member("name", "github/cpu/eddsazerosigngen"),
		member("version", "1.0"),
	}
	jwk := vectorgen.RawObject{
		member("kty", "OKP"),
		member("crv", c.jwkCrv),
		member("kid", "none"),
		member("x", base64.RawURLEncoding.EncodeToString(pk)),
	}
	group := vectorgen.RawObject{
		member("type", "EddsaVerify"),
		member("source", &source),
		member("publicKey", &pubKey),
		member("publicKeyDer", hex.EncodeToString(der)),
		member("publicKeyPem", string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))),
		member("publicKeyJwk", &jwk),
	}
	return mustMarshal(&group)
}

func member(name string, v any) vectorgen.ObjectMember[jsontext.Value] {
	return vectorgen.ObjectMember[jsontext.Value]{Name: name, Value: mustMarshal(v)}
}

func mustMarshal(v any) jsontext.Value {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

type point struct {
	x, y *big.Int
}

type curve struct {
	name       string
	vectorFile string
	curveName  string
	jwkCrv     string
	spkiPrefix string
	rfcSection string
	keySize    int
	p          *big.Int
	order      *big.Int
	d          *big.Int
	a          *big.Int
	base       point
	encLen     int
	signBit    uint
	rfcSeed    []byte
	rfcPub     []byte
}

func ed25519() *curve {
	c := &curve{
		name:       "ed25519",
		vectorFile: "testvectors_v1/ed25519_test.json",
		curveName:  "edwards25519",
		jwkCrv:     "Ed25519",
		spkiPrefix: "302a300506032b6570032100",
		rfcSection: "5.1.3",
		keySize:    255,
		p:          bigInt("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed"),
		order:      bigInt("1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed"),
		base: point{
			x: bigInt("216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a"),
			y: bigInt("6666666666666666666666666666666666666666666666666666666666666658"),
		},
		encLen:  32,
		signBit: 255,
		rfcSeed: hexBytes("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"),
		rfcPub:  hexBytes("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"),
	}
	c.a = new(big.Int).Sub(c.p, big.NewInt(1))
	num := big.NewInt(-121665)
	den := big.NewInt(121666)
	c.d = new(big.Int).Mul(num.Mod(num, c.p), new(big.Int).ModInverse(den, c.p))
	c.d.Mod(c.d, c.p)
	return c
}

func ed448() *curve {
	c := &curve{
		name:       "ed448",
		vectorFile: "testvectors_v1/ed448_test.json",
		curveName:  "edwards448",
		jwkCrv:     "Ed448",
		spkiPrefix: "3043300506032b6571033a00",
		rfcSection: "5.2.3",
		keySize:    448,
		p:          bigInt("fffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
		order:      bigInt("3fffffffffffffffffffffffffffffffffffffffffffffffffffffff7cca23e9c44edb49aed63690216cc2728dc58f552378c292ab5844f3"),
		base: point{
			x: bigInt("4f1970c66bed0ded221d15a622bf36da9e146570470f1767ea6de324a3d3a46412ae1af72ab66511433b80e18b00938e2626a82bc70cc05e"),
			y: bigInt("693f46716eb6bc248876203756c9c7624bea73736ca3984087789c1e05a0c2d73ad3ff1ce67c39c4fdbd132c4ed7c8ad9808795bf230fa14"),
		},
		encLen:  57,
		signBit: 455,
		rfcSeed: hexBytes("6c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6e348a3528c8a3fcc2f044e39a3fc5b94492f8f032e7549a20098f95b"),
		rfcPub:  hexBytes("5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180"),
	}
	c.a = big.NewInt(1)
	c.d = big.NewInt(-39081)
	c.d.Mod(c.d, c.p)
	return c
}

func (c *curve) deriveKey() (*big.Int, []byte) {
	var buf []byte
	if c.name == "ed25519" {
		h := sha512.Sum512(c.rfcSeed)
		buf = h[:32]
		buf[0] &= 248
		buf[31] &= 127
		buf[31] |= 64
	} else {
		buf = shake256(c.rfcSeed, 114)[:57]
		buf[0] &= 252
		buf[56] = 0
		buf[55] |= 128
	}
	a := leInt(buf)
	A := c.smul(a, c.base)
	return a, c.encodePoint(A)
}

func (c *curve) hash(r, pk, msg []byte) *big.Int {
	var h []byte
	if c.name == "ed25519" {
		sum := sha512.Sum512(concat(r, pk, msg))
		h = sum[:]
	} else {
		dom := append([]byte("SigEd448"), 0, 0)
		h = shake256(concat(dom, r, pk, msg), 114)
	}
	return new(big.Int).Mod(leInt(h), c.order)
}

func (c *curve) selfCheck(r []byte, s, k, a *big.Int) {
	if _, err := c.decode(r, true); err == nil {
		log.Fatalf("%s: strict decoding accepted R", c.name)
	} else if err.Error() != "x is zero with sign bit set" {
		log.Fatalf("%s: strict decoding rejected R for the wrong reason: %v", c.name, err)
	}
	lenient, err := c.decode(r, false)
	if err != nil {
		log.Fatalf("%s: lenient decoding failed: %v", c.name, err)
	}
	if lenient.x.Sign() != 0 || lenient.y.Cmp(big.NewInt(1)) != 0 {
		log.Fatalf("%s: lenient decoding is not the neutral point", c.name)
	}
	A := c.smul(a, c.base)
	sB := c.smul(s, c.base)
	kA := c.smul(k, A)
	if sB.x.Cmp(kA.x) != 0 || sB.y.Cmp(kA.y) != 0 {
		log.Fatalf("%s: lenient verification equation does not hold", c.name)
	}
}

func (c *curve) decode(enc []byte, strict bool) (point, error) {
	y := leInt(enc)
	x0 := y.Bit(int(c.signBit))
	y.SetBit(y, int(c.signBit), 0)
	if y.Cmp(c.p) >= 0 {
		return point{}, fmt.Errorf("y out of range")
	}
	y2 := new(big.Int).Mul(y, y)
	num := new(big.Int).Sub(y2, big.NewInt(1))
	den := new(big.Int).Mul(c.d, y2)
	den.Sub(den, c.a)
	den.Mod(den, c.p)
	x2 := num.Mul(num, new(big.Int).ModInverse(den, c.p))
	x2.Mod(x2, c.p)
	x := new(big.Int).ModSqrt(x2, c.p)
	if x == nil {
		return point{}, fmt.Errorf("not on curve")
	}
	if x.Sign() == 0 && x0 == 1 {
		if strict {
			return point{}, fmt.Errorf("x is zero with sign bit set")
		}
	} else if x.Bit(0) != x0 {
		x.Sub(c.p, x)
	}
	return point{x, y}, nil
}

func (c *curve) encodePoint(P point) []byte {
	y := new(big.Int).Set(P.y)
	y.SetBit(y, int(c.signBit), uint(P.x.Bit(0)))
	return leBytes(y, c.encLen)
}

func (c *curve) encodeScalar(s *big.Int) []byte {
	return leBytes(s, c.encLen)
}

func (c *curve) add(P, Q point) point {
	t := new(big.Int).Mul(P.x, Q.x)
	t.Mul(t, P.y).Mul(t, Q.y).Mul(t, c.d).Mod(t, c.p)
	xnum := new(big.Int).Mul(P.x, Q.y)
	xnum.Add(xnum, new(big.Int).Mul(Q.x, P.y))
	xden := new(big.Int).Add(big.NewInt(1), t)
	ynum := new(big.Int).Mul(P.y, Q.y)
	ynum.Sub(ynum, new(big.Int).Mul(new(big.Int).Mul(c.a, P.x), Q.x))
	yden := new(big.Int).Sub(big.NewInt(1), t)
	x := xnum.Mul(xnum, new(big.Int).ModInverse(xden.Mod(xden, c.p), c.p))
	y := ynum.Mul(ynum, new(big.Int).ModInverse(yden.Mod(yden, c.p), c.p))
	return point{x.Mod(x, c.p), y.Mod(y, c.p)}
}

func (c *curve) smul(k *big.Int, P point) point {
	R := point{big.NewInt(0), big.NewInt(1)}
	for i := k.BitLen() - 1; i >= 0; i-- {
		R = c.add(R, R)
		if k.Bit(i) == 1 {
			R = c.add(R, P)
		}
	}
	return R
}

func shake256(data []byte, n int) []byte {
	h := sha3.NewSHAKE256()
	h.Write(data)
	out := make([]byte, n)
	h.Read(out)
	return out
}

func concat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func leInt(b []byte) *big.Int {
	rev := make([]byte, len(b))
	for i, v := range b {
		rev[len(b)-1-i] = v
	}
	return new(big.Int).SetBytes(rev)
}

func leBytes(v *big.Int, n int) []byte {
	b := v.Bytes()
	out := make([]byte, n)
	for i, x := range b {
		out[len(b)-1-i] = x
	}
	return out
}

func bigInt(hexStr string) *big.Int {
	v, ok := new(big.Int).SetString(hexStr, 16)
	if !ok {
		panic("bad constant")
	}
	return v
}

func hexBytes(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}
