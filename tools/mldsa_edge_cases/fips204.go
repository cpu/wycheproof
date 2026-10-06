package main

import (
	"crypto/sha3"
	"encoding/binary"
	"fmt"
)

const fipsN = 256

type fipsPoly [fipsN]int64

type fipsKey struct {
	p      parameters
	a      []fipsPoly
	s1     []fipsPoly
	s2     []fipsPoly
	t0     []fipsPoly
	secret [32]byte
	tr     [64]byte
	public []byte

	powerPositive int
	powerNegative int
}

var fipsZetas = func() [fipsN]int64 {
	var z [fipsN]int64
	for i := 1; i < fipsN; i++ {
		z[i] = fipsPow(1753, uint64(reverseByte(byte(i))))
	}
	return z
}()

func reverseByte(x byte) byte {
	x = x>>4 | x<<4
	x = (x>>2)&0x33 | (x&0x33)<<2
	x = (x>>1)&0x55 | (x&0x55)<<1
	return x
}

func fipsMod(x int64) int64 {
	x %= q
	if x < 0 {
		x += q
	}
	return x
}

func fipsPow(x int64, n uint64) int64 {
	r := int64(1)
	for n != 0 {
		if n&1 != 0 {
			r = fipsMod(r * x)
		}
		x = fipsMod(x * x)
		n >>= 1
	}
	return r
}

func fipsCentered(x int64) int64 {
	x = fipsMod(x)
	if x > q/2 {
		x -= q
	}
	return x
}

// fipsNTT and fipsInverseNTT implement FIPS 204 Algorithms 41 and 42 with
// ordinary modular arithmetic rather than Montgomery representation.
func fipsNTT(a fipsPoly) fipsPoly {
	k := 0
	for length := 128; length >= 1; length >>= 1 {
		for start := 0; start < fipsN; start += 2 * length {
			k++
			zeta := fipsZetas[k]
			for j := start; j < start+length; j++ {
				t := fipsMod(zeta * a[j+length])
				a[j+length] = fipsMod(a[j] - t)
				a[j] = fipsMod(a[j] + t)
			}
		}
	}
	return a
}

func fipsInverseNTT(a fipsPoly) fipsPoly {
	k := 256
	for length := 1; length < fipsN; length <<= 1 {
		for start := 0; start < fipsN; start += 2 * length {
			k--
			zeta := fipsZetas[k]
			for j := start; j < start+length; j++ {
				t := a[j]
				a[j] = fipsMod(t + a[j+length])
				a[j+length] = fipsMod(zeta * (a[j+length] - t))
			}
		}
	}
	invN := fipsPow(fipsN, q-2)
	for i := range a {
		a[i] = fipsMod(a[i] * invN)
	}
	return a
}

func fipsPointwise(a, b fipsPoly) (out fipsPoly) {
	for i := range out {
		out[i] = fipsMod(a[i] * b[i])
	}
	return out
}

func fipsAdd(a, b fipsPoly) (out fipsPoly) {
	for i := range out {
		out[i] = fipsMod(a[i] + b[i])
	}
	return out
}

func fipsSub(a, b fipsPoly) (out fipsPoly) {
	for i := range out {
		out[i] = fipsMod(a[i] - b[i])
	}
	return out
}

func fipsSampleNTT(rho []byte, s, r byte) fipsPoly {
	h := sha3.NewSHAKE128()
	h.Write(rho)
	h.Write([]byte{s, r})
	var out fipsPoly
	var buf [168]byte
	off := len(buf)
	for i := 0; i < fipsN; {
		if off+3 > len(buf) {
			h.Read(buf[:])
			off = 0
		}
		v := int64(buf[off]) | int64(buf[off+1])<<8 | int64(buf[off+2])<<16
		off += 3
		v &= 0x7f_ffff
		if v < q {
			out[i] = v
			i++
		}
	}
	return out
}

func fipsSampleBounded(rho []byte, nonce uint16, eta int) fipsPoly {
	h := sha3.NewSHAKE256()
	h.Write(rho)
	var n [2]byte
	binary.LittleEndian.PutUint16(n[:], nonce)
	h.Write(n[:])
	var out fipsPoly
	var buf [136]byte
	off := len(buf)
	for i := 0; i < fipsN; {
		if off == len(buf) {
			h.Read(buf[:])
			off = 0
		}
		b := buf[off]
		off++
		for _, nibble := range []byte{b & 0x0f, b >> 4} {
			var value int
			var ok bool
			switch eta {
			case 2:
				ok = nibble < 15
				value = 2 - int(nibble%5)
			case 4:
				ok = nibble < 9
				value = 4 - int(nibble)
			}
			if ok {
				out[i] = fipsMod(int64(value))
				i++
				if i == fipsN {
					break
				}
			}
		}
	}
	return out
}

func fipsPower2Round(x int64) (hi int64, lo int64) {
	x = fipsMod(x)
	hi = (x + (1 << 12) - 1) >> 13
	lo = fipsCentered(x - hi*(1<<13))
	return hi, lo
}

func fipsNewKey(seed [32]byte, p parameters) *fipsKey {
	input := append(seed[:], byte(p.k), byte(p.l))
	expanded := sha3.SumSHAKE256(input, 128)
	rho, rhoPrime := expanded[:32], expanded[32:96]

	key := &fipsKey{p: p}
	copy(key.secret[:], expanded[96:128])
	key.a = make([]fipsPoly, p.k*p.l)
	for r := range p.k {
		for s := range p.l {
			key.a[r*p.l+s] = fipsSampleNTT(rho, byte(s), byte(r))
		}
	}
	key.s1 = make([]fipsPoly, p.l)
	for i := range key.s1 {
		key.s1[i] = fipsNTT(fipsSampleBounded(rhoPrime, uint16(i), p.eta))
	}
	key.s2 = make([]fipsPoly, p.k)
	for i := range key.s2 {
		key.s2[i] = fipsNTT(fipsSampleBounded(rhoPrime, uint16(p.l+i), p.eta))
	}

	t1 := make([][fipsN]uint16, p.k)
	key.t0 = make([]fipsPoly, p.k)
	for i := range p.k {
		tHat := key.s2[i]
		for j := range p.l {
			tHat = fipsAdd(tHat, fipsPointwise(key.a[i*p.l+j], key.s1[j]))
		}
		t := fipsInverseNTT(tHat)
		var t0 fipsPoly
		for j := range t {
			hi, lo := fipsPower2Round(t[j])
			if lo == 4096 {
				key.powerPositive++
			}
			if lo == -4095 {
				key.powerNegative++
			}
			t1[i][j] = uint16(hi)
			t0[j] = fipsMod(lo)
		}
		key.t0[i] = fipsNTT(t0)
	}

	pk := fipsEncodePublicKey(rho, t1)
	key.public = pk
	copy(key.tr[:], sha3.SumSHAKE256(pk, 64))
	return key
}

func fipsEncodePublicKey(rho []byte, t1 [][fipsN]uint16) []byte {
	pk := append([]byte(nil), rho...)
	for _, poly := range t1 {
		for i := 0; i < fipsN; i += 4 {
			c0, c1 := poly[i], poly[i+1]
			c2, c3 := poly[i+2], poly[i+3]
			pk = append(pk,
				byte(c0),
				byte(c0>>8|c1<<2),
				byte(c1>>6|c2<<4),
				byte(c2>>4|c3<<6),
				byte(c3>>2))
		}
	}
	return pk
}

func fipsMessageHash(tr [64]byte, message []byte) [64]byte {
	h := sha3.NewSHAKE256()
	h.Write(tr[:])
	h.Write([]byte{0, 0}) // Pure ML-DSA with an empty context.
	h.Write(message)
	var mu [64]byte
	h.Read(mu[:])
	return mu
}

func fipsExpandMask(seed []byte, nonce uint16, p parameters) fipsPoly {
	h := sha3.NewSHAKE256()
	h.Write(seed)
	var n [2]byte
	binary.LittleEndian.PutUint16(n[:], nonce)
	h.Write(n[:])
	width := p.gamma1 + 1
	buf := make([]byte, width*fipsN/8)
	h.Read(buf)

	var out fipsPoly
	var accumulator uint64
	var bits uint
	off := 0
	mask := uint64(1<<width) - 1
	for i := range out {
		for bits < uint(width) {
			accumulator |= uint64(buf[off]) << bits
			bits += 8
			off++
		}
		value := accumulator & mask
		accumulator >>= width
		bits -= uint(width)
		out[i] = fipsMod(int64(1<<p.gamma1) - int64(value))
	}
	return out
}

func fipsDecompose(x int64, p parameters) (hi, lo int64) {
	x = fipsMod(x)
	alpha := int64(2 * ((q - 1) / p.gamma2Den))
	lo = x % alpha
	if lo > alpha/2 {
		lo -= alpha
	}
	if x-lo == q-1 {
		return 0, lo - 1
	}
	return (x - lo) / alpha, lo
}

func fipsHighBits(poly fipsPoly, p parameters) (out [fipsN]byte) {
	for i := range poly {
		hi, _ := fipsDecompose(poly[i], p)
		out[i] = byte(hi)
	}
	return out
}

func fipsWriteW1(h *sha3.SHAKE, w [fipsN]byte, p parameters) {
	if p.gamma2Den == 32 {
		buf := make([]byte, fipsN/2)
		for i := 0; i < fipsN; i += 2 {
			buf[i/2] = w[i] | w[i+1]<<4
		}
		h.Write(buf)
		return
	}
	buf := make([]byte, 3*fipsN/4)
	for i := 0; i < fipsN; i += 4 {
		buf[3*i/4] = w[i] | w[i+1]<<6
		buf[3*i/4+1] = w[i+1]>>2 | w[i+2]<<4
		buf[3*i/4+2] = w[i+2]>>4 | w[i+3]<<2
	}
	h.Write(buf)
}

func fipsSampleInBall(challenge []byte, p parameters) (fipsPoly, int) {
	h := sha3.NewSHAKE256()
	h.Write(challenge)
	var signs [8]byte
	h.Read(signs[:])
	consumed := 8
	var c fipsPoly
	var candidate [1]byte
	for i := fipsN - p.tau; i < fipsN; i++ {
		for {
			h.Read(candidate[:])
			consumed++
			if int(candidate[0]) <= i {
				break
			}
		}
		j := int(candidate[0])
		c[i] = c[j]
		bit := i + p.tau - fipsN
		if signs[bit/8]&(1<<uint(bit%8)) == 0 {
			c[j] = 1
		} else {
			c[j] = q - 1
		}
	}
	return c, consumed
}

func fipsExceeds(poly fipsPoly, bound int64) bool {
	for _, coefficient := range poly {
		v := fipsCentered(coefficient)
		if v < 0 {
			v = -v
		}
		if v >= bound {
			return true
		}
	}
	return false
}

func fipsLowBitsExceed(poly fipsPoly, bound int64, p parameters) bool {
	for _, coefficient := range poly {
		_, lo := fipsDecompose(coefficient, p)
		if lo < 0 {
			lo = -lo
		}
		if lo >= bound {
			return true
		}
	}
	return false
}

func (key *fipsKey) challenge(message []byte) ([]byte, int, error) {
	p := key.p
	mu := fipsMessageHash(key.tr, message)
	h := sha3.NewSHAKE256()
	h.Write(key.secret[:])
	h.Write(make([]byte, 32)) // Deterministic signing uses rnd = 0^32.
	h.Write(mu[:])
	var rhoPrimePrime [64]byte
	h.Read(rhoPrimePrime[:])

	beta := int64(p.tau * p.eta)
	gamma1 := int64(1 << p.gamma1)
	gamma2 := int64((q - 1) / p.gamma2Den)
	kappa := 0
	for attempts := 0; attempts < 10_000; attempts++ {
		y := make([]fipsPoly, p.l)
		yHat := make([]fipsPoly, p.l)
		for i := range y {
			y[i] = fipsExpandMask(rhoPrimePrime[:], uint16(kappa), p)
			yHat[i] = fipsNTT(y[i])
			kappa++
		}

		w := make([]fipsPoly, p.k)
		for i := range w {
			var wHat fipsPoly
			for j := range p.l {
				wHat = fipsAdd(wHat, fipsPointwise(key.a[i*p.l+j], yHat[j]))
			}
			w[i] = fipsInverseNTT(wHat)
		}

		h.Reset()
		h.Write(mu[:])
		for i := range w {
			fipsWriteW1(h, fipsHighBits(w[i], p), p)
		}
		challenge := make([]byte, p.lambda/4)
		h.Read(challenge)
		c, consumed := fipsSampleInBall(challenge, p)
		cHat := fipsNTT(c)

		cs1 := make([]fipsPoly, p.l)
		rejected := false
		for i := range cs1 {
			cs1[i] = fipsInverseNTT(fipsPointwise(cHat, key.s1[i]))
			if fipsExceeds(fipsAdd(y[i], cs1[i]), gamma1-beta) {
				rejected = true
				break
			}
		}
		if rejected {
			continue
		}

		cs2 := make([]fipsPoly, p.k)
		for i := range cs2 {
			cs2[i] = fipsInverseNTT(fipsPointwise(cHat, key.s2[i]))
			if fipsLowBitsExceed(fipsSub(w[i], cs2[i]), gamma2-beta, p) {
				rejected = true
				break
			}
		}
		if rejected {
			continue
		}

		ct0 := make([]fipsPoly, p.k)
		for i := range ct0 {
			ct0[i] = fipsInverseNTT(fipsPointwise(cHat, key.t0[i]))
			if fipsExceeds(ct0[i], gamma2) {
				rejected = true
				break
			}
		}
		if rejected {
			continue
		}

		hints := 0
		for i := range w {
			rPlusZ := fipsSub(w[i], cs2[i])
			for j := range rPlusZ {
				before, _ := fipsDecompose(rPlusZ[j], p)
				after, _ := fipsDecompose(rPlusZ[j]+ct0[i][j], p)
				if before != after {
					hints++
				}
			}
		}
		if hints > p.omega {
			continue
		}
		return challenge, consumed, nil
	}
	return nil, 0, fmt.Errorf("signing did not converge")
}
