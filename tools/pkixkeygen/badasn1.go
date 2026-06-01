package main

import (
	"fmt"

	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// rewrapOuter strips the outer tag and length octets from a TLV and returns
// the body. Used by outer-DER mutation cases that rewrap a known-good payload
// with a malformed outer length encoding.
func rewrapOuter(der []byte) []byte {
	l := der[1]
	lenOctets := 1
	if l&0x80 != 0 {
		lenOctets += int(l & 0x7f)
	}
	return der[1+lenOctets:]
}

// rawTLV emits a tag-length-value triple, with the length encoded per the
// chosen lengthMode. The declared length is len(body)+lenDelta.
// lenDelta lets cases declare a length that doesn't match the actual body
// length, which is how the over/under-declared-length tests are built.
func rawTLV(tag cbasn1.Tag, body []byte, mode lengthMode, lenDelta int) []byte {
	declared := len(body) + lenDelta
	out := []byte{byte(tag)}
	switch mode {
	case lengthShortest:
		out = append(out, shortestLength(declared)...)
		out = append(out, body...)
	case lengthLongForm1:
		out = append(out, 0x81, byte(declared))
		out = append(out, body...)
	case lengthLongForm2:
		out = append(out, 0x82, byte(declared>>8), byte(declared))
		out = append(out, body...)
	case lengthLongForm3:
		out = append(out, 0x83, byte(declared>>16), byte(declared>>8), byte(declared))
		out = append(out, body...)
	case lengthIndefinite:
		out = append(out, 0x80)
		out = append(out, body...)
		out = append(out, 0x00, 0x00)
	case lengthReservedFF:
		out = append(out, 0xff)
		out = append(out, body...)
	case lengthOverflow:
		// 4-octet long form declaring a length larger than any plausible
		// buffer. Parsers that don't bound-check this can be tricked into
		// reading past the end or allocating absurd buffers.
		out = append(out, 0x84, 0xff, 0xff, 0xff, 0xff)
		out = append(out, body...)
	default:
		panic(fmt.Sprintf("unknown LengthMode %d", mode))
	}
	return out
}

// shortestLength encodes n in the shortest valid DER length form.
func shortestLength(n int) []byte {
	switch {
	case n < 0:
		panic(fmt.Sprintf("negative length %d", n))
	case n < 0x80:
		return []byte{byte(n)}
	case n < 0x100:
		return []byte{0x81, byte(n)}
	case n < 0x10000:
		return []byte{0x82, byte(n >> 8), byte(n)}
	case n < 0x1000000:
		return []byte{0x83, byte(n >> 16), byte(n >> 8), byte(n)}
	default:
		return []byte{0x84, byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
	}
}

// lengthMode controls how a TLV's length octets are encoded. Used by
// rawTLV to produce length encodings that aren't shortest-form DER, in
// order to test parser leniency / strictness around BER acceptance.
type lengthMode int

const (
	// lengthShortest uses the shortest valid DER length encoding for the
	// supplied (possibly delta-adjusted) declared length.
	lengthShortest lengthMode = iota
	// lengthLongForm1 forces 1-octet long form: 0x81 ll. Non-minimal
	// (and therefore invalid DER) when the declared length is < 128.
	lengthLongForm1
	// lengthLongForm2 forces 2-octet long form: 0x82 hh ll. Non-minimal
	// for any declared length < 256.
	lengthLongForm2
	// lengthLongForm3 forces 3-octet long form: 0x83 hh mm ll. Non-minimal
	// for any declared length < 0x10000.
	lengthLongForm3
	// lengthIndefinite emits 0x80 as the length byte and appends an EOC
	// 0x00 0x00 sentinel after the body. Legal BER, illegal DER.
	lengthIndefinite
	// lengthReservedFF emits 0xff as the length byte. X.690 8.1.3.5
	// reserves this value; it is illegal in both DER and BER.
	lengthReservedFF
	// lengthOverflow emits a 4-octet long-form length of 0xffffffff,
	// far larger than any plausible body. Tests bound-checking on the
	// declared length.
	lengthOverflow
)
