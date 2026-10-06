// mldsa_edge_cases regenerates matching ML-DSA signing and verification
// vectors that exercise edge cases in FIPS 204 internals.
//
// The original vectors were searched with SHAKE256(xi), the pre-FIPS key
// derivation. FIPS 204 derives rho and rhoPrime from
// SHAKE256(xi || IntegerToBytes(k, 1) || IntegerToBytes(l, 1), 128), so the
// original seeds no longer exercised the properties in their comments.
//
// Requires OpenSSL 3.5 or newer when -write is used. OpenSSL is deliberately
// used only after the seed search, to generate and verify the deterministic
// key and signature material independently of the sampling code below.
package main

import (
	"bytes"
	"crypto/sha3"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"github.com/c2sp/wycheproof/vectorgen"
)

const (
	shake128Rate  = 168
	shake256Rate  = 136
	q             = 8_380_417
	message       = "Hello world"
	vectorSource  = "github/cpu/mldsa-edge-cases"
	legacySource  = "github/cpu/mldsa-seed-expansion"
	vectorVersion = "1.0"
	gendxSource   = "github/gendx"
	gendxVersion  = "0.1"
)

type parameters struct {
	level      int
	k          int
	l          int
	eta        int
	gamma1     int
	gamma2Den  int
	lambda     int
	tau        int
	omega      int
	publicLen  int
	privateLen int
	sigLen     int
	oidLast    byte
	verifyOff  int
}

var parameterSets = []parameters{
	{level: 44, k: 4, l: 4, eta: 2, gamma1: 17, gamma2Den: 88, lambda: 128, tau: 39, omega: 80, publicLen: 1312, privateLen: 2560, sigLen: 2420, oidLast: 17, verifyOff: 15},
	{level: 65, k: 6, l: 5, eta: 4, gamma1: 19, gamma2Den: 32, lambda: 192, tau: 49, omega: 55, publicLen: 1952, privateLen: 4032, sigLen: 3309, oidLast: 18, verifyOff: 16},
	{level: 87, k: 8, l: 7, eta: 2, gamma1: 19, gamma2Den: 32, lambda: 256, tau: 60, omega: 75, publicLen: 2592, privateLen: 4896, sigLen: 4627, oidLast: 19, verifyOff: 18},
}

type metricKind int

const (
	aMax metricKind = iota
	aBytes
	sMax
	sBytes
	sBlocks
	sampleInBallBytes
	power2RoundPositive
	power2RoundNegative
	power2RoundBoth
)

func (m metricKind) String() string {
	switch m {
	case aMax:
		return "ExpandA maximum bytes"
	case aBytes:
		return "ExpandA total bytes"
	case sMax:
		return "ExpandS maximum bytes"
	case sBytes:
		return "ExpandS total bytes"
	case sBlocks:
		return "ExpandS rate blocks"
	case sampleInBallBytes:
		return "SampleInBall bytes"
	case power2RoundPositive:
		return "Power2Round +4096 occurrences"
	case power2RoundNegative:
		return "Power2Round -4095 occurrences"
	case power2RoundBoth:
		return "Power2Round edge pairs"
	default:
		return fmt.Sprintf("metricKind(%d)", m)
	}
}

type target struct {
	tcIDs        []int
	kind         metricKind
	want         int
	start        uint64
	fixedSeed    *uint64
	fixedMessage *uint64
	requireS1    bool
	verifyTCIDs  []int
}

func counter(n uint64) *uint64 { return &n }

// Targets retain the existing tcIds and their advertised edge cases.
var targets = map[int][]target{
	44: {
		{tcIDs: []int{41}, verifyTCIDs: []int{55}, kind: sampleInBallBytes, want: 61, fixedMessage: counter(0x3ea5)},
		{tcIDs: []int{57}, kind: aMax, want: 783},
		{tcIDs: []int{58}, kind: aBytes, want: 12_330},
		{tcIDs: []int{59}, kind: sBlocks, want: 16},
		{tcIDs: []int{60}, kind: sMax, want: 149},
		{tcIDs: []int{61}, kind: sBytes, want: 1_125},
		{tcIDs: []int{62}, kind: power2RoundPositive, want: 1, start: 2},
		{tcIDs: []int{63}, kind: power2RoundNegative, want: 1},
	},
	65: {
		{tcIDs: []int{45}, verifyTCIDs: []int{60}, kind: sampleInBallBytes, want: 76, fixedMessage: counter(0x3a93)},
		{tcIDs: []int{60}, kind: aMax, want: 783},
		{tcIDs: []int{61}, kind: aBytes, want: 23_103},
		{tcIDs: []int{62, 63}, kind: sBlocks, want: 23, requireS1: true},
		// Keep the exact-byte case distinct from the rate-block case.
		{tcIDs: []int{64}, kind: sMax, want: 277, start: 0x1f1f7, requireS1: true},
		{tcIDs: []int{65}, kind: sBytes, want: 2_649},
		{tcIDs: []int{66, 67}, kind: power2RoundBoth, want: 1},
	},
	87: {
		{tcIDs: []int{36}, verifyTCIDs: []int{53}, kind: sampleInBallBytes, want: 91, fixedMessage: counter(0x36a5)},
		{tcIDs: []int{53}, kind: aMax, want: 783},
		{tcIDs: []int{54}, kind: aBytes, want: 43_101},
		{tcIDs: []int{55}, kind: sBlocks, want: 30},
		{tcIDs: []int{56}, kind: sMax, want: 149},
		{tcIDs: []int{57}, kind: sBytes, want: 2_093},
		{tcIDs: []int{58}, kind: power2RoundNegative, want: 1},
	},
}

type metrics struct {
	aMax, aBytes, aBlocks int
	sMax, sBytes, sBlocks int
	s1Max                 int
	ballBytes             int
	powerPositive         int
	powerNegative         int
}

func (m metrics) value(kind metricKind) int {
	switch kind {
	case aMax:
		return m.aMax
	case aBytes:
		return m.aBytes
	case sMax:
		return m.sMax
	case sBytes:
		return m.sBytes
	case sBlocks:
		return m.sBlocks
	case sampleInBallBytes:
		return m.ballBytes
	case power2RoundPositive:
		return min(m.powerPositive, 1)
	case power2RoundNegative:
		return min(m.powerNegative, 1)
	case power2RoundBoth:
		return min(m.powerPositive, m.powerNegative, 1)
	default:
		panic("unreachable")
	}
}

type foundTarget struct {
	target
	seed    [32]byte
	message []byte
	metrics metrics
}

type vectorFile struct {
	Algorithm     string           `json:"algorithm"`
	Header        []string         `json:"header"`
	Notes         jsontext.Value   `json:"notes"`
	NumberOfTests int              `json:"numberOfTests"`
	Schema        string           `json:"schema"`
	TestGroups    []jsontext.Value `json:"testGroups"`
}

type testGroup struct {
	Type            string  `json:"type"`
	PrivateSeed     string  `json:"privateSeed"`
	PrivateKeyPKCS8 *string `json:"privateKeyPkcs8,omitzero"`
	PublicKey       *string `json:"publicKey"`
	Source          source  `json:"source"`
	Tests           []test  `json:"tests"`
}

type noseedGroup struct {
	Type       string  `json:"type"`
	PrivateKey string  `json:"privateKey"`
	PublicKey  *string `json:"publicKey"`
	Source     source  `json:"source"`
	Tests      []test  `json:"tests"`
}

type verifyGroup struct {
	Type         string `json:"type"`
	PublicKey    string `json:"publicKey"`
	PublicKeyDER string `json:"publicKeyDer"`
	Source       source `json:"source"`
	Tests        []test `json:"tests"`
}

type source struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type test struct {
	TCID    int      `json:"tcId"`
	Comment string   `json:"comment"`
	Msg     *string  `json:"msg,omitzero"`
	Ctx     *string  `json:"ctx,omitzero"`
	Rnd     *string  `json:"rnd,omitzero"`
	Mu      *string  `json:"mu,omitzero"`
	Sig     string   `json:"sig"`
	Result  string   `json:"result"`
	Flags   []string `json:"flags"`
}

type generatedMaterial struct {
	seedHex      string
	messageHex   string
	pkcs8Hex     string
	privateHex   string
	publicHex    string
	publicDERHex string
	muHex        string
	sigHex       string
}

type materialKey struct {
	seed    [32]byte
	message string
}

func (f foundTarget) materialKey() materialKey {
	return materialKey{seed: f.seed, message: string(f.message)}
}

func main() {
	write := flag.Bool("write", false, "write regenerated vectors in place")
	vectorsDir := flag.String("vectors", "testvectors_v1", "test-vector directory")
	schemasDir := flag.String("schemas", "schemas", "schema directory")
	openssl := flag.String("openssl", "openssl", "OpenSSL executable (3.5 or newer)")
	searchLimit := flag.Uint64("search-limit", 10_000_000, "maximum counter seed examined per target")
	flag.Parse()

	for _, p := range parameterSets {
		found, err := searchTargets(p, targets[p.level], *searchLimit)
		if err != nil {
			fatalf("ML-DSA-%d: %v", p.level, err)
		}
		for _, f := range found {
			fmt.Printf("ML-DSA-%d tcIds %v: seed=%s; %s=%d\n",
				p.level, f.tcIDs, hex.EncodeToString(f.seed[:]), f.kind, f.metrics.value(f.kind))
			if f.kind == sampleInBallBytes {
				fmt.Printf("  message=%s\n", hex.EncodeToString(f.message))
			}
		}
		if !*write {
			continue
		}

		seedPath := filepath.Join(*vectorsDir, fmt.Sprintf("mldsa_%d_sign_seed_test.json", p.level))
		materials, err := regenerateSeedFile(seedPath, *schemasDir, *openssl, p, found)
		if err != nil {
			fatalf("ML-DSA-%d: %v", p.level, err)
		}
		noseedPath := filepath.Join(*vectorsDir, fmt.Sprintf("mldsa_%d_sign_noseed_test.json", p.level))
		if err := regenerateNoseedFile(noseedPath, *schemasDir, p, found, materials); err != nil {
			fatalf("ML-DSA-%d: %v", p.level, err)
		}
		verifyPath := filepath.Join(*vectorsDir, fmt.Sprintf("mldsa_%d_verify_test.json", p.level))
		if err := regenerateVerifyFile(verifyPath, *schemasDir, p, found, materials); err != nil {
			fatalf("ML-DSA-%d: %v", p.level, err)
		}
	}
}

func searchTargets(p parameters, wanted []target, limit uint64) ([]foundTarget, error) {
	result := make([]foundTarget, len(wanted))
	errs := make(chan error, len(wanted))
	var wg sync.WaitGroup
	for i, t := range wanted {
		wg.Add(1)
		go func() {
			defer wg.Done()
			found, err := searchTarget(p, t, limit)
			if err != nil {
				errs <- err
				return
			}
			result[i] = found
		}()
	}
	wg.Wait()
	close(errs)
	if err := <-errs; err != nil {
		return nil, err
	}
	seenSeeds := make(map[[32]byte][]int)
	for _, found := range result {
		if ids, ok := seenSeeds[found.seed]; ok {
			return nil, fmt.Errorf("tcIds %v and %v selected the same seed", ids, found.tcIDs)
		}
		seenSeeds[found.seed] = found.tcIDs
	}
	return result, nil
}

func searchTarget(p parameters, t target, limit uint64) (foundTarget, error) {
	if t.kind == sampleInBallBytes {
		var seed [32]byte
		for i := range seed {
			seed[i] = 0x2a
		}
		key := fipsNewKey(seed, p)
		if t.fixedMessage != nil {
			message := seedFromCounter(*t.fixedMessage)
			_, consumed, err := key.challenge(message[:])
			if err != nil {
				return foundTarget{}, err
			}
			if consumed != t.want {
				return foundTarget{}, fmt.Errorf("fixed message %x gives %s=%d, want %d",
					*t.fixedMessage, t.kind, consumed, t.want)
			}
			return foundTarget{
				target: t, seed: seed, message: slices.Clone(message[:]),
				metrics: metrics{ballBytes: consumed},
			}, nil
		}
		for n := t.start; n < limit; n++ {
			message := seedFromCounter(n)
			_, consumed, err := key.challenge(message[:])
			if err != nil {
				return foundTarget{}, err
			}
			if consumed == t.want {
				return foundTarget{
					target: t, seed: seed, message: slices.Clone(message[:]),
					metrics: metrics{ballBytes: consumed},
				}, nil
			}
		}
		return foundTarget{}, fmt.Errorf("no message below %d gives %s=%d for tcIds %v",
			limit, t.kind, t.want, t.tcIDs)
	}

	if t.fixedSeed != nil {
		seed := seedFromCounter(*t.fixedSeed)
		m := calculateMetrics(seed, p, t.kind)
		if !matches(m, t) {
			return foundTarget{}, fmt.Errorf("fixed seed %x gives %s=%d, want %d",
				*t.fixedSeed, t.kind, m.value(t.kind), t.want)
		}
		return foundTarget{target: t, seed: seed, message: []byte(message), metrics: m}, nil
	}

	for n := t.start; n < limit; n++ {
		seed := seedFromCounter(n)
		m := calculateMetrics(seed, p, t.kind)
		if matches(m, t) {
			return foundTarget{target: t, seed: seed, message: []byte(message), metrics: m}, nil
		}
	}
	return foundTarget{}, fmt.Errorf("no seed below %d gives %s=%d for tcIds %v",
		limit, t.kind, t.want, t.tcIDs)
}

func matches(m metrics, t target) bool {
	if m.value(t.kind) != t.want {
		return false
	}
	if !t.requireS1 {
		return true
	}
	switch t.kind {
	case sBlocks:
		return m.s1Max > 2*shake256Rate
	case sMax:
		return m.s1Max == m.sMax
	default:
		panic("requireS1 used with an unsupported metric")
	}
}

func seedFromCounter(n uint64) [32]byte {
	var seed [32]byte
	binary.LittleEndian.PutUint64(seed[:8], n)
	return seed
}

func calculateMetrics(seed [32]byte, p parameters, kind metricKind) metrics {
	if kind == power2RoundPositive || kind == power2RoundNegative || kind == power2RoundBoth {
		key := fipsNewKey(seed, p)
		return metrics{
			powerPositive: key.powerPositive,
			powerNegative: key.powerNegative,
		}
	}
	input := append(slices.Clone(seed[:]), byte(p.k), byte(p.l))
	expanded := sha3.SumSHAKE256(input, 128)
	rho, rhoPrime := expanded[:32], expanded[32:96]

	var m metrics
	if kind == aMax || kind == aBytes {
		for r := range p.k {
			for s := range p.l {
				n := rejNTTBytes(rho, byte(s), byte(r))
				m.aMax = max(m.aMax, n)
				m.aBytes += n
				m.aBlocks += blocks(n, shake128Rate)
			}
		}
	}
	if kind == sMax || kind == sBytes || kind == sBlocks {
		for nonce := range p.k + p.l {
			n := rejBoundedBytes(rhoPrime, uint16(nonce), p.eta)
			m.sMax = max(m.sMax, n)
			if nonce < p.l {
				m.s1Max = max(m.s1Max, n)
			}
			m.sBytes += n
			m.sBlocks += blocks(n, shake256Rate)
		}
	}
	return m
}

func rejNTTBytes(rho []byte, s, r byte) int {
	input := append(slices.Clone(rho), s, r)
	stream := sha3.SumSHAKE128(input, 1024)
	accepted := 0
	for pos := 0; pos+2 < len(stream); pos += 3 {
		candidate := (uint32(stream[pos]) | uint32(stream[pos+1])<<8 | uint32(stream[pos+2])<<16) & 0x7f_ffff
		if candidate < q {
			accepted++
			if accepted == 256 {
				return pos + 3
			}
		}
	}
	panic("RejNTTPoly consumed more than 1024 bytes")
}

func rejBoundedBytes(rhoPrime []byte, nonce uint16, eta int) int {
	input := append(slices.Clone(rhoPrime), byte(nonce), byte(nonce>>8))
	stream := sha3.SumSHAKE256(input, 512)
	accepted := 0
	for pos, b := range stream {
		for _, candidate := range []byte{b & 0x0f, b >> 4} {
			if eta == 2 && candidate < 15 || eta == 4 && candidate < 9 {
				accepted++
				if accepted == 256 {
					return pos + 1
				}
			}
		}
	}
	panic("RejBoundedPoly consumed more than 512 bytes")
}

func blocks(n, rate int) int { return (n + rate - 1) / rate }

func regenerateSeedFile(path, schemasDir, openssl string, p parameters, found []foundTarget) (map[materialKey]generatedMaterial, error) {
	original, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var file vectorFile
	if err := json.Unmarshal(original, &file); err != nil {
		return nil, fmt.Errorf("decoding %s: %w", path, err)
	}
	if file.Algorithm != fmt.Sprintf("ML-DSA-%d", p.level) {
		return nil, fmt.Errorf("unexpected algorithm %q in %s", file.Algorithm, path)
	}

	byTCID := make(map[int]foundTarget)
	for _, f := range found {
		for _, id := range f.tcIDs {
			if _, duplicate := byTCID[id]; duplicate {
				return nil, fmt.Errorf("tcId %d has multiple regeneration targets", id)
			}
			byTCID[id] = f
		}
	}

	materialByTarget := make(map[materialKey]generatedMaterial)
	seen := make(map[int]bool)
	for gi := range file.TestGroups {
		var group testGroup
		if err := json.Unmarshal(file.TestGroups[gi], &group); err != nil {
			return nil, fmt.Errorf("decoding test group %d in %s: %w", gi, path, err)
		}
		var selected *foundTarget
		for _, test := range group.Tests {
			f, ok := byTCID[test.TCID]
			if !ok {
				continue
			}
			if selected != nil && (selected.seed != f.seed || string(selected.message) != string(f.message)) {
				return nil, fmt.Errorf("group containing tcId %d has targets with different seeds", test.TCID)
			}
			copy := f
			selected = &copy
			seen[test.TCID] = true
		}
		if selected == nil {
			continue
		}

		key := selected.materialKey()
		material, ok := materialByTarget[key]
		if !ok {
			material, err = generateMaterial(openssl, p, selected.seed, selected.message)
			if err != nil {
				return nil, fmt.Errorf("generating tcIds %v: %w", selected.tcIDs, err)
			}
			materialByTarget[key] = material
		}

		keyChanged := group.PrivateSeed != material.seedHex ||
			!equalOptionalString(group.PrivateKeyPKCS8, material.pkcs8Hex) ||
			!equalOptionalString(group.PublicKey, material.publicHex)
		group.PrivateSeed = material.seedHex
		group.PrivateKeyPKCS8 = &material.pkcs8Hex
		group.PublicKey = &material.publicHex
		group.Source = regeneratedSource(group.Source, selected.kind, keyChanged)
		for ti := range group.Tests {
			test := &group.Tests[ti]
			if _, ok := byTCID[test.TCID]; !ok {
				continue
			}
			test.Msg = &material.messageHex
			test.Mu = &material.muHex
			test.Sig = material.sigHex
		}
		encodedGroup, err := json.Marshal(&group)
		if err != nil {
			return nil, fmt.Errorf("encoding test group %d in %s: %w", gi, path, err)
		}
		file.TestGroups[gi] = encodedGroup
	}
	for id := range byTCID {
		if !seen[id] {
			return nil, fmt.Errorf("tcId %d was not found in %s", id, path)
		}
	}

	if err := writeVectorFile(path, schemasDir, &file); err != nil {
		return nil, err
	}
	return materialByTarget, nil
}

func regenerateNoseedFile(path, schemasDir string, p parameters, found []foundTarget, materials map[materialKey]generatedMaterial) error {
	file, err := readVectorFile(path, p)
	if err != nil {
		return err
	}
	byTCID, err := targetsByTCID(found, p, false)
	if err != nil {
		return err
	}

	seen := make(map[int]bool)
	for gi := range file.TestGroups {
		var group noseedGroup
		if err := json.Unmarshal(file.TestGroups[gi], &group); err != nil {
			return fmt.Errorf("decoding test group %d in %s: %w", gi, path, err)
		}
		selected, err := selectTarget(group.Tests, byTCID, seen)
		if err != nil {
			return err
		}
		if selected == nil {
			continue
		}
		material, ok := materials[selected.materialKey()]
		if !ok {
			return fmt.Errorf("no generated material for tcIds %v", selected.tcIDs)
		}

		keyChanged := group.PrivateKey != material.privateHex ||
			!equalOptionalString(group.PublicKey, material.publicHex)
		group.PrivateKey = material.privateHex
		group.PublicKey = &material.publicHex
		group.Source = regeneratedSource(group.Source, selected.kind, keyChanged)
		for ti := range group.Tests {
			test := &group.Tests[ti]
			if _, ok := byTCID[test.TCID]; !ok {
				continue
			}
			if err := updateSigningTest(test, material); err != nil {
				return err
			}
		}
		encodedGroup, err := json.Marshal(&group)
		if err != nil {
			return fmt.Errorf("encoding test group %d in %s: %w", gi, path, err)
		}
		file.TestGroups[gi] = encodedGroup
	}
	if err := checkTargetsSeen(path, byTCID, seen); err != nil {
		return err
	}
	return writeVectorFile(path, schemasDir, file)
}

func regenerateVerifyFile(path, schemasDir string, p parameters, found []foundTarget, materials map[materialKey]generatedMaterial) error {
	file, err := readVectorFile(path, p)
	if err != nil {
		return err
	}
	byTCID, err := targetsByTCID(found, p, true)
	if err != nil {
		return err
	}

	seen := make(map[int]bool)
	for gi := range file.TestGroups {
		var group verifyGroup
		if err := json.Unmarshal(file.TestGroups[gi], &group); err != nil {
			return fmt.Errorf("decoding test group %d in %s: %w", gi, path, err)
		}
		selected, err := selectTarget(group.Tests, byTCID, seen)
		if err != nil {
			return err
		}
		if selected == nil {
			continue
		}
		material, ok := materials[selected.materialKey()]
		if !ok {
			return fmt.Errorf("no generated material for tcIds %v", selected.tcIDs)
		}

		keyChanged := group.PublicKey != material.publicHex || group.PublicKeyDER != material.publicDERHex
		group.PublicKey = material.publicHex
		group.PublicKeyDER = material.publicDERHex
		group.Source = regeneratedSource(group.Source, selected.kind, keyChanged)
		for ti := range group.Tests {
			test := &group.Tests[ti]
			if _, ok := byTCID[test.TCID]; !ok {
				continue
			}
			test.Msg = &material.messageHex
			test.Sig = material.sigHex
		}
		encodedGroup, err := json.Marshal(&group)
		if err != nil {
			return fmt.Errorf("encoding test group %d in %s: %w", gi, path, err)
		}
		file.TestGroups[gi] = encodedGroup
	}
	if err := checkTargetsSeen(path, byTCID, seen); err != nil {
		return err
	}
	return writeVectorFile(path, schemasDir, file)
}

func readVectorFile(path string, p parameters) (*vectorFile, error) {
	original, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var file vectorFile
	if err := json.Unmarshal(original, &file); err != nil {
		return nil, fmt.Errorf("decoding %s: %w", path, err)
	}
	if file.Algorithm != fmt.Sprintf("ML-DSA-%d", p.level) {
		return nil, fmt.Errorf("unexpected algorithm %q in %s", file.Algorithm, path)
	}
	return &file, nil
}

func targetsByTCID(found []foundTarget, p parameters, verify bool) (map[int]foundTarget, error) {
	byTCID := make(map[int]foundTarget)
	for _, f := range found {
		ids := f.tcIDs
		if verify && len(f.verifyTCIDs) != 0 {
			ids = f.verifyTCIDs
		}
		for _, id := range ids {
			if verify && len(f.verifyTCIDs) == 0 {
				id += p.verifyOff
			}
			if _, duplicate := byTCID[id]; duplicate {
				return nil, fmt.Errorf("tcId %d has multiple regeneration targets", id)
			}
			byTCID[id] = f
		}
	}
	return byTCID, nil
}

func selectTarget(tests []test, byTCID map[int]foundTarget, seen map[int]bool) (*foundTarget, error) {
	var selected *foundTarget
	for _, test := range tests {
		f, ok := byTCID[test.TCID]
		if !ok {
			continue
		}
		if selected != nil && (selected.seed != f.seed || string(selected.message) != string(f.message)) {
			return nil, fmt.Errorf("group containing tcId %d has targets with different seeds", test.TCID)
		}
		copy := f
		selected = &copy
		seen[test.TCID] = true
	}
	return selected, nil
}

func checkTargetsSeen(path string, byTCID map[int]foundTarget, seen map[int]bool) error {
	for id := range byTCID {
		if !seen[id] {
			return fmt.Errorf("tcId %d was not found in %s", id, path)
		}
	}
	return nil
}

func updateSigningTest(test *test, material generatedMaterial) error {
	test.Msg = &material.messageHex
	test.Mu = &material.muHex
	test.Sig = material.sigHex
	return nil
}

func equalOptionalString(value *string, want string) bool {
	return value != nil && *value == want
}

func regeneratedSource(current source, kind metricKind, keyChanged bool) source {
	if kind == sampleInBallBytes && !keyChanged {
		// These tests share the original gendx baseline groups. Earlier
		// revisions of this tool incorrectly claimed the whole group.
		return source{Name: gendxSource, Version: gendxVersion}
	}
	if keyChanged || current.Name == legacySource {
		return source{Name: vectorSource, Version: vectorVersion}
	}
	return current
}

func writeVectorFile(path, schemasDir string, file *vectorFile) error {
	encoded, err := json.Marshal(file)
	if err != nil {
		return fmt.Errorf("encoding %s: %w", path, err)
	}
	formatted, err := vectorgen.FormatBytes(encoded)
	if err != nil {
		return err
	}
	if err := vectorgen.LintBytes(formatted, os.DirFS(schemasDir)); err != nil {
		return fmt.Errorf("linting generated %s: %w", path, err)
	}
	return writeAtomic(path, formatted, 0o644)
}

func generateMaterial(openssl string, p parameters, seed [32]byte, msg []byte) (generatedMaterial, error) {
	pkcs8 := seedPKCS8(p, seed)
	tmp, err := os.MkdirTemp("", "wycheproof-mldsa-edge-cases-*")
	if err != nil {
		return generatedMaterial{}, err
	}
	defer os.RemoveAll(tmp)

	keyPath := filepath.Join(tmp, "key.der")
	msgPath := filepath.Join(tmp, "message")
	privatePath := filepath.Join(tmp, "private.der")
	pubPath := filepath.Join(tmp, "public.der")
	sigPath := filepath.Join(tmp, "signature")
	if err := os.WriteFile(keyPath, pkcs8, 0o600); err != nil {
		return generatedMaterial{}, err
	}
	if err := os.WriteFile(msgPath, msg, 0o600); err != nil {
		return generatedMaterial{}, err
	}

	if err := run(openssl, "pkey", "-inform", "DER", "-in", keyPath, "-pubout", "-outform", "DER", "-out", pubPath); err != nil {
		return generatedMaterial{}, err
	}
	spki, err := os.ReadFile(pubPath)
	if err != nil {
		return generatedMaterial{}, err
	}
	if len(spki) < p.publicLen {
		return generatedMaterial{}, fmt.Errorf("OpenSSL returned a %d-byte SPKI, shorter than the %d-byte public key", len(spki), p.publicLen)
	}
	public := slices.Clone(spki[len(spki)-p.publicLen:])

	if err := run(openssl, "pkey", "-inform", "DER", "-in", keyPath,
		"-outform", "DER", "-out", privatePath,
		"-provparam", "ml-dsa.output_formats=bare-priv"); err != nil {
		return generatedMaterial{}, err
	}
	privateDER, err := os.ReadFile(privatePath)
	if err != nil {
		return generatedMaterial{}, err
	}
	var privateKeyInfo struct {
		Version    int
		Algorithm  asn1.RawValue
		PrivateKey []byte
	}
	rest, err := asn1.Unmarshal(privateDER, &privateKeyInfo)
	if err != nil {
		return generatedMaterial{}, fmt.Errorf("parsing OpenSSL private key: %w", err)
	}
	if len(rest) != 0 {
		return generatedMaterial{}, fmt.Errorf("OpenSSL private key has %d trailing bytes", len(rest))
	}
	if len(privateKeyInfo.PrivateKey) != p.privateLen {
		return generatedMaterial{}, fmt.Errorf("OpenSSL returned a %d-byte bare private key, want %d", len(privateKeyInfo.PrivateKey), p.privateLen)
	}

	if err := run(openssl, "pkeyutl", "-sign", "-rawin", "-keyform", "DER", "-inkey", keyPath,
		"-in", msgPath, "-out", sigPath, "-pkeyopt", "deterministic:1"); err != nil {
		return generatedMaterial{}, err
	}
	sig, err := os.ReadFile(sigPath)
	if err != nil {
		return generatedMaterial{}, err
	}
	if len(sig) != p.sigLen {
		return generatedMaterial{}, fmt.Errorf("OpenSSL returned a %d-byte signature, want %d", len(sig), p.sigLen)
	}
	fipsKey := fipsNewKey(seed, p)
	if !bytes.Equal(public, fipsKey.public) {
		return generatedMaterial{}, fmt.Errorf("OpenSSL public key differs from the independent FIPS 204 implementation")
	}
	challenge, _, err := fipsKey.challenge(msg)
	if err != nil {
		return generatedMaterial{}, fmt.Errorf("computing the independent FIPS 204 challenge: %w", err)
	}
	if !bytes.Equal(sig[:len(challenge)], challenge) {
		return generatedMaterial{}, fmt.Errorf("OpenSSL signature challenge differs from the independent FIPS 204 implementation")
	}
	if err := run(openssl, "pkeyutl", "-verify", "-rawin", "-pubin", "-keyform", "DER", "-inkey", pubPath,
		"-in", msgPath, "-sigfile", sigPath); err != nil {
		return generatedMaterial{}, fmt.Errorf("verifying generated signature: %w", err)
	}

	tr := sha3.SumSHAKE256(public, 64)
	muInput := append(tr, 0, 0) // Pure ML-DSA with an empty context.
	muInput = append(muInput, msg...)
	mu := sha3.SumSHAKE256(muInput, 64)

	return generatedMaterial{
		seedHex:      hex.EncodeToString(seed[:]),
		messageHex:   hex.EncodeToString(msg),
		pkcs8Hex:     hex.EncodeToString(pkcs8),
		privateHex:   hex.EncodeToString(privateKeyInfo.PrivateKey),
		publicHex:    hex.EncodeToString(public),
		publicDERHex: hex.EncodeToString(spki),
		muHex:        hex.EncodeToString(mu),
		sigHex:       hex.EncodeToString(sig),
	}, nil
}

func seedPKCS8(p parameters, seed [32]byte) []byte {
	// PrivateKeyInfo ::= SEQUENCE {
	//   version                   INTEGER 0,
	//   privateKeyAlgorithm       AlgorithmIdentifier { id-ml-dsa-* },
	//   privateKey                OCTET STRING { OCTET STRING seed }
	// }
	prefix := []byte{
		0x30, 0x34, 0x02, 0x01, 0x00, 0x30, 0x0b, 0x06, 0x09,
		0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, p.oidLast,
		0x04, 0x22, 0x80, 0x20,
	}
	return append(prefix, seed[:]...)
}

func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w\n%s", name, strings.Join(args, " "), err, bytes.TrimSpace(output))
	}
	return nil
}

func writeAtomic(path string, data []byte, mode fs.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".mldsa-edge-cases-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	keep := false
	defer func() {
		if !keep {
			_ = os.Remove(tmpPath)
		}
	}()
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	keep = true
	return nil
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "mldsa_edge_cases: "+format+"\n", args...)
	os.Exit(1)
}
