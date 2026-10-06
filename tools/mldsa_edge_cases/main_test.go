package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"testing"
)

func TestFIPSNTT(t *testing.T) {
	var a, b fipsPoly
	for i := range a {
		a[i] = int64(i*i + 3*i + 1)
		b[i] = int64(7*i + 5)
	}
	if got := fipsInverseNTT(fipsNTT(a)); got != a {
		t.Fatal("inverse NTT does not undo NTT")
	}
	got := fipsInverseNTT(fipsPointwise(fipsNTT(a), fipsNTT(b)))
	var want fipsPoly
	for i := range a {
		for j := range b {
			coefficient := a[i] * b[j]
			index := i + j
			if index >= fipsN {
				index -= fipsN
				coefficient = -coefficient
			}
			want[index] = fipsMod(want[index] + coefficient)
		}
	}
	if got != want {
		t.Fatal("NTT multiplication does not match negacyclic multiplication")
	}
}

func TestFIPSKeyAndChallenge(t *testing.T) {
	want := map[int]struct {
		publicHash string
		challenge  string
	}{
		44: {"d87f8ca136ac1aa55e2d6c4521680efb3a378cbb9bc0bfb446e9c60893931ea3", "1aa69cb5ed35204534f25f40a17eb0d767f8981f5e7cec46d3bf3252bfc78e09"},
		65: {"b7acce2ddb11f8cc1aa46e2bafac6eacfa2b732ef192bd636ad8d3a56d649c66", "69da5aec6d5f58fbf29439c520bd68b966e3dd2ca633b68351c2862344713a1e9c086a44f9a870a3ccc14de62d6c12b2"},
		87: {"d43128fa8a8c785c1d44c9e7db538dbf9dd88fe6c8ad911a344bcec1017c6d54", "ba4275ff54c22d2d09ea1937a0667362acd44925c6d6965fad350b111d1cbcce68ddbd0e576d1a8810eb4e71623781f32f747d44c8e693749df191682f588906"},
	}
	var seed [32]byte
	for i := range seed {
		seed[i] = 0x2a
	}
	for _, p := range parameterSets {
		key := fipsNewKey(seed, p)
		publicHash := sha256.Sum256(key.public)
		if got := hex.EncodeToString(publicHash[:]); got != want[p.level].publicHash {
			t.Errorf("ML-DSA-%d public key hash = %s, want %s", p.level, got, want[p.level].publicHash)
		}
		challenge, _, err := key.challenge([]byte(message))
		if err != nil {
			t.Fatalf("ML-DSA-%d signing: %v", p.level, err)
		}
		if got := hex.EncodeToString(challenge); got != want[p.level].challenge {
			t.Errorf("ML-DSA-%d challenge = %s, want %s", p.level, got, want[p.level].challenge)
		}
	}
}

func TestEmptyOptionalFieldsSurviveRoundTrip(t *testing.T) {
	input := []byte(`{"type":"","privateSeed":"","privateKeyPkcs8":"",` +
		`"publicKey":null,"source":{"name":"","version":""},"tests":[{` +
		`"tcId":0,"comment":"","msg":"","ctx":"","rnd":"","mu":"",` +
		`"sig":"","result":"","flags":[]}]}`)

	var group testGroup
	if err := json.Unmarshal(input, &group); err != nil {
		t.Fatal(err)
	}
	got, err := json.Marshal(group)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(input) {
		t.Fatalf("round trip removed explicit empty fields:\n got: %s\nwant: %s", got, input)
	}
}

func TestUntouchedGroupOrderSurvivesRoundTrip(t *testing.T) {
	input := []byte(`{"algorithm":"ML-DSA-44","header":[],"notes":{},` +
		`"numberOfTests":1,"schema":"schema.json","testGroups":[{` +
		`"tests":[],"source":{"version":"1","name":"generator"},` +
		`"publicKey":"","privateSeed":"","type":"MlDsaSign"}]}`)

	var file vectorFile
	if err := json.Unmarshal(input, &file); err != nil {
		t.Fatal(err)
	}
	got, err := json.Marshal(file)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(input) {
		t.Fatalf("round trip reordered an untouched group:\n got: %s\nwant: %s", got, input)
	}
}

func TestRegeneratedSource(t *testing.T) {
	gendx := source{Name: gendxSource, Version: gendxVersion}
	legacy := source{Name: legacySource, Version: vectorVersion}
	want := source{Name: vectorSource, Version: vectorVersion}

	if got := regeneratedSource(legacy, sampleInBallBytes, false); got != gendx {
		t.Errorf("test-only baseline rewrite source = %#v, want %#v", got, gendx)
	}
	if got := regeneratedSource(legacy, sMax, false); got != want {
		t.Errorf("legacy tool source migration = %#v, want %#v", got, want)
	}
	if got := regeneratedSource(gendx, sMax, true); got != want {
		t.Errorf("key replacement source = %#v, want %#v", got, want)
	}
}

func TestFinalFIPSDerivationCounts(t *testing.T) {
	p := parameters{level: 65, k: 6, l: 5, eta: 4}

	old := calculateMetrics(seedFromCounter(0x3a09), p, sBlocks)
	if old.sMax != 246 || old.sBytes != 2503 || old.sBlocks != 22 {
		t.Fatalf("stale tcIds 62/63 metrics = max %d, bytes %d, blocks %d; want 246, 2503, 22",
			old.sMax, old.sBytes, old.sBlocks)
	}

	s2ThirdBlock := calculateMetrics(seedFromCounter(0x274f), p, sBlocks)
	blocksTarget := target{kind: sBlocks, want: 23, requireS1: true}
	if matches(s2ThirdBlock, blocksTarget) {
		t.Fatal("s2-only third-block seed satisfies the s1-constrained target")
	}

	thirdBlock := calculateMetrics(seedFromCounter(0x1f1f6), p, sBlocks)
	if thirdBlock.sMax != 273 || thirdBlock.s1Max != 273 || thirdBlock.sBytes != 2572 || thirdBlock.sBlocks != 23 {
		t.Fatalf("s1 third-block metrics = max %d, s1 max %d, bytes %d, blocks %d; want 273, 273, 2572, 23",
			thirdBlock.sMax, thirdBlock.s1Max, thirdBlock.sBytes, thirdBlock.sBlocks)
	}
	if !matches(thirdBlock, blocksTarget) {
		t.Fatal("s1 third-block seed does not satisfy the s1-constrained target")
	}

	s2ExactBytes := calculateMetrics(seedFromCounter(0x1052e), p, sMax)
	exactTarget := target{kind: sMax, want: 277, requireS1: true}
	if matches(s2ExactBytes, exactTarget) {
		t.Fatal("s2-only 277-byte seed satisfies the s1-constrained target")
	}
	exactBytes := calculateMetrics(seedFromCounter(0x2ce4c), p, sMax)
	if exactBytes.sMax != 277 || exactBytes.s1Max != 277 || exactBytes.sBytes != 2576 || exactBytes.sBlocks != 23 {
		t.Fatalf("s1 exact-byte metrics = max %d, s1 max %d, bytes %d, blocks %d; want 277, 277, 2576, 23",
			exactBytes.sMax, exactBytes.s1Max, exactBytes.sBytes, exactBytes.sBlocks)
	}
	if !matches(exactBytes, exactTarget) {
		t.Fatal("s1 277-byte seed does not satisfy the s1-constrained target")
	}
}

func TestExistingMLDSA87Power2RoundPositiveCase(t *testing.T) {
	p := parameterSets[2]
	m := calculateMetrics(seedFromCounter(1), p, power2RoundPositive)
	if m.powerPositive == 0 {
		t.Fatal("ML-DSA-87 seed 1 no longer produces a +4096 remainder")
	}
}

func TestSeedPKCS8(t *testing.T) {
	seed := seedFromCounter(0)
	for _, p := range parameterSets {
		got := seedPKCS8(p, seed)
		if len(got) != 54 {
			t.Errorf("ML-DSA-%d PKCS#8 length = %d, want 54", p.level, len(got))
		}
		if got[17] != p.oidLast {
			t.Errorf("ML-DSA-%d OID suffix = %d, want %d", p.level, got[17], p.oidLast)
		}
	}
}
