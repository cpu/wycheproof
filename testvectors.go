// Wycheproof test vectors as an embedded filesystem of JSON content.
//
// Downstream Go code can import github.com/c2sp/wycheproof and access
// TestVectors using the standard library embed.FS interface.

package wycheproof

import "embed"

//go:embed testvectors_v1
var TestVectors embed.FS
