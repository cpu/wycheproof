// Wycheproof test schemas as an embedded filesystem of JSON content.
//
// Downstream Go code can import github.com/c2sp/wycheproof and access
// Schemas using the standard library embed.FS interface.

package wycheproof

import "embed"

//go:embed schemas
var Schemas embed.FS
