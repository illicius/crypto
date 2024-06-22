/**
ISC License

Copyright 2023 @mekramy (github.com/mekramy)

Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted, provided that the above copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/

package crypto

import (
	"strings"
)


// HashAlgo available hash algo list
type HashAlgo int

// Parse algo from string
func (a *HashAlgo) Parse(algo string) bool {
	algo = strings.ToUpper(algo)
	switch algo {
	case "MD4":
		*a = MD4
	case "MD5":
		*a = MD5
	case "SHA1":
		*a = MD5
	case "SHA256":
		*a = SHA256
	case "SHA256224":
		*a = SHA256224
	case "SHA512":
		*a = SHA512
	case "SHA512224":
		*a = SHA512224
	case "SHA512256":
		*a = SHA512256
	case "SHA384":
		*a = SHA384
	case "SHA3224":
		*a = SHA3224
	case "SHA3256":
		*a = SHA3256
	case "SHA3384":
		*a = SHA3384
	case "SHA3512":
		*a = SHA3512
	case "KECCAK256":
		*a = KECCAK256
	case "KECCAK512":
		*a = KECCAK512
	default:
		*a = 0
		return false
	}
	return true
}

const (
	// MD4 hash algorithm
	MD4 HashAlgo = iota + 1
	// MD5 hash algorithm
	MD5
	// SHA1 hash algorithm
	SHA1
	// SHA256 hash algorithm
	SHA256
	// SHA256224 hash algorithm
	SHA256224
	// SHA384 hash algorithm
	SHA384
	// SHA512 hash algorithm
	SHA512
	// SHA512224 hash algorithm
	SHA512224
	// SHA512256 hash algorithm
	SHA512256
	// SHA3224 hash algorithm
	SHA3224
	// SHA3256 hash algorithm
	SHA3256
	// SHA3384 hash algorithm
	SHA3384
	// SHA3512 hash algorithm
	SHA3512
	// KECCAK256 hash algorithm
	KECCAK256
	// KECCAK512 hash algorithm
	KECCAK512
)
