//
// SPDX-License-Identifier: BSD-3-Clause
//
// Adapted-from: https://github.com/golang/go/blob/24ec7d2120d3d/src/net/http/internal/http2/ascii.go
//

// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package llws

// asciiEqualFold is strings.EqualFold, ASCII only. It reports whether s and t
// are equal, ASCII-case-insensitively.
func asciiEqualFold(s, t string) bool {
	if len(s) != len(t) {
		return false
	}
	for i := 0; i < len(s); i++ {
		if lower(s[i]) != lower(t[i]) {
			return false
		}
	}
	return true
}

// lower returns the ASCII lowercase version of b.
func lower(b byte) byte {
	if 'A' <= b && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}

// asciiTrimOWS trims optional whitespace (OWS) as defined by
// RFC 9110, Section 5.6.3: OWS = *( SP / HTAB ). Unlike
// [strings.TrimSpace], this only removes ASCII SP (0x20) and
// HTAB (0x09), not Unicode whitespace such as U+00A0.
func asciiTrimOWS(s string) string {
	start := 0
	for start < len(s) && (s[start] == ' ' || s[start] == '\t') {
		start++
	}
	end := len(s)
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t') {
		end--
	}
	return s[start:end]
}
