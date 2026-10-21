//
// SPDX-License-Identifier: BSD-3-Clause
//
// Adapted-from: https://github.com/golang/go/blob/24ec7d2120d3d/src/net/http/internal/http2/ascii_test.go
//

// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package llws

import "testing"

func TestASCIIEqualFold(t *testing.T) {
	var tests = []struct {
		name string
		a, b string
		want bool
	}{
		{
			name: "empty",
			want: true,
		},
		{
			name: "simple match",
			a:    "CHUNKED",
			b:    "chunked",
			want: true,
		},
		{
			name: "same string",
			a:    "chunked",
			b:    "chunked",
			want: true,
		},
		{
			name: "same length different chars",
			a:    "chunked",
			b:    "chunxed",
			want: false,
		},
		{
			name: "different lengths",
			a:    "chunked",
			b:    "chunk",
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := asciiEqualFold(tt.a, tt.b); got != tt.want {
				t.Errorf("asciiEqualFold(%q,%q): got %v want %v", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestASCIITrimOWS(t *testing.T) {
	var tests = []struct {
		name string
		in   string
		want string
	}{
		{name: "empty", in: "", want: ""},
		{name: "no whitespace", in: "websocket", want: "websocket"},
		{name: "leading space", in: "  websocket", want: "websocket"},
		{name: "trailing space", in: "websocket  ", want: "websocket"},
		{name: "both sides", in: "  websocket  ", want: "websocket"},
		{name: "tabs", in: "\t\twebsocket\t\t", want: "websocket"},
		{name: "mixed SP and HTAB", in: " \t websocket \t ", want: "websocket"},
		{name: "only whitespace", in: "  \t  ", want: ""},
		{name: "preserves inner whitespace", in: "web socket", want: "web socket"},
		{name: "does not trim U+00A0", in: "\xc2\xa0websocket", want: "\xc2\xa0websocket"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := asciiTrimOWS(tt.in); got != tt.want {
				t.Errorf("asciiTrimOWS(%q): got %q want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestLower(t *testing.T) {
	var tests = []struct {
		name string
		in   byte
		want byte
	}{
		{name: "uppercase A", in: 'A', want: 'a'},
		{name: "uppercase Z", in: 'Z', want: 'z'},
		{name: "lowercase a", in: 'a', want: 'a'},
		{name: "digit", in: '5', want: '5'},
		{name: "symbol", in: '-', want: '-'},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := lower(tt.in); got != tt.want {
				t.Errorf("lower(%q): got %q want %q", tt.in, got, tt.want)
			}
		})
	}
}
