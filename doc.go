// SPDX-License-Identifier: GPL-3.0-or-later

// Package llws provides low-level WebSocket framing primitives (RFC 6455):
// frame header encoding and decoding, payload masking, the opening handshake
// for both client and server, and performance-tuned buffered I/O setup.
//
// It also includes a minimal [*Conn] implementation designed to work well in
// research contexts such as implementing NDT-like protocols.
//
// This package is probably more suitable for research and understanding the
// overall performance limits than it is for writing production code.
//
// See https://datatracker.ietf.org/doc/html/rfc6455.
package llws
