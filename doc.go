// SPDX-License-Identifier: GPL-3.0-or-later

// Package llws provides low-level WebSocket framing primitives (RFC 6455):
// frame header encoding and decoding, payload masking, the opening handshake
// for both client and server, and performance-tuned buffered I/O setup.
//
// It deliberately does not implement message reassembly, control-frame dispatch,
// or connection lifecycle management. Consumers build their own WebSocket protocol
// logic on top of these primitives.
//
// As such, this package is probably more suitable for research and understanding
// the limits of other implementations than it is for writing production code.
//
// See https://datatracker.ietf.org/doc/html/rfc6455.
package llws
