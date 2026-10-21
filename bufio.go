// SPDX-License-Identifier: GPL-3.0-or-later

package llws

import (
	"bufio"
	"net"
)

// DefaultReadBufferSize is the read buffer size used by [NewReadWriter].
//
// Tuned for ~1 syscall per WebSocket message read.
const DefaultReadBufferSize = 1<<17 + 128 // 128 KiB payload + header headroom

// DefaultWriteBufferSize is the write buffer size used by [NewReadWriter].
//
// Tuned to minimize memmove; ~2 syscalls per write.
const DefaultWriteBufferSize = 4 << 10

// NewReadWriter makes a [*bufio.ReadWriter] with performance-tuned defaults
// ([DefaultReadBufferSize], [DefaultWriteBufferSize]). For custom sizes,
// compose [bufio.NewReaderSize] and [bufio.NewWriterSize] manually.
func NewReadWriter(conn net.Conn) *bufio.ReadWriter {
	return bufio.NewReadWriter(
		bufio.NewReaderSize(conn, DefaultReadBufferSize),
		bufio.NewWriterSize(conn, DefaultWriteBufferSize),
	)
}
