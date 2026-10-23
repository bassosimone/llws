// SPDX-License-Identifier: GPL-3.0-or-later

package llws

import (
	"bufio"
	"io"
)

// DefaultReadBufferSize is the read buffer size used by [NewReader].
//
// Tuned for ~1 syscall per WebSocket message read.
const DefaultReadBufferSize = 1<<17 + 128 // 128 KiB payload + header headroom

// DefaultWriteBufferSize is the write buffer size used by [NewWriter].
//
// Tuned to minimize memmove; ~2 syscalls per write.
const DefaultWriteBufferSize = 4 << 10

// NewReader makes a [*bufio.Reader] with [DefaultReadBufferSize] bytes of buffering.
func NewReader(r io.Reader) *bufio.Reader {
	return bufio.NewReaderSize(r, DefaultReadBufferSize)
}

// NewWriter makes a [*bufio.Writer] with [DefaultWriteBufferSize] bytes of buffering.
func NewWriter(w io.Writer) *bufio.Writer {
	return bufio.NewWriterSize(w, DefaultWriteBufferSize)
}

// NewReadWriter makes a [*bufio.ReadWriter] using [NewReader] and [NewWriter].
func NewReadWriter(rw io.ReadWriter) *bufio.ReadWriter {
	return bufio.NewReadWriter(NewReader(rw), NewWriter(rw))
}
