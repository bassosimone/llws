// SPDX-License-Identifier: GPL-3.0-or-later

package llws

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewReadWriter(t *testing.T) {
	t.Run("returns a valid ReadWriter", func(t *testing.T) {
		client, server := net.Pipe()
		defer client.Close()
		defer server.Close()
		rw := NewReadWriter(client)
		assert.NotNil(t, rw)
		assert.NotNil(t, rw.Reader)
		assert.NotNil(t, rw.Writer)
	})

	t.Run("uses configured buffer sizes", func(t *testing.T) {
		client, server := net.Pipe()
		defer client.Close()
		defer server.Close()
		rw := NewReadWriter(client)
		assert.Equal(t, DefaultReadBufferSize, rw.Reader.Size())
		assert.Equal(t, DefaultWriteBufferSize, rw.Writer.Available())
	})
}

// Pin constants to their values so we get a test error if we change them and
// we can think twice about whether they should actually be changed.
func TestBufferSizeConstants(t *testing.T) {
	t.Run("read buffer is 128KiB plus 128 bytes", func(t *testing.T) {
		assert.Equal(t, 1<<17+128, DefaultReadBufferSize)
	})

	t.Run("write buffer is 4 KiB", func(t *testing.T) {
		assert.Equal(t, 4096, DefaultWriteBufferSize)
	})
}
