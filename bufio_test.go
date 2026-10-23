// SPDX-License-Identifier: GPL-3.0-or-later

package llws

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewReader(t *testing.T) {
	t.Run("returns a valid Reader", func(t *testing.T) {
		r := NewReader(&bytes.Buffer{})
		assert.NotNil(t, r)
	})

	t.Run("uses the configured buffer size", func(t *testing.T) {
		r := NewReader(&bytes.Buffer{})
		assert.Equal(t, DefaultReadBufferSize, r.Size())
	})
}

func TestNewWriter(t *testing.T) {
	t.Run("returns a valid Writer", func(t *testing.T) {
		w := NewWriter(&bytes.Buffer{})
		assert.NotNil(t, w)
	})

	t.Run("uses the configured buffer size", func(t *testing.T) {
		w := NewWriter(&bytes.Buffer{})
		assert.Equal(t, DefaultWriteBufferSize, w.Size())
	})
}

func TestNewReadWriter(t *testing.T) {
	t.Run("returns a valid ReadWriter", func(t *testing.T) {
		rw := NewReadWriter(&bytes.Buffer{})
		assert.NotNil(t, rw)
		assert.NotNil(t, rw.Reader)
		assert.NotNil(t, rw.Writer)
	})

	t.Run("uses configured buffer sizes", func(t *testing.T) {
		rw := NewReadWriter(&bytes.Buffer{})
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
