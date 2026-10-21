// SPDX-License-Identifier: GPL-3.0-or-later

package llws

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMaskPayload(t *testing.T) {
	t.Run("empty body is a no-op", func(t *testing.T) {
		MaskPayload(nil, [4]byte{0xff, 0xff, 0xff, 0xff})
	})

	t.Run("masks single byte", func(t *testing.T) {
		body := []byte{0xaa}
		MaskPayload(body, [4]byte{0xff, 0x00, 0x00, 0x00})
		assert.Equal(t, []byte{0x55}, body)
	})

	t.Run("masks exactly four bytes", func(t *testing.T) {
		body := []byte{0x01, 0x02, 0x03, 0x04}
		mask := [4]byte{0xff, 0xff, 0xff, 0xff}
		MaskPayload(body, mask)
		assert.Equal(t, []byte{0xfe, 0xfd, 0xfc, 0xfb}, body)
	})

	t.Run("mask repeats across longer body", func(t *testing.T) {
		body := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
		mask := [4]byte{0xaa, 0xbb, 0xcc, 0xdd}
		MaskPayload(body, mask)
		assert.Equal(t, []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xaa, 0xbb}, body)
	})

	t.Run("double mask is identity", func(t *testing.T) {
		original := []byte("Hello, WebSocket!")
		body := make([]byte, len(original))
		copy(body, original)
		mask := [4]byte{0x37, 0xfa, 0x21, 0x3d}
		MaskPayload(body, mask)
		assert.NotEqual(t, original, body)
		MaskPayload(body, mask)
		assert.Equal(t, original, body)
	})

	t.Run("zero mask is identity", func(t *testing.T) {
		body := []byte{0xde, 0xad, 0xbe, 0xef}
		MaskPayload(body, [4]byte{0x00, 0x00, 0x00, 0x00})
		assert.Equal(t, []byte{0xde, 0xad, 0xbe, 0xef}, body)
	})

	t.Run("bulk-tail boundary with distinct mask bytes", func(t *testing.T) {
		body := make([]byte, 13)
		mask := [4]byte{0xaa, 0xbb, 0xcc, 0xdd}
		MaskPayload(body, mask)
		assert.Equal(t, []byte{
			0xaa, 0xbb, 0xcc, 0xdd, 0xaa, 0xbb, 0xcc, 0xdd,
			0xaa, 0xbb, 0xcc, 0xdd, 0xaa,
		}, body)
	})

	t.Run("length sweep with distinct mask", func(t *testing.T) {
		mask := [4]byte{0xaa, 0xbb, 0xcc, 0xdd}
		for n := 0; n <= 24; n++ {
			body := make([]byte, n)
			MaskPayload(body, mask)
			for i := 0; i < n; i++ {
				assert.Equalf(t, mask[i%4], body[i], "n=%d i=%d", n, i)
			}
		}
	})
}

type failWriter struct{ err error }

func (w *failWriter) Write([]byte) (int, error) { return 0, w.err }

type failReader struct{ err error }

func (r *failReader) Read([]byte) (int, error) { return 0, r.err }

// eofReader returns all remaining data together with io.EOF in a single
// Read call, as permitted by the io.Reader contract.
type eofReader struct {
	data []byte
	pos  int
}

func (r *eofReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	n := copy(p, r.data[r.pos:])
	r.pos += n
	if r.pos >= len(r.data) {
		return n, io.EOF
	}
	return n, nil
}

// newHeaderWithLength builds a Header with the given payload length set.
func newHeaderWithLength(length uint64) *Header {
	var h Header
	h.SetFlagFIN(true)
	h.SetOpcode(OpcodeBinary)
	if err := h.SetPayloadLen(length); err != nil {
		panic(err)
	}
	return &h
}

func TestDiscardPayload(t *testing.T) {
	t.Run("zero-length payload", func(t *testing.T) {
		r := bufio.NewReader(strings.NewReader(""))
		h := newHeaderWithLength(0)
		err := DiscardPayload(r, h)
		require.NoError(t, err)
	})

	t.Run("discards short payload", func(t *testing.T) {
		data := "hello, world"
		r := bufio.NewReader(strings.NewReader(data + "trailing"))
		h := newHeaderWithLength(uint64(len(data)))
		err := DiscardPayload(r, h)
		require.NoError(t, err)

		// The trailing bytes should still be readable
		rest, err := io.ReadAll(r)
		require.NoError(t, err)
		assert.Equal(t, "trailing", string(rest))
	})

	t.Run("discards payload larger than bufio buffer", func(t *testing.T) {
		payload := strings.Repeat("x", 8192)
		r := bufio.NewReaderSize(strings.NewReader(payload+"end"), 512)
		h := newHeaderWithLength(uint64(len(payload)))
		err := DiscardPayload(r, h)
		require.NoError(t, err)

		rest, err := io.ReadAll(r)
		require.NoError(t, err)
		assert.Equal(t, "end", string(rest))
	})

	t.Run("returns ErrUnexpectedEOF on short read", func(t *testing.T) {
		r := bufio.NewReader(strings.NewReader("short"))
		h := newHeaderWithLength(100)
		err := DiscardPayload(r, h)
		require.ErrorIs(t, err, io.ErrUnexpectedEOF)
	})

	t.Run("handles (count, io.EOF) when all bytes were discarded", func(t *testing.T) {
		r := bufio.NewReader(&eofReader{data: []byte("hello")})
		h := newHeaderWithLength(5)
		err := DiscardPayload(r, h)
		require.NoError(t, err)
	})

	t.Run("returns non-EOF error from reader", func(t *testing.T) {
		r := bufio.NewReader(&failReader{err: errors.New("connection reset")})
		h := newHeaderWithLength(100)
		err := DiscardPayload(r, h)
		require.EqualError(t, err, "connection reset")
	})
}

func TestReadPayload(t *testing.T) {
	t.Run("zero-length payload", func(t *testing.T) {
		r := bufio.NewReader(strings.NewReader(""))
		h := newHeaderWithLength(0)
		var buf bytes.Buffer
		err := ReadPayload(r, h, &buf)
		require.NoError(t, err)
		assert.Empty(t, buf.Bytes())
	})

	t.Run("reads exact payload", func(t *testing.T) {
		data := "hello, world"
		r := bufio.NewReader(strings.NewReader(data + "trailing"))
		h := newHeaderWithLength(uint64(len(data)))
		var buf bytes.Buffer
		err := ReadPayload(r, h, &buf)
		require.NoError(t, err)
		assert.Equal(t, data, buf.String())

		// Trailing bytes should still be readable
		rest, err := io.ReadAll(r)
		require.NoError(t, err)
		assert.Equal(t, "trailing", string(rest))
	})

	t.Run("reads payload larger than bufio buffer", func(t *testing.T) {
		payload := strings.Repeat("x", 8192)
		r := bufio.NewReaderSize(strings.NewReader(payload+"end"), 512)
		h := newHeaderWithLength(uint64(len(payload)))
		var buf bytes.Buffer
		err := ReadPayload(r, h, &buf)
		require.NoError(t, err)
		assert.Equal(t, payload, buf.String())

		rest, err := io.ReadAll(r)
		require.NoError(t, err)
		assert.Equal(t, "end", string(rest))
	})

	t.Run("returns error when writer fails", func(t *testing.T) {
		r := bufio.NewReader(strings.NewReader("hello"))
		h := newHeaderWithLength(5)
		w := &failWriter{err: errors.New("disk full")}
		err := ReadPayload(r, h, w)
		require.EqualError(t, err, "disk full")
	})

	t.Run("returns ErrUnexpectedEOF on short read", func(t *testing.T) {
		r := bufio.NewReader(strings.NewReader("short"))
		h := newHeaderWithLength(100)
		var buf bytes.Buffer
		err := ReadPayload(r, h, &buf)
		require.ErrorIs(t, err, io.ErrUnexpectedEOF)
		assert.Equal(t, "short", buf.String())
	})
}
