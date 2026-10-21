// SPDX-License-Identifier: GPL-3.0-or-later

package llws

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWriteTextFrame(t *testing.T) {
	t.Run("writes unmasked text frame", func(t *testing.T) {
		var buf bytes.Buffer
		payload := []byte("hello")
		err := WriteTextFrame(&buf, payload, nil)
		require.NoError(t, err)

		var h Header
		r := bufio.NewReader(&buf)
		require.NoError(t, ReadHeader(r, &h))
		assert.True(t, h.FlagFIN())
		assert.Equal(t, uint8(OpcodeText), h.Opcode())
		assert.Equal(t, uint64(5), h.PayloadLen())
		assert.False(t, h.FlagMask())

		var got bytes.Buffer
		require.NoError(t, ReadPayload(r, &h, &got))
		assert.Equal(t, "hello", got.String())
	})

	t.Run("writes masked text frame", func(t *testing.T) {
		var buf bytes.Buffer
		payload := []byte("hello")
		original := make([]byte, len(payload))
		copy(original, payload)

		mask := [4]byte{0xaa, 0xbb, 0xcc, 0xdd}
		err := WriteTextFrame(&buf, payload, &mask)
		require.NoError(t, err)

		var h Header
		r := bufio.NewReader(&buf)
		require.NoError(t, ReadHeader(r, &h))
		assert.True(t, h.FlagMask())
		got, err := h.Mask()
		require.NoError(t, err)
		assert.Equal(t, mask, got)

		var masked bytes.Buffer
		require.NoError(t, ReadPayload(r, &h, &masked))
		result := masked.Bytes()
		MaskPayload(result, mask)
		assert.Equal(t, original, result)
	})

	t.Run("propagates WriteHeader error", func(t *testing.T) {
		w := &failWriter{err: errors.New("broken")}
		err := WriteTextFrame(w, []byte("hello"), nil)
		require.EqualError(t, err, "broken")
	})

	t.Run("propagates payload write error", func(t *testing.T) {
		w := &writeHeaderOnlyWriter{headerErr: nil, payloadErr: errors.New("full")}
		err := WriteTextFrame(w, []byte("hello"), nil)
		require.EqualError(t, err, "full")
	})
}

func TestWriteBinaryFrame(t *testing.T) {
	t.Run("writes unmasked binary frame", func(t *testing.T) {
		var buf bytes.Buffer
		payload := []byte{0xde, 0xad, 0xbe, 0xef}
		err := WriteBinaryFrame(&buf, payload, nil)
		require.NoError(t, err)

		var h Header
		r := bufio.NewReader(&buf)
		require.NoError(t, ReadHeader(r, &h))
		assert.True(t, h.FlagFIN())
		assert.Equal(t, uint8(OpcodeBinary), h.Opcode())
		assert.Equal(t, uint64(4), h.PayloadLen())

		var got bytes.Buffer
		require.NoError(t, ReadPayload(r, &h, &got))
		assert.Equal(t, payload, got.Bytes())
	})
}

func TestWriteControlFrame(t *testing.T) {
	t.Run("writes unmasked close frame", func(t *testing.T) {
		var buf bytes.Buffer
		payload := []byte{0x03, 0xe8} // status 1000
		err := WriteControlFrame(&buf, OpcodeClose, payload, nil)
		require.NoError(t, err)

		var h Header
		r := bufio.NewReader(&buf)
		require.NoError(t, ReadHeader(r, &h))
		assert.True(t, h.FlagFIN())
		assert.Equal(t, uint8(OpcodeClose), h.Opcode())
		assert.Equal(t, uint64(2), h.PayloadLen())
		assert.False(t, h.FlagMask())

		var got bytes.Buffer
		require.NoError(t, ReadPayload(r, &h, &got))
		assert.Equal(t, payload, got.Bytes())
	})

	t.Run("writes masked ping frame", func(t *testing.T) {
		var buf bytes.Buffer
		payload := []byte("ping")
		original := make([]byte, len(payload))
		copy(original, payload)

		mask := [4]byte{0x11, 0x22, 0x33, 0x44}
		err := WriteControlFrame(&buf, OpcodePing, payload, &mask)
		require.NoError(t, err)

		var h Header
		r := bufio.NewReader(&buf)
		require.NoError(t, ReadHeader(r, &h))
		assert.Equal(t, uint8(OpcodePing), h.Opcode())
		assert.True(t, h.FlagMask())

		var masked bytes.Buffer
		require.NoError(t, ReadPayload(r, &h, &masked))
		result := masked.Bytes()
		MaskPayload(result, mask)
		assert.Equal(t, original, result)
	})

	t.Run("writes pong frame", func(t *testing.T) {
		var buf bytes.Buffer
		err := WriteControlFrame(&buf, OpcodePong, []byte("pong"), nil)
		require.NoError(t, err)

		var h Header
		r := bufio.NewReader(&buf)
		require.NoError(t, ReadHeader(r, &h))
		assert.Equal(t, uint8(OpcodePong), h.Opcode())
	})

	t.Run("rejects non-control opcode", func(t *testing.T) {
		var buf bytes.Buffer
		err := WriteControlFrame(&buf, OpcodeText, []byte("hello"), nil)
		require.ErrorIs(t, err, ErrNotControlOpcode)
		assert.Empty(t, buf.Bytes())
	})

	t.Run("rejects payload over 125 bytes", func(t *testing.T) {
		var buf bytes.Buffer
		payload := make([]byte, 126)
		err := WriteControlFrame(&buf, OpcodePing, payload, nil)
		require.ErrorIs(t, err, ErrControlFrame)
		assert.Empty(t, buf.Bytes())
	})

	t.Run("accepts 125-byte payload", func(t *testing.T) {
		var buf bytes.Buffer
		payload := make([]byte, 125)
		err := WriteControlFrame(&buf, OpcodePing, payload, nil)
		require.NoError(t, err)
	})

	t.Run("propagates write error", func(t *testing.T) {
		w := &failWriter{err: errors.New("broken")}
		err := WriteControlFrame(w, OpcodeClose, []byte{0x03, 0xe8}, nil)
		require.EqualError(t, err, "broken")
	})
}

func TestWriteCloseFrame(t *testing.T) {
	t.Run("writes unmasked close with status code", func(t *testing.T) {
		var buf bytes.Buffer
		err := WriteCloseFrame(&buf, StatusNormalClosure, nil)
		require.NoError(t, err)

		var h Header
		r := bufio.NewReader(&buf)
		require.NoError(t, ReadHeader(r, &h))
		assert.True(t, h.FlagFIN())
		assert.Equal(t, uint8(OpcodeClose), h.Opcode())
		assert.Equal(t, uint64(2), h.PayloadLen())
		assert.False(t, h.FlagMask())

		var got bytes.Buffer
		require.NoError(t, ReadPayload(r, &h, &got))
		assert.Equal(t, uint16(1000), binary.BigEndian.Uint16(got.Bytes()))
	})

	t.Run("writes masked close with status code", func(t *testing.T) {
		var buf bytes.Buffer
		mask := [4]byte{0x12, 0x34, 0x56, 0x78}
		err := WriteCloseFrame(&buf, StatusGoingAway, &mask)
		require.NoError(t, err)

		var h Header
		r := bufio.NewReader(&buf)
		require.NoError(t, ReadHeader(r, &h))
		assert.True(t, h.FlagMask())

		var masked bytes.Buffer
		require.NoError(t, ReadPayload(r, &h, &masked))
		result := masked.Bytes()
		MaskPayload(result, mask)
		assert.Equal(t, uint16(1001), binary.BigEndian.Uint16(result))
	})

	t.Run("propagates write error", func(t *testing.T) {
		w := &failWriter{err: errors.New("broken")}
		err := WriteCloseFrame(w, StatusNormalClosure, nil)
		require.EqualError(t, err, "broken")
	})
}

// writeHeaderOnlyWriter accepts the first Write (header) and fails on the second (payload).
type writeHeaderOnlyWriter struct {
	headerErr  error
	payloadErr error
	calls      int
}

func (w *writeHeaderOnlyWriter) Write(p []byte) (int, error) {
	w.calls++
	if w.calls == 1 {
		if w.headerErr != nil {
			return 0, w.headerErr
		}
		return len(p), nil
	}
	return 0, w.payloadErr
}
