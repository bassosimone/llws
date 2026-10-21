// SPDX-License-Identifier: GPL-3.0-or-later

package llws

import (
	"bufio"
	"bytes"
	"io"
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
)

func readHeaderFrom(data []byte) (*Header, error) {
	var h Header
	err := ReadHeader(bufio.NewReader(bytes.NewReader(data)), &h)
	return &h, err
}

func TestReadHeader(t *testing.T) {
	// --- success: short (len <= 125) ---

	t.Run("short unmasked text frame", func(t *testing.T) {
		// FIN=1, opcode=text(1), MASK=0, len=5
		h, err := readHeaderFrom([]byte{0x81, 0x05})
		assert.NoError(t, err)
		assert.True(t, h.FlagFIN())
		assert.Equal(t, uint8(OpcodeText), h.Opcode())
		assert.False(t, h.FlagMask())
		assert.Equal(t, uint64(5), h.Length())
	})

	t.Run("short masked text frame", func(t *testing.T) {
		// FIN=1, opcode=text, MASK=1, len=5, mask=0xAABBCCDD
		h, err := readHeaderFrom([]byte{0x81, 0x85, 0xAA, 0xBB, 0xCC, 0xDD})
		assert.NoError(t, err)
		assert.True(t, h.FlagMask())
		assert.Equal(t, uint64(5), h.Length())
		mask, merr := h.Mask()
		assert.NoError(t, merr)
		assert.Equal(t, [4]byte{0xAA, 0xBB, 0xCC, 0xDD}, mask)
	})

	t.Run("zero-length frame", func(t *testing.T) {
		// FIN=1, opcode=text, MASK=0, len=0
		h, err := readHeaderFrom([]byte{0x81, 0x00})
		assert.NoError(t, err)
		assert.Equal(t, uint64(0), h.Length())
	})

	// --- success: medium (16-bit extended length) ---

	t.Run("medium unmasked frame", func(t *testing.T) {
		// FIN=1, opcode=text, MASK=0, len0=126, extended=300 (0x012C)
		h, err := readHeaderFrom([]byte{0x81, 0x7E, 0x01, 0x2C})
		assert.NoError(t, err)
		assert.Equal(t, uint64(300), h.Length())
		assert.False(t, h.FlagMask())
	})

	t.Run("medium masked frame", func(t *testing.T) {
		// FIN=1, opcode=text, MASK=1, len0=126, extended=300, mask=0xAABBCCDD
		h, err := readHeaderFrom([]byte{0x81, 0xFE, 0x01, 0x2C, 0xAA, 0xBB, 0xCC, 0xDD})
		assert.NoError(t, err)
		assert.Equal(t, uint64(300), h.Length())
		mask, merr := h.Mask()
		assert.NoError(t, merr)
		assert.Equal(t, [4]byte{0xAA, 0xBB, 0xCC, 0xDD}, mask)
	})

	// --- success: long (64-bit extended length) ---

	t.Run("long unmasked frame", func(t *testing.T) {
		// FIN=1, opcode=text, MASK=0, len0=127, extended=70000 (0x11170)
		h, err := readHeaderFrom([]byte{
			0x81, 0x7F,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x11, 0x70,
		})
		assert.NoError(t, err)
		assert.Equal(t, uint64(70000), h.Length())
		assert.False(t, h.FlagMask())
	})

	t.Run("long masked frame", func(t *testing.T) {
		// FIN=1, opcode=binary, MASK=1, len0=127, extended=70000, mask=0x11223344
		h, err := readHeaderFrom([]byte{
			0x82, 0xFF,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x11, 0x70,
			0x11, 0x22, 0x33, 0x44,
		})
		assert.NoError(t, err)
		assert.Equal(t, uint8(OpcodeBinary), h.Opcode())
		assert.Equal(t, uint64(70000), h.Length())
		mask, merr := h.Mask()
		assert.NoError(t, merr)
		assert.Equal(t, [4]byte{0x11, 0x22, 0x33, 0x44}, mask)
	})

	// --- success: control frames ---

	t.Run("valid close frame", func(t *testing.T) {
		// FIN=1, opcode=close(8), MASK=0, len=2
		h, err := readHeaderFrom([]byte{0x88, 0x02})
		assert.NoError(t, err)
		assert.Equal(t, uint8(OpcodeClose), h.Opcode())
		assert.Equal(t, uint64(2), h.Length())
	})

	t.Run("valid ping frame", func(t *testing.T) {
		// FIN=1, opcode=ping(9), MASK=0, len=0
		h, err := readHeaderFrom([]byte{0x89, 0x00})
		assert.NoError(t, err)
		assert.Equal(t, uint8(OpcodePing), h.Opcode())
	})

	t.Run("valid pong frame", func(t *testing.T) {
		// FIN=1, opcode=pong(10), MASK=0, len=5
		h, err := readHeaderFrom([]byte{0x8A, 0x05})
		assert.NoError(t, err)
		assert.Equal(t, uint8(OpcodePong), h.Opcode())
	})

	// --- success: other ---

	t.Run("continuation frame with FIN=0", func(t *testing.T) {
		// FIN=0, opcode=continuation(0), MASK=0, len=5
		h, err := readHeaderFrom([]byte{0x00, 0x05})
		assert.NoError(t, err)
		assert.False(t, h.FlagFIN())
		assert.Equal(t, uint8(OpcodeContinue), h.Opcode())
	})

	t.Run("unknown opcode passes through", func(t *testing.T) {
		// FIN=1, opcode=3 (reserved), MASK=0, len=5
		h, err := readHeaderFrom([]byte{0x83, 0x05})
		assert.NoError(t, err)
		assert.Equal(t, uint8(3), h.Opcode())
	})

	// --- errors: read failures ---

	t.Run("EOF on base bytes", func(t *testing.T) {
		_, err := readHeaderFrom([]byte{})
		assert.ErrorIs(t, err, io.EOF)
	})

	t.Run("short read on base bytes", func(t *testing.T) {
		_, err := readHeaderFrom([]byte{0x81})
		assert.ErrorIs(t, err, io.ErrUnexpectedEOF)
	})

	t.Run("EOF on extended bytes", func(t *testing.T) {
		// Medium frame (needs 4 bytes) but only 3 provided
		_, err := readHeaderFrom([]byte{0x81, 0x7E, 0x01})
		assert.ErrorIs(t, err, io.ErrUnexpectedEOF)
	})

	// --- RSV bits pass through ---

	t.Run("RSV1 set", func(t *testing.T) {
		// 0xC1 = 1100_0001: FIN=1, RSV1=1, opcode=1
		h, err := readHeaderFrom([]byte{0xC1, 0x05})
		assert.NoError(t, err)
		assert.Equal(t, uint8(0x40), h.RSV())
	})

	t.Run("RSV2 set", func(t *testing.T) {
		// 0xA1 = 1010_0001: FIN=1, RSV2=1, opcode=1
		h, err := readHeaderFrom([]byte{0xA1, 0x05})
		assert.NoError(t, err)
		assert.Equal(t, uint8(0x20), h.RSV())
	})

	t.Run("RSV3 set", func(t *testing.T) {
		// 0x91 = 1001_0001: FIN=1, RSV3=1, opcode=1
		h, err := readHeaderFrom([]byte{0x91, 0x05})
		assert.NoError(t, err)
		assert.Equal(t, uint8(0x10), h.RSV())
	})

	// --- errors: control frame violations ---

	t.Run("close frame with extended length", func(t *testing.T) {
		// FIN=1, opcode=close(8), len0=126 (> 125)
		_, err := readHeaderFrom([]byte{0x88, 0x7E})
		assert.ErrorIs(t, err, ErrControlFrame)
	})

	t.Run("close frame without FIN", func(t *testing.T) {
		// FIN=0, opcode=close(8), len=5
		_, err := readHeaderFrom([]byte{0x08, 0x05})
		assert.ErrorIs(t, err, ErrControlFrame)
	})

	t.Run("ping frame without FIN", func(t *testing.T) {
		// FIN=0, opcode=ping(9), len=5
		_, err := readHeaderFrom([]byte{0x09, 0x05})
		assert.ErrorIs(t, err, ErrControlFrame)
	})

	t.Run("pong frame with extended length", func(t *testing.T) {
		// FIN=1, opcode=pong(10), len0=126 (> 125)
		_, err := readHeaderFrom([]byte{0x8A, 0x7E})
		assert.ErrorIs(t, err, ErrControlFrame)
	})

	// --- errors: 64-bit length MSB ---

	t.Run("64-bit length with MSB set", func(t *testing.T) {
		// FIN=1, opcode=text, len0=127, first byte of extended = 0x80
		_, err := readHeaderFrom([]byte{
			0x81, 0x7F,
			0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		})
		assert.ErrorIs(t, err, ErrLengthTooLarge)
	})
}

func TestHeaderBuild(t *testing.T) {
	type testCase struct {
		name    string
		fin     bool
		opcode  uint8
		length  uint64
		mask    *[4]byte
		wantBuf []byte
	}

	m := func(a, b, c, d byte) *[4]byte { return &[4]byte{a, b, c, d} }

	cases := []testCase{
		{
			name:    "short unmasked text",
			fin:     true,
			opcode:  OpcodeText,
			length:  5,
			wantBuf: []byte{0x81, 0x05},
		},
		{
			name:    "short masked binary",
			fin:     true,
			opcode:  OpcodeBinary,
			length:  10,
			mask:    m(0xAA, 0xBB, 0xCC, 0xDD),
			wantBuf: []byte{0x82, 0x8A, 0xAA, 0xBB, 0xCC, 0xDD},
		},
		{
			name:    "medium unmasked",
			fin:     true,
			opcode:  OpcodeText,
			length:  300,
			wantBuf: []byte{0x81, 0x7E, 0x01, 0x2C},
		},
		{
			name:    "medium masked",
			fin:     true,
			opcode:  OpcodeText,
			length:  300,
			mask:    m(0x11, 0x22, 0x33, 0x44),
			wantBuf: []byte{0x81, 0xFE, 0x01, 0x2C, 0x11, 0x22, 0x33, 0x44},
		},
		{
			name:   "long unmasked",
			fin:    true,
			opcode: OpcodeText,
			length: 70000,
			wantBuf: []byte{
				0x81, 0x7F,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x11, 0x70,
			},
		},
		{
			name:   "long masked binary",
			fin:    true,
			opcode: OpcodeBinary,
			length: 70000,
			mask:   m(0xAA, 0xBB, 0xCC, 0xDD),
			wantBuf: []byte{
				0x82, 0xFF,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x11, 0x70,
				0xAA, 0xBB, 0xCC, 0xDD,
			},
		},
		{
			name:    "zero-length close",
			fin:     true,
			opcode:  OpcodeClose,
			length:  0,
			wantBuf: []byte{0x88, 0x00},
		},
		{
			name:    "max short continuation without FIN",
			fin:     false,
			opcode:  OpcodeContinue,
			length:  125,
			wantBuf: []byte{0x00, 0x7D},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Build the header using the setter API.
			//
			// Required call order: FIN/Opcode, then SetLength, then SetMask.
			var h Header
			h.SetFlagFIN(tc.fin)
			h.SetOpcode(tc.opcode)
			assert.NoError(t, h.SetLength(tc.length))
			if tc.mask != nil {
				h.SetMask(*tc.mask)
			}

			assert.Equal(t, tc.wantBuf, h.Slice())

			// Verify getters roundtrip correctly.
			assert.Equal(t, tc.fin, h.FlagFIN())
			assert.Equal(t, tc.opcode, h.Opcode())
			assert.Equal(t, tc.length, h.Length())
			if tc.mask != nil {
				assert.True(t, h.FlagMask())
				got, err := h.Mask()
				assert.NoError(t, err)
				assert.Equal(t, *tc.mask, got)
			} else {
				assert.False(t, h.FlagMask())
			}
		})
	}
}

func TestWriteHeader(t *testing.T) {
	t.Run("roundtrip through WriteHeader and ReadHeader", func(t *testing.T) {
		type testCase struct {
			name   string
			fin    bool
			opcode uint8
			length uint64
			mask   *[4]byte
		}

		m := func(a, b, c, d byte) *[4]byte { return &[4]byte{a, b, c, d} }

		cases := []testCase{
			{name: "short unmasked", fin: true, opcode: OpcodeText, length: 5},
			{name: "short masked", fin: true, opcode: OpcodeBinary, length: 10, mask: m(0xAA, 0xBB, 0xCC, 0xDD)},
			{name: "medium unmasked", fin: true, opcode: OpcodeText, length: 300},
			{name: "medium masked", fin: true, opcode: OpcodeText, length: 300, mask: m(0x11, 0x22, 0x33, 0x44)},
			{name: "long unmasked", fin: true, opcode: OpcodeText, length: 70000},
			{name: "long masked", fin: true, opcode: OpcodeBinary, length: 70000, mask: m(0xAA, 0xBB, 0xCC, 0xDD)},
			{name: "zero-length close", fin: true, opcode: OpcodeClose, length: 0},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				var wh Header
				wh.SetFlagFIN(tc.fin)
				wh.SetOpcode(tc.opcode)
				assert.NoError(t, wh.SetLength(tc.length))
				if tc.mask != nil {
					wh.SetMask(*tc.mask)
				}

				var buf bytes.Buffer
				assert.NoError(t, WriteHeader(&buf, &wh))

				var rh Header
				assert.NoError(t, ReadHeader(bufio.NewReader(&buf), &rh))
				assert.Equal(t, tc.fin, rh.FlagFIN())
				assert.Equal(t, tc.opcode, rh.Opcode())
				assert.Equal(t, tc.length, rh.Length())
				if tc.mask != nil {
					got, err := rh.Mask()
					assert.NoError(t, err)
					assert.Equal(t, *tc.mask, got)
				}
			})
		}
	})

	t.Run("propagates write error", func(t *testing.T) {
		var h Header
		h.SetFlagFIN(true)
		h.SetOpcode(OpcodeText)
		assert.NoError(t, h.SetLength(5))

		var full [0]byte
		err := WriteHeader(fixedWriter(full[:]), &h)
		assert.Error(t, err)
	})
}

type fixedWriter []byte

func (w fixedWriter) Write([]byte) (int, error) {
	return 0, io.ErrShortWrite
}

func TestClear(t *testing.T) {
	var h Header
	h.SetFlagFIN(true)
	h.SetOpcode(OpcodeText)
	assert.NoError(t, h.SetLength(5))
	h.Clear()
	assert.False(t, h.FlagFIN())
	assert.Equal(t, uint8(0), h.Opcode())
	assert.Equal(t, uint64(0), h.Length())
	assert.Equal(t, [14]byte{}, h.buf)
}

func TestFlagFIN(t *testing.T) {
	t.Run("default is false", func(t *testing.T) {
		var h Header
		assert.False(t, h.FlagFIN())
	})

	t.Run("set true", func(t *testing.T) {
		var h Header
		h.SetFlagFIN(true)
		assert.True(t, h.FlagFIN())
	})

	t.Run("set true then false", func(t *testing.T) {
		var h Header
		h.SetFlagFIN(true)
		h.SetFlagFIN(false)
		assert.False(t, h.FlagFIN())
	})

	t.Run("does not clobber opcode", func(t *testing.T) {
		var h Header
		h.SetOpcode(OpcodeBinary)
		h.SetFlagFIN(true)
		assert.Equal(t, uint8(OpcodeBinary), h.Opcode())
		assert.True(t, h.FlagFIN())
	})
}

func TestOpcode(t *testing.T) {
	t.Run("default is zero", func(t *testing.T) {
		var h Header
		assert.Equal(t, uint8(0), h.Opcode())
	})

	t.Run("set each standard opcode", func(t *testing.T) {
		for _, op := range []uint8{
			OpcodeContinue, OpcodeText, OpcodeBinary,
			OpcodeClose, OpcodePing, OpcodePong,
		} {
			var h Header
			h.SetOpcode(op)
			assert.Equal(t, op, h.Opcode())
		}
	})

	t.Run("does not clobber FIN", func(t *testing.T) {
		var h Header
		h.SetFlagFIN(true)
		h.SetOpcode(OpcodePing)
		assert.True(t, h.FlagFIN())
		assert.Equal(t, uint8(OpcodePing), h.Opcode())
	})
}

func TestRSV(t *testing.T) {
	t.Run("default is zero", func(t *testing.T) {
		var h Header
		assert.Equal(t, uint8(0), h.RSV())
	})

	t.Run("set each reserved bit", func(t *testing.T) {
		for _, bit := range []uint8{0x10, 0x20, 0x40} {
			var h Header
			h.SetRSV(bit)
			assert.Equal(t, bit, h.RSV())
		}
	})

	t.Run("set combined bits", func(t *testing.T) {
		var h Header
		h.SetRSV(0x70)
		assert.Equal(t, uint8(0x70), h.RSV())
	})

	t.Run("ignores bits outside the mask", func(t *testing.T) {
		var h Header
		h.SetRSV(0xff)
		assert.Equal(t, uint8(0x70), h.RSV())
		assert.False(t, h.FlagFIN())
		assert.Equal(t, uint8(0), h.Opcode())
	})

	t.Run("does not clobber FIN or opcode", func(t *testing.T) {
		var h Header
		h.SetFlagFIN(true)
		h.SetOpcode(OpcodePing)
		h.SetRSV(0x40)
		assert.True(t, h.FlagFIN())
		assert.Equal(t, uint8(OpcodePing), h.Opcode())
		assert.Equal(t, uint8(0x40), h.RSV())
	})
}

func TestFlagMask(t *testing.T) {
	t.Run("default is false", func(t *testing.T) {
		var h Header
		assert.False(t, h.FlagMask())
	})

	t.Run("set true", func(t *testing.T) {
		var h Header
		h.SetFlagMask(true)
		assert.True(t, h.FlagMask())
	})

	t.Run("set true then false", func(t *testing.T) {
		var h Header
		h.SetFlagMask(true)
		h.SetFlagMask(false)
		assert.False(t, h.FlagMask())
	})

	t.Run("does not clobber length bits", func(t *testing.T) {
		var h Header
		assert.NoError(t, h.SetLength(50))
		h.SetFlagMask(true)
		assert.Equal(t, uint64(50), h.Length())
		assert.True(t, h.FlagMask())
	})
}

func TestSetLengthAndLength(t *testing.T) {
	t.Run("short tier boundaries", func(t *testing.T) {
		for _, length := range []uint64{0, 1, 125} {
			var h Header
			assert.NoError(t, h.SetLength(length))
			assert.Equal(t, length, h.Length())
		}
	})

	t.Run("medium tier boundaries", func(t *testing.T) {
		for _, length := range []uint64{126, 300, math.MaxUint16} {
			var h Header
			assert.NoError(t, h.SetLength(length))
			assert.Equal(t, length, h.Length())
		}
	})

	t.Run("long tier", func(t *testing.T) {
		for _, length := range []uint64{math.MaxUint16 + 1, 1 << 32, math.MaxInt64} {
			var h Header
			assert.NoError(t, h.SetLength(length))
			assert.Equal(t, length, h.Length())
		}
	})

	t.Run("rejects length exceeding MaxInt64", func(t *testing.T) {
		var h Header
		err := h.SetLength(math.MaxInt64 + 1)
		assert.ErrorIs(t, err, ErrLengthTooLarge)
	})

	t.Run("rejects MaxUint64", func(t *testing.T) {
		var h Header
		err := h.SetLength(math.MaxUint64)
		assert.ErrorIs(t, err, ErrLengthTooLarge)
	})
}

func TestMaskAndSetMask(t *testing.T) {
	testMask := [4]byte{0xAA, 0xBB, 0xCC, 0xDD}

	t.Run("Mask returns error when mask flag not set", func(t *testing.T) {
		var h Header
		_, err := h.Mask()
		assert.ErrorIs(t, err, ErrMaskNotSet)
	})

	t.Run("short length tier", func(t *testing.T) {
		var h Header
		assert.NoError(t, h.SetLength(50))
		h.SetMask(testMask)
		assert.True(t, h.FlagMask())
		got, err := h.Mask()
		assert.NoError(t, err)
		assert.Equal(t, testMask, got)
	})

	t.Run("medium length tier", func(t *testing.T) {
		var h Header
		assert.NoError(t, h.SetLength(300))
		h.SetMask(testMask)
		got, err := h.Mask()
		assert.NoError(t, err)
		assert.Equal(t, testMask, got)
	})

	t.Run("long length tier", func(t *testing.T) {
		var h Header
		assert.NoError(t, h.SetLength(70000))
		h.SetMask(testMask)
		got, err := h.Mask()
		assert.NoError(t, err)
		assert.Equal(t, testMask, got)
	})

	t.Run("mask does not overwrite length", func(t *testing.T) {
		var h Header
		assert.NoError(t, h.SetLength(300))
		h.SetMask(testMask)
		assert.Equal(t, uint64(300), h.Length())
	})
}
