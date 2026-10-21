//
// SPDX-License-Identifier: BSD-3-Clause
//
// Adapted-from: https://github.com/measurement-kit/libndt
//

package llws

import (
	"bufio"
	"errors"
	"io"
	"math"

	"github.com/bassosimone/runtimex"
)

// Opcodes defined by RFC 6455, Section 11.8.
const (
	OpcodeContinue = 0
	OpcodeText     = 1
	OpcodeBinary   = 2
	OpcodeClose    = 8
	OpcodePing     = 9
	OpcodePong     = 10
)

// Errors returned by [Header] methods.
var (
	// ErrPayloadLenTooLarge indicates a payload length with the most significant
	// bit set, which RFC 6455, Section 5.2 forbids.
	ErrPayloadLenTooLarge = errors.New("llws: payload length too large")

	// ErrMaskNotSet indicates that [Header.Mask] was called on a frame
	// whose mask bit is not set.
	ErrMaskNotSet = errors.New("llws: mask flag not set")

	// ErrControlFrame indicates a control frame that violates
	// RFC 6455, Section 5.5: payload exceeds 125 bytes or FIN not set.
	ErrControlFrame = errors.New("llws: invalid control frame")
)

// Header is a WebSocket frame header (RFC 6455 §5.2). To reuse a [*Header]
// you MUST call [*Header.Clear] to clear its state ahead of reusing it.
type Header struct {
	buf [14]byte
}

// Clear zeroes the header, preparing it for reuse.
func (h *Header) Clear() {
	clear(h.buf[:])
}

// FlagFIN reports whether the FIN bit is set.
func (h *Header) FlagFIN() bool {
	return (h.buf[0] & 0x80) != 0
}

// SetFlagFIN sets or clears the FIN bit.
func (h *Header) SetFlagFIN(value bool) {
	if value {
		h.buf[0] |= 0x80
	} else {
		h.buf[0] &= 0x7f
	}
}

// RSV returns the three reserved bits in their wire position (mask 0x70).
//
// Their meaning is defined by whichever extension was negotiated in the
// handshake; llws does not interpret them.
func (h *Header) RSV() uint8 {
	return h.buf[0] & 0x70
}

// SetRSV sets the reserved bits from v (mask 0x70).
func (h *Header) SetRSV(v uint8) {
	h.buf[0] |= v & 0x70
}

// Opcode returns the 4-bit opcode field.
func (h *Header) Opcode() uint8 {
	return h.buf[0] & 0x0f
}

// SetOpcode sets the 4-bit opcode field.
func (h *Header) SetOpcode(opcode uint8) {
	runtimex.Assert(opcode <= 0x0f)
	h.buf[0] |= opcode & 0x0f
}

// FlagMask reports whether the mask bit is set.
func (h *Header) FlagMask() bool {
	return (h.buf[1] & 0x80) != 0
}

// SetFlagMask sets or clears the mask bit.
func (h *Header) SetFlagMask(value bool) {
	if value {
		h.buf[1] |= 0x80
	} else {
		h.buf[1] &= 0x7f
	}
}

func (h *Header) len0() uint8 {
	return h.buf[1] & 0x7f
}

// PayloadLen returns the payload length.
func (h *Header) PayloadLen() uint64 {
	length := uint64(h.len0())

	switch length {
	case 0x7e:
		length = uint64(h.buf[2]) << 8
		length |= uint64(h.buf[3])

	case 0x7f:
		length = uint64(h.buf[2]) << 56
		length |= uint64(h.buf[3]) << 48
		length |= uint64(h.buf[4]) << 40
		length |= uint64(h.buf[5]) << 32
		length |= uint64(h.buf[6]) << 24
		length |= uint64(h.buf[7]) << 16
		length |= uint64(h.buf[8]) << 8
		length |= uint64(h.buf[9])
	}

	return length
}

// SetPayloadLen sets the payload length. Returns [ErrPayloadLenTooLarge] if
// value >= 2^63. MUST be called before [Header.SetMask].
func (h *Header) SetPayloadLen(value uint64) error {
	if value > math.MaxInt64 {
		return ErrPayloadLenTooLarge
	}

	switch {
	case value <= 0x7d:
		h.buf[1] |= uint8(value & 0x7f)

	case value <= math.MaxUint16:
		h.buf[1] |= 0x7e
		h.buf[2] = uint8((value >> 8) & 0xff)
		h.buf[3] = uint8(value & 0xff)

	default:
		h.buf[1] |= 0x7f
		h.buf[2] = uint8((value >> 56) & 0xff)
		h.buf[3] = uint8((value >> 48) & 0xff)
		h.buf[4] = uint8((value >> 40) & 0xff)
		h.buf[5] = uint8((value >> 32) & 0xff)
		h.buf[6] = uint8((value >> 24) & 0xff)
		h.buf[7] = uint8((value >> 16) & 0xff)
		h.buf[8] = uint8((value >> 8) & 0xff)
		h.buf[9] = uint8(value & 0xff)
	}

	return nil
}

// Mask returns the 4-byte masking key.
//
// Returns [ErrMaskNotSet] if the mask bit is not set.
func (h *Header) Mask() ([4]byte, error) {
	var mask [4]byte
	if !h.FlagMask() {
		return mask, ErrMaskNotSet
	}

	length := h.len0()
	runtimex.Assert(length <= 0x7f)
	switch {
	case length <= 0x7d:
		mask[0] = h.buf[2]
		mask[1] = h.buf[3]
		mask[2] = h.buf[4]
		mask[3] = h.buf[5]

	case length == 0x7e:
		mask[0] = h.buf[4]
		mask[1] = h.buf[5]
		mask[2] = h.buf[6]
		mask[3] = h.buf[7]

	case length == 0x7f:
		mask[0] = h.buf[10]
		mask[1] = h.buf[11]
		mask[2] = h.buf[12]
		mask[3] = h.buf[13]
	}

	return mask, nil
}

// SetMask sets the 4-byte masking key and the mask flag.
//
// MUST be called after [Header.SetPayloadLen].
func (h *Header) SetMask(mask [4]byte) {
	h.SetFlagMask(true)

	length := h.len0()
	runtimex.Assert(length <= 0x7f)
	switch {
	case length <= 0x7d:
		h.buf[2] = mask[0]
		h.buf[3] = mask[1]
		h.buf[4] = mask[2]
		h.buf[5] = mask[3]

	case length == 0x7e:
		h.buf[4] = mask[0]
		h.buf[5] = mask[1]
		h.buf[6] = mask[2]
		h.buf[7] = mask[3]

	case length == 0x7f:
		h.buf[10] = mask[0]
		h.buf[11] = mask[1]
		h.buf[12] = mask[2]
		h.buf[13] = mask[3]
	}
}

// ReadHeader reads a WebSocket header into h.
//
// Remember to call [*Header.Clear] before reusing a [*Header].
//
// Enforces RFC 6455 §5.2 (64-bit length MSB zero) and §5.5 (control frames
// ≤125 bytes, FIN set). Reserved opcodes and RSV bits pass through. Non-minimal
// length encodings are accepted (Postel's law).
func ReadHeader(r *bufio.Reader, h *Header) error {
	if _, err := io.ReadFull(r, h.buf[:2]); err != nil {
		return err
	}

	len0 := h.len0()

	// RFC 6455, Section 5.5: control frames MUST NOT be fragmented and payload <= 125
	switch h.Opcode() {
	case OpcodeClose, OpcodePing, OpcodePong:
		if len0 > 0x7d || !h.FlagFIN() {
			return ErrControlFrame
		}
	}

	// Branchless computation of how much to read next.
	//
	// The layout is contiguous with two optional sections of bytes:
	//
	//     <base: 2><extLength: 0|2|8><mask: 0|4>
	//
	// Here's an explanation of the algorithm:
	//
	// 1. isExtended is 0x1 for 0x7e and 0x7f and zero otherwise
	// 2. isLong is 0x01 for 0x7f and 0x00 for 0x7e
	// 3. hasMask is 0x01 if the mask bit is set
	// 4. extra becomes the actual extra size to read
	//
	// We're doing this to minimize io.ReadFull calls and to eliminate
	// branches from the length/mask dispatch.
	//
	// Short message frames call io.ReadFull one more time than needed
	// however this code is designed for reading large frames.
	isExtended := uint64(len0+2) >> 7
	isLong := uint64(len0&1) & isExtended
	hasMask := uint64(h.buf[1]) >> 7
	extra := isExtended*2 + isLong*6 + hasMask*4

	// Note that reading h.buf[2:2] short circuits to return (0, nil)
	if _, err := io.ReadFull(r, h.buf[2:2+extra]); err != nil {
		return err
	}

	// RFC 6455, Section 5.2: the most significant bit MUST be zero
	if isLong == 1 && h.buf[2]&0x80 != 0 {
		return ErrPayloadLenTooLarge
	}
	return nil
}

// Slice returns the slice of the heaader buffer that
// should be sent in order to emit this header.
func (h *Header) Slice() []byte {
	length := h.len0()
	runtimex.Assert(length <= 0x7f)
	switch {
	case length <= 0x7d:
		if h.FlagMask() {
			return h.buf[:6]
		}
		return h.buf[:2]

	case length == 0x7e:
		if h.FlagMask() {
			return h.buf[:8]
		}
		return h.buf[:4]

	default:
		if h.FlagMask() {
			return h.buf[:14]
		}
		return h.buf[:10]
	}
}

// WriteHeader writes the [*Header] content into the given [io.Writer].
func WriteHeader(w io.Writer, h *Header) error {
	_, err := w.Write(h.Slice())
	return err
}
