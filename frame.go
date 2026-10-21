// SPDX-License-Identifier: GPL-3.0-or-later

package llws

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"

	"github.com/bassosimone/runtimex"
)

// ErrNotControlOpcode indicates that [WriteControlFrame] was called with
// an opcode that is not Close, Ping, or Pong.
var ErrNotControlOpcode = errors.New("llws: not a control opcode")

// Close status codes defined by RFC 6455, Section 7.4.1.
//
// Codes 1005 and 1006 are intentionally omitted: the RFC forbids
// sending them in a Close frame.
const (
	StatusNormalClosure   uint16 = 1000
	StatusGoingAway       uint16 = 1001
	StatusProtocolError   uint16 = 1002
	StatusUnsupportedData uint16 = 1003
	StatusInvalidPayload  uint16 = 1007
	StatusPolicyViolation uint16 = 1008
	StatusMessageTooBig   uint16 = 1009
	StatusInternalError   uint16 = 1011
)

// NewMask generates a fresh 4-byte masking key using crypto/rand.
func NewMask() [4]byte {
	var mask [4]byte
	runtimex.PanicOnError1(rand.Read(mask[:]))
	return mask
}

// WriteBinaryFrame writes a complete binary frame.
//
// If maskp is not nil, MUTATES the payload in place to apply the mask.
func WriteBinaryFrame(w io.Writer, payload []byte, maskp *[4]byte) error {
	return doWriteFrame(w, payload, maskp, OpcodeBinary)
}

// WriteTextFrame is like [WriteBinaryFrame] but for text frames.
func WriteTextFrame(w io.Writer, payload []byte, maskp *[4]byte) error {
	return doWriteFrame(w, payload, maskp, OpcodeText)
}

// WriteControlFrame writes a control frame (Close, Ping, or Pong).
//
// Returns [ErrNotControlOpcode] if opcode is not control, or
// [ErrControlFrame] if len(payload) > 125 (RFC 6455 §5.5).
//
// If maskp is not nil, MUTATES the payload in place to apply the mask.
func WriteControlFrame(w io.Writer, opcode uint8, payload []byte, maskp *[4]byte) error {
	switch opcode {
	case OpcodeClose, OpcodePing, OpcodePong:
	default:
		return ErrNotControlOpcode
	}
	if len(payload) > 125 {
		return ErrControlFrame
	}
	return doWriteFrame(w, payload, maskp, opcode)
}

// WriteCloseFrame writes a Close frame carrying statusCode.
//
// If maskp is not nil, masks the 2-byte payload.
func WriteCloseFrame(w io.Writer, statusCode uint16, maskp *[4]byte) error {
	var payload [2]byte
	binary.BigEndian.PutUint16(payload[:], statusCode)
	return WriteControlFrame(w, OpcodeClose, payload[:], maskp)
}

func doWriteFrame(w io.Writer, payload []byte, maskp *[4]byte, opcode uint8) error {
	var header Header
	header.SetFlagFIN(true)
	header.SetOpcode(opcode)
	// Cannot fail: len() returns int, so uint64(len(payload)) <= math.MaxInt64.
	runtimex.PanicOnError0(header.SetLength(uint64(len(payload))))
	if maskp != nil {
		header.SetMask(*maskp)
		MaskPayload(payload, *maskp)
	}
	if err := WriteHeader(w, &header); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}
