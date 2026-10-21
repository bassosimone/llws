// SPDX-License-Identifier: GPL-3.0-or-later

package llws

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
	"math"

	"github.com/bassosimone/runtimex"
)

// MaskPayload XORs body with the 4-byte repeating mask key in place
// per RFC 6455, Section 5.3.
func MaskPayload(body []byte, mask [4]byte) {
	m32 := binary.LittleEndian.Uint32(mask[:])
	m64 := uint64(m32) | uint64(m32)<<32
	n, i := len(body), 0
	for ; i+8 <= n; i += 8 {
		binary.LittleEndian.PutUint64(body[i:],
			binary.LittleEndian.Uint64(body[i:])^m64)
	}
	for j := 0; i < n; i, j = i+1, j+1 {
		body[i] ^= mask[j&3]
	}
}

// DiscardPayload discards the payload of the given [*Header].
//
// Returns [io.ErrUnexpectedEOF] if the reader is exhausted early.
func DiscardPayload(r *bufio.Reader, h *Header) error {
	length := h.Length()
	for length > 0 {
		amount := int(min(math.MaxInt, length))
		count, err := r.Discard(amount)
		length -= uint64(count) // before checking in case discard returns (<count>, io.EOF)
		if err != nil {
			if errors.Is(err, io.EOF) && length > 0 {
				return io.ErrUnexpectedEOF
			}
			return err
		}
	}
	return nil
}

// ReadPayload reads the payload of [*Header] into w. Returns
// [io.ErrUnexpectedEOF] if the reader is exhausted early.
//
// Each call pays an extra memcpy and a heap allocation. For the hot
// path, use io.ReadFull(r, buf) with buf sized to h.Length().
func ReadPayload(r *bufio.Reader, h *Header, w io.Writer) error {
	length := h.Length()
	runtimex.Assert(length <= math.MaxInt64)
	lr := &io.LimitedReader{
		R: r,
		N: int64(length),
	}
	if _, err := io.Copy(w, lr); err != nil {
		return err
	}
	if lr.N > 0 {
		return io.ErrUnexpectedEOF
	}
	return nil
}
