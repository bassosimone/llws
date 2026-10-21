// SPDX-License-Identifier: GPL-3.0-or-later

package llws

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

// loopReader serves the same bytes in a continuous loop so the read benchmarks
// can keep feeding the same pre-built frame to the bufio.Reader.
type loopReader struct {
	data []byte
	pos  int
}

func (r *loopReader) Read(p []byte) (int, error) {
	n := 0
	for n < len(p) {
		if r.pos >= len(r.data) {
			r.pos = 0
		}
		m := copy(p[n:], r.data[r.pos:])
		r.pos += m
		n += m
	}
	return n, nil
}

// memSink is an [io.Writer] that copies bytes into a reusable buffer.
//
// Used by the I/O benchmarks to force memcpy on every Write, unlike
// [io.Discard] which would short-circuit large writes to a no-op.
type memSink struct {
	buf []byte
}

func (s *memSink) Write(p []byte) (int, error) {
	copy(s.buf[:len(p)], p)
	return len(p), nil
}

func BenchmarkMaskPayload(b *testing.B) {
	mask := [4]byte{0x37, 0xfa, 0x21, 0x3d}
	for _, n := range []int{16, 1024, 65536, 1 << 17, 1 << 20, 16 << 20} {
		b.Run(fmt.Sprintf("%d", n), func(b *testing.B) {
			body := make([]byte, n)
			b.SetBytes(int64(n))
			for b.Loop() {
				MaskPayload(body, mask)
			}
		})
	}
}

// BenchmarkReadFrameAndDiscard measures the cost of a receive pattern where
// we read the header and subsequently discard the payload. This receive pattern
// approximates what NDT does when receiving binary messages.
func BenchmarkReadFrameAndDiscard(b *testing.B) {
	for _, n := range []int{16, 1024, 65536, 1 << 17, 1 << 20, 16 << 20} {
		b.Run(fmt.Sprintf("%d", n), func(b *testing.B) {
			var hdr Header
			hdr.SetFlagFIN(true)
			hdr.SetOpcode(OpcodeBinary)
			require.NoError(b, hdr.SetLength(uint64(n)))

			frame := append([]byte(nil), hdr.Slice()...)
			frame = append(frame, make([]byte, n)...)

			br := bufio.NewReaderSize(&loopReader{data: frame}, DefaultReadBufferSize)
			var h Header

			b.SetBytes(int64(n))
			for b.Loop() {
				h.Clear()
				if err := ReadHeader(br, &h); err != nil {
					b.Fatal(err)
				}
				if err := DiscardPayload(br, &h); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkReadFrameAndCopy measures a receive pattern where we read the
// header and then copy the payload. This pattern is what NDT does when
// it cannot dispose of a message but must process it. In reality, NDT only
// does that for (rare) text messages only, so this benchmark is not very
// realistic, but it provides us with a performance baseline.
func BenchmarkReadFrameAndCopy(b *testing.B) {
	for _, n := range []int{16, 1024, 65536, 1 << 17, 1 << 20, 16 << 20} {
		b.Run(fmt.Sprintf("%d", n), func(b *testing.B) {
			var hdr Header
			hdr.SetFlagFIN(true)
			hdr.SetOpcode(OpcodeBinary)
			require.NoError(b, hdr.SetLength(uint64(n)))

			frame := append([]byte(nil), hdr.Slice()...)
			frame = append(frame, make([]byte, n)...)

			br := bufio.NewReaderSize(&loopReader{data: frame}, DefaultReadBufferSize)
			buf := make([]byte, n)
			var h Header

			b.SetBytes(int64(n))
			for b.Loop() {
				h.Clear()
				if err := ReadHeader(br, &h); err != nil {
					b.Fatal(err)
				}
				if _, err := io.ReadFull(br, buf); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkReadFrameAndMatch answers the question: what if, rather than
// reading the header and then reading/discarding the payload, we read the
// frame using a single Read?
//
// Note that the obvious precondition for implementing this in reality is
// assuming that the receiver knows the frame size and that the frame size
// does not scale. This is not how NDT works, but exploring this question
// helps us understand what a hypothetical implementation that wanted to
// minimize the Read calls would look like.
//
// An interesting outcome of this benchmark seems to be that, as soon as
// the fixed unit you're reading is larger than the L2 cache of the machine
// where the benchmark is running, the performance drops. In such a case,
// the [BenchmarkReadFrameAndDiscard] becomes more efficient.
func BenchmarkReadFrameAndMatch(b *testing.B) {
	for _, n := range []int{16, 1024, 65536, 1 << 17, 1 << 20, 16 << 20} {
		b.Run(fmt.Sprintf("%d", n), func(b *testing.B) {
			var hdr Header
			hdr.SetFlagFIN(true)
			hdr.SetOpcode(OpcodeBinary)
			require.NoError(b, hdr.SetLength(uint64(n)))

			expected := append([]byte(nil), hdr.Slice()...)
			hdrLen := len(expected)
			frame := append([]byte(nil), expected...)
			frame = append(frame, make([]byte, n)...)

			src := &loopReader{data: frame}
			buf := make([]byte, hdrLen+n)

			b.SetBytes(int64(n))
			for b.Loop() {
				if _, err := io.ReadFull(src, buf); err != nil {
					b.Fatal(err)
				}
				if !bytes.Equal(buf[:hdrLen], expected) {
					b.Fatal("header mismatch")
				}
			}
		})
	}
}

// BenchmarkWriteFrame measures the per-frame cost of sending a single
// unmasked BINARY frame: WriteHeader + payload write through a bufio.Writer
// into a memcpy sink. There is no minimum-overhead reference counterpart
// because a prebuilt frame written via a single conn.Write has no
// userspace cost to measure beyond what the kernel's TCP stack imposes.
func BenchmarkWriteFrame(b *testing.B) {
	for _, n := range []int{16, 1024, 65536, 1 << 17, 1 << 20, 16 << 20} {
		b.Run(fmt.Sprintf("%d", n), func(b *testing.B) {
			payload := make([]byte, n)
			sink := &memSink{buf: make([]byte, max(n, DefaultWriteBufferSize))}
			bw := bufio.NewWriterSize(sink, DefaultWriteBufferSize)
			var h Header

			b.SetBytes(int64(n))
			for b.Loop() {
				h.Clear()
				h.SetFlagFIN(true)
				h.SetOpcode(OpcodeBinary)
				if err := h.SetLength(uint64(n)); err != nil {
					b.Fatal(err)
				}
				if err := WriteHeader(bw, &h); err != nil {
					b.Fatal(err)
				}
				if _, err := bw.Write(payload); err != nil {
					b.Fatal(err)
				}
			}
			_ = bw.Flush()
		})
	}
}
