// SPDX-License-Identifier: GPL-3.0-or-later

package llws

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestConn returns a [*Conn] reading the given input and writing into output.
func newTestConn(input []byte, output io.Writer, omask bool) *Conn {
	return &Conn{
		br:     bufio.NewReader(bytes.NewReader(input)),
		hdr:    &Header{},
		omask:  omask,
		w:      output,
		pingCh: make(chan struct{}, 1),
	}
}

// testFrame encodes a single frame, masking it when maskp is not nil.
//
// Unlike [WriteBinaryFrame], it allows clearing FIN and does not mutate payload.
func testFrame(fin bool, opcode uint8, payload string, maskp *[4]byte) []byte {
	var h Header
	h.SetFlagFIN(fin)
	h.SetOpcode(opcode)
	if err := h.SetPayloadLen(uint64(len(payload))); err != nil {
		panic(err)
	}
	if maskp != nil {
		h.SetMask(*maskp)
	}
	hs := h.Slice()
	frame := append(append([]byte{}, hs...), payload...)
	if maskp != nil {
		MaskPayload(frame[len(hs):], *maskp)
	}
	return frame
}

// hugeFrameHeader encodes a binary FIN frame header announcing 1<<40 bytes
// of payload without the payload itself.
func hugeFrameHeader() []byte {
	var h Header
	h.SetFlagFIN(true)
	h.SetOpcode(OpcodeBinary)
	if err := h.SetPayloadLen(1 << 40); err != nil {
		panic(err)
	}
	return append([]byte{}, h.Slice()...)
}

// readTestFrame reads a frame written by the [*Conn] and returns its
// header and its unmasked payload.
func readTestFrame(t *testing.T, br *bufio.Reader) (*Header, string) {
	t.Helper()
	var h Header
	require.NoError(t, ReadHeader(br, &h))
	var payload bytes.Buffer
	require.NoError(t, ReadPayload(br, &h, &payload))
	data := payload.Bytes()
	if mask, err := h.Mask(); err == nil {
		MaskPayload(data, mask)
	}
	return &h, string(data)
}

// trailerFrame is appended to the input of read tests so that, on success,
// we can check that the stream is still in sync after the method returns.
var trailerFrame = testFrame(true, OpcodeBinary, "next", nil)

// requireTrailer checks that the next message is trailerFrame.
func requireTrailer(t *testing.T, c *Conn) {
	t.Helper()
	opcode, err := c.ReadHeader()
	require.NoError(t, err)
	require.Equal(t, uint8(OpcodeBinary), opcode)
	var buff bytes.Buffer
	require.NoError(t, c.ReadMessage(&buff, 1<<20))
	require.Equal(t, "next", buff.String())
}

func TestConnReadHeader(t *testing.T) {
	cases := []struct {
		name       string
		input      [][]byte
		wantOpcode uint8
		wantErr    error
		wantPing   bool
	}{{
		name:       "text frame",
		input:      [][]byte{testFrame(true, OpcodeText, "hello", nil)},
		wantOpcode: OpcodeText,
	}, {
		name:       "binary frame",
		input:      [][]byte{testFrame(true, OpcodeBinary, "hello", nil)},
		wantOpcode: OpcodeBinary,
	}, {
		name:       "non-FIN first fragment",
		input:      [][]byte{testFrame(false, OpcodeText, "hel", nil)},
		wantOpcode: OpcodeText,
	}, {
		name: "skips ping and records it",
		input: [][]byte{
			testFrame(true, OpcodePing, "p", nil),
			testFrame(true, OpcodeText, "hello", nil),
		},
		wantOpcode: OpcodeText,
		wantPing:   true,
	}, {
		name: "skips pong",
		input: [][]byte{
			testFrame(true, OpcodePong, "p", nil),
			testFrame(true, OpcodeBinary, "hello", nil),
		},
		wantOpcode: OpcodeBinary,
	}, {
		name:    "close",
		input:   [][]byte{testFrame(true, OpcodeClose, string(closeFramePayload(StatusNormalClosure)), nil)},
		wantErr: io.EOF,
	}, {
		name:    "continue without a first fragment",
		input:   [][]byte{testFrame(true, OpcodeContinue, "hello", nil)},
		wantErr: ErrConnUnexpectedOpcode,
	}, {
		name:    "reserved opcode",
		input:   [][]byte{testFrame(true, 3, "hello", nil)},
		wantErr: ErrConnUnexpectedOpcode,
	}, {
		name:    "empty stream",
		input:   nil,
		wantErr: io.EOF,
	}, {
		name:    "truncated header",
		input:   [][]byte{{0x82}},
		wantErr: io.ErrUnexpectedEOF,
	}, {
		name:    "truncated ping payload",
		input:   [][]byte{testFrame(true, OpcodePing, "ping", nil)[:3]},
		wantErr: io.ErrUnexpectedEOF,
	}, {
		name:    "truncated pong payload",
		input:   [][]byte{testFrame(true, OpcodePong, "pong", nil)[:3]},
		wantErr: io.ErrUnexpectedEOF,
	}, {
		name:    "truncated close payload",
		input:   [][]byte{testFrame(true, OpcodeClose, "xx", nil)[:3]},
		wantErr: io.ErrUnexpectedEOF,
	}}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := newTestConn(bytes.Join(tc.input, nil), io.Discard, true)

			opcode, err := c.ReadHeader()
			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.wantOpcode, opcode)
			assert.Equal(t, tc.wantPing, c.hasIncomingPing())
			assert.Equal(t, tc.wantPing, len(c.IncomingPingChan()) == 1)
		})
	}
}

// readMessageCases are the inputs shared by the ReadMessage and DiscardMessage tests.
//
// The input starts with the first frame of the message. On success, wantMsg is what
// ReadMessage returns. Cases with a nonzero maxSize only apply to ReadMessage.
type readMessageCase struct {
	name     string
	input    [][]byte
	maxSize  uint64
	wantMsg  string
	wantErr  error
	wantPing bool
}

var readMessageCases = []readMessageCase{{
	name:    "single frame",
	input:   [][]byte{testFrame(true, OpcodeText, "hello", nil)},
	wantMsg: "hello",
}, {
	name:    "empty single frame",
	input:   [][]byte{testFrame(true, OpcodeText, "", nil)},
	wantMsg: "",
}, {
	name: "fragmented message",
	input: [][]byte{
		testFrame(false, OpcodeText, "hel", nil),
		testFrame(false, OpcodeContinue, "l", nil),
		testFrame(true, OpcodeContinue, "o", nil),
	},
	wantMsg: "hello",
}, {
	name: "ping between fragments",
	input: [][]byte{
		testFrame(false, OpcodeText, "hel", nil),
		testFrame(true, OpcodePing, "ping", nil),
		testFrame(true, OpcodeContinue, "lo", nil),
	},
	wantMsg:  "hello",
	wantPing: true,
}, {
	name: "pong between fragments",
	input: [][]byte{
		testFrame(false, OpcodeText, "hel", nil),
		testFrame(true, OpcodePong, "pong", nil),
		testFrame(true, OpcodeContinue, "lo", nil),
	},
	wantMsg: "hello",
}, {
	name:    "masked frame is unmasked",
	input:   [][]byte{testFrame(true, OpcodeBinary, "hello", &[4]byte{1, 2, 3, 4})},
	wantMsg: "hello",
}, {
	name: "close between fragments",
	input: [][]byte{
		testFrame(false, OpcodeText, "hel", nil),
		testFrame(true, OpcodeClose, string(closeFramePayload(StatusGoingAway)), nil),
	},
	wantErr: io.EOF,
}, {
	name: "text instead of continue",
	input: [][]byte{
		testFrame(false, OpcodeText, "hel", nil),
		testFrame(true, OpcodeText, "lo", nil),
	},
	wantErr: ErrConnUnexpectedOpcode,
}, {
	name: "binary instead of continue",
	input: [][]byte{
		testFrame(false, OpcodeText, "hel", nil),
		testFrame(true, OpcodeBinary, "lo", nil),
	},
	wantErr: ErrConnUnexpectedOpcode,
}, {
	name:    "truncated payload",
	input:   [][]byte{testFrame(true, OpcodeText, "hello", nil)[:4]},
	wantErr: io.ErrUnexpectedEOF,
}, {
	name:    "stream ends after a non-FIN fragment",
	input:   [][]byte{testFrame(false, OpcodeText, "hel", nil)},
	wantErr: io.EOF,
}, {
	name: "truncated ping between fragments",
	input: [][]byte{
		testFrame(false, OpcodeText, "hel", nil),
		testFrame(true, OpcodePing, "ping", nil)[:3],
	},
	wantErr: io.ErrUnexpectedEOF,
}, {
	name: "truncated pong between fragments",
	input: [][]byte{
		testFrame(false, OpcodeText, "hel", nil),
		testFrame(true, OpcodePong, "pong", nil)[:3],
	},
	wantErr: io.ErrUnexpectedEOF,
}}

func TestConnReadMessage(t *testing.T) {
	cases := append([]readMessageCase{}, readMessageCases...)

	cases = append(cases, []readMessageCase{{
		name:    "message exactly at maxSize",
		input:   [][]byte{testFrame(true, OpcodeText, "hello", nil)},
		maxSize: 5,
		wantMsg: "hello",
	}, {
		name:    "message one byte over maxSize",
		input:   [][]byte{testFrame(true, OpcodeText, "hello", nil)},
		maxSize: 4,
		wantErr: ErrMessageTooLarge,
	}, {
		name: "fragmented message exactly at maxSize",
		input: [][]byte{
			testFrame(false, OpcodeText, "hel", nil),
			testFrame(true, OpcodeContinue, "lo", nil),
		},
		maxSize: 5,
		wantMsg: "hello",
	}, {
		name: "fragmented message over maxSize",
		input: [][]byte{
			testFrame(false, OpcodeText, "hel", nil),
			testFrame(true, OpcodeContinue, "lo", nil),
		},
		maxSize: 4,
		wantErr: ErrMessageTooLarge,
	}, {
		// The payload is missing: getting ErrMessageTooLarge rather than
		// io.ErrUnexpectedEOF shows we check the size before reading.
		name:    "huge announced length is rejected before reading",
		input:   [][]byte{hugeFrameHeader()},
		maxSize: 1 << 20,
		wantErr: ErrMessageTooLarge,
	}}...)

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			input := bytes.Join(tc.input, nil)
			if tc.wantErr == nil {
				input = append(input, trailerFrame...)
			}
			c := newTestConn(input, io.Discard, true)
			_, err := c.ReadHeader()
			require.NoError(t, err)

			maxSize := tc.maxSize
			if maxSize <= 0 {
				maxSize = 1 << 20
			}
			var buff bytes.Buffer
			err = c.ReadMessage(&buff, maxSize)
			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.wantMsg, buff.String())
			assert.Equal(t, tc.wantPing, c.hasIncomingPing())
			requireTrailer(t, c)
		})
	}

	t.Run("propagates writer errors", func(t *testing.T) {
		c := newTestConn(testFrame(true, OpcodeText, "hello", nil), io.Discard, true)
		_, err := c.ReadHeader()
		require.NoError(t, err)
		expected := errors.New("mocked error")
		err = c.ReadMessage(&failWriter{err: expected}, 1<<20)
		require.ErrorIs(t, err, expected)
	})

	t.Run("panics without a previous ReadHeader", func(t *testing.T) {
		c := newTestConn(nil, io.Discard, true)
		assert.Panics(t, func() { c.ReadMessage(io.Discard, 1<<20) })
	})
}

func TestConnDiscardMessage(t *testing.T) {
	for _, tc := range readMessageCases {
		t.Run(tc.name, func(t *testing.T) {
			input := bytes.Join(tc.input, nil)
			if tc.wantErr == nil {
				input = append(input, trailerFrame...)
			}
			c := newTestConn(input, io.Discard, true)
			_, err := c.ReadHeader()
			require.NoError(t, err)

			err = c.DiscardMessage()
			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.wantPing, c.hasIncomingPing())
			requireTrailer(t, c)
		})
	}

	t.Run("panics without a previous ReadHeader", func(t *testing.T) {
		c := newTestConn(nil, io.Discard, true)
		assert.Panics(t, func() { c.DiscardMessage() })
	})
}

func TestConnPrepareFrame(t *testing.T) {
	prepare := map[string]struct {
		opcode uint8
		fn     func(c *Conn, payload []byte) []byte
	}{
		"text":   {OpcodeText, (*Conn).PrepareTextFrame},
		"binary": {OpcodeBinary, (*Conn).PrepareBinaryFrame},
	}

	// The sizes exercise the three payload length encodings.
	sizes := []int{0, 1, 125, 126, 65535, 65536, 100000}

	for name, p := range prepare {
		for _, omask := range []bool{false, true} {
			for _, size := range sizes {
				t.Run(fmt.Sprintf("%s/omask=%v/size=%d", name, omask, size), func(t *testing.T) {
					payload := bytes.Repeat([]byte{0x41}, size)
					orig := bytes.Clone(payload)
					c := newTestConn(nil, io.Discard, omask)

					frame := p.fn(c, payload)

					assert.Equal(t, orig, payload, "payload mutated")
					br := bufio.NewReader(bytes.NewReader(frame))
					h, got := readTestFrame(t, br)
					assert.True(t, h.FlagFIN())
					assert.Equal(t, p.opcode, h.Opcode())
					assert.Equal(t, omask, h.FlagMask())
					assert.Equal(t, string(orig), got)
					assert.Equal(t, 0, br.Buffered())
				})
			}
		}
	}

	t.Run("close", func(t *testing.T) {
		c := newTestConn(nil, io.Discard, true)
		frame := c.PrepareCloseFrame(StatusGoingAway)
		h, got := readTestFrame(t, bufio.NewReader(bytes.NewReader(frame)))
		assert.True(t, h.FlagFIN())
		assert.Equal(t, uint8(OpcodeClose), h.Opcode())
		assert.True(t, h.FlagMask())
		assert.Equal(t, StatusGoingAway, binary.BigEndian.Uint16([]byte(got)))
	})
}

// pingThenText is a stream containing a ping followed by a text message.
func pingThenText(payloads ...string) []byte {
	var frames [][]byte
	for _, p := range payloads {
		frames = append(frames, testFrame(true, OpcodePing, p, nil))
	}
	frames = append(frames, testFrame(true, OpcodeText, "hello", nil))
	return bytes.Join(frames, nil)
}

func TestConnPong(t *testing.T) {
	for _, omask := range []bool{false, true} {
		t.Run(fmt.Sprintf("MaybePong answers a ping once with omask=%v", omask), func(t *testing.T) {
			var output bytes.Buffer
			c := newTestConn(pingThenText("ping"), &output, omask)
			_, err := c.ReadHeader()
			require.NoError(t, err)

			select {
			case <-c.IncomingPingChan():
			default:
				t.Fatal("expected a token on the ping channel")
			}

			require.NoError(t, c.MaybePong())
			br := bufio.NewReader(&output)
			h, got := readTestFrame(t, br)
			assert.Equal(t, uint8(OpcodePong), h.Opcode())
			assert.Equal(t, omask, h.FlagMask())
			assert.Equal(t, "ping", got)

			require.NoError(t, c.MaybePong())
			assert.Equal(t, 0, output.Len()+br.Buffered())
		})
	}

	t.Run("answers only the latest ping", func(t *testing.T) {
		var output bytes.Buffer
		c := newTestConn(pingThenText("first", "second"), &output, true)
		_, err := c.ReadHeader()
		require.NoError(t, err)
		assert.Equal(t, 1, len(c.IncomingPingChan()))

		require.NoError(t, c.MaybePong())
		br := bufio.NewReader(&output)
		_, got := readTestFrame(t, br)
		assert.Equal(t, "second", got)
		assert.Equal(t, 0, output.Len()+br.Buffered())
	})

	t.Run("WritePreparedFrame pongs before the message", func(t *testing.T) {
		var output bytes.Buffer
		c := newTestConn(pingThenText("ping"), &output, true)
		_, err := c.ReadHeader()
		require.NoError(t, err)

		require.NoError(t, c.WritePreparedFrame(c.PrepareBinaryFrame([]byte("data"))))
		br := bufio.NewReader(&output)
		h, got := readTestFrame(t, br)
		assert.Equal(t, uint8(OpcodePong), h.Opcode())
		assert.Equal(t, "ping", got)
		h, got = readTestFrame(t, br)
		assert.Equal(t, uint8(OpcodeBinary), h.Opcode())
		assert.Equal(t, "data", got)
		assert.False(t, c.hasIncomingPing())
	})

	t.Run("WritePreparedFrame without pending ping", func(t *testing.T) {
		var output bytes.Buffer
		c := newTestConn(nil, &output, true)
		frame := c.PrepareBinaryFrame([]byte("data"))
		require.NoError(t, c.WritePreparedFrame(frame))
		assert.Equal(t, frame, output.Bytes())
	})

	t.Run("MaybePong propagates write errors", func(t *testing.T) {
		expected := errors.New("mocked error")
		c := newTestConn(pingThenText("ping"), &failWriter{err: expected}, true)
		_, err := c.ReadHeader()
		require.NoError(t, err)
		require.ErrorIs(t, c.MaybePong(), expected)
	})

	t.Run("WritePreparedFrame propagates pong write errors", func(t *testing.T) {
		expected := errors.New("mocked error")
		c := newTestConn(pingThenText("ping"), &failWriter{err: expected}, true)
		_, err := c.ReadHeader()
		require.NoError(t, err)
		require.ErrorIs(t, c.WritePreparedFrame(c.PrepareBinaryFrame(nil)), expected)
	})

	t.Run("WritePreparedFrame propagates message write errors", func(t *testing.T) {
		expected := errors.New("mocked error")
		c := newTestConn(nil, &failWriter{err: expected}, true)
		require.ErrorIs(t, c.WritePreparedFrame(c.PrepareBinaryFrame(nil)), expected)
	})
}

// closeRecorder is a [net.Conn] recording whether Close was called.
type closeRecorder struct {
	net.Conn
	closed atomic.Bool
}

func (c *closeRecorder) Close() error {
	c.closed.Store(true)
	return c.Conn.Close()
}

// newClientConnPipe returns a request, a [*closeRecorder] for the client side,
// and the server side of a [net.Pipe].
func newClientConnPipe(t *testing.T, subprotocols []string) (*http.Request, *closeRecorder, net.Conn) {
	t.Helper()
	req, err := NewClientUpgradeRequest(context.Background(), "ws://localhost/ws", subprotocols)
	require.NoError(t, err)
	client, server := net.Pipe()
	t.Cleanup(func() { client.Close(); server.Close() })
	return req, &closeRecorder{Conn: client}, server
}

func TestNewClientConn(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		req, client, server := newClientConnPipe(t, []string{"chat"})
		done := make(chan struct{})
		go func() {
			defer close(done)
			mockServer(server, func(_ *http.Request, resp *http.Response) {
				resp.Header.Set("Sec-WebSocket-Protocol", "chat")
			})
		}()

		c, err := NewClientConn(client, req)
		require.NoError(t, err)
		<-done // mockServer has closed its end of the pipe
		assert.Equal(t, "chat", c.NegotiatedProtocol())
		assert.Same(t, client, c.NetConn())
		assert.True(t, c.omask)
		assert.Equal(t, 1, cap(c.pingCh)) // an unbuffered channel loses wakeups
		assert.False(t, client.closed.Load())

		assert.Equal(t, client.LocalAddr(), c.LocalAddr())
		assert.Equal(t, client.RemoteAddr(), c.RemoteAddr())
		// Since the server end is closed, net.Pipe rejects deadlines: getting
		// io.ErrClosedPipe shows that the calls reach the underlying conn.
		deadline := time.Now().Add(time.Hour)
		assert.ErrorIs(t, c.SetDeadline(deadline), io.ErrClosedPipe)
		assert.ErrorIs(t, c.SetReadDeadline(deadline), io.ErrClosedPipe)
		assert.ErrorIs(t, c.SetWriteDeadline(deadline), io.ErrClosedPipe)

		require.NoError(t, c.Close())
		assert.True(t, client.closed.Load())
	})

	t.Run("keeps frames sent right after the response", func(t *testing.T) {
		req, client, server := newClientConnPipe(t, nil)
		go func() {
			defer server.Close()
			sreq, err := http.ReadRequest(bufio.NewReader(server))
			if err != nil {
				return
			}
			key := sreq.Header.Get("Sec-WebSocket-Key")
			data := "HTTP/1.1 101 Switching Protocols\r\n" +
				"Upgrade: websocket\r\n" +
				"Connection: Upgrade\r\n" +
				"Sec-WebSocket-Accept: " + acceptKey(key) + "\r\n" +
				"\r\n" + string(trailerFrame)
			server.Write([]byte(data)) // single write so ReadResponse buffers the frame
		}()

		c, err := NewClientConn(client, req)
		require.NoError(t, err)
		requireTrailer(t, c)
	})

	t.Run("closes the conn when the request cannot be written", func(t *testing.T) {
		req, client, _ := newClientConnPipe(t, nil)
		req.Host, req.URL = "", nil // makes req.Write fail with errMissingHost

		_, err := NewClientConn(client, req)
		require.Error(t, err)
		assert.True(t, client.closed.Load())
	})

	t.Run("closes the conn when flushing fails", func(t *testing.T) {
		req, client, server := newClientConnPipe(t, nil)
		server.Close()

		_, err := NewClientConn(client, req)
		require.ErrorIs(t, err, io.ErrClosedPipe)
		assert.True(t, client.closed.Load())
	})

	t.Run("closes the conn when the response cannot be read", func(t *testing.T) {
		req, client, server := newClientConnPipe(t, nil)
		go func() {
			defer server.Close()
			if _, err := http.ReadRequest(bufio.NewReader(server)); err != nil {
				return
			}
			server.Write([]byte("garbage\r\n\r\n"))
		}()

		_, err := NewClientConn(client, req)
		require.Error(t, err)
		assert.True(t, client.closed.Load())
	})

	t.Run("closes the conn when the response is invalid", func(t *testing.T) {
		req, client, server := newClientConnPipe(t, nil)
		go mockServer(server, func(_ *http.Request, resp *http.Response) {
			resp.StatusCode = http.StatusForbidden
		})

		_, err := NewClientConn(client, req)
		require.ErrorIs(t, err, ErrStatus)
		assert.True(t, client.closed.Load())
	})
}
