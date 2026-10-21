// SPDX-License-Identifier: GPL-3.0-or-later

package llws_test

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"

	"github.com/bassosimone/llws"
	"github.com/bassosimone/runtimex"
)

func Example_serverSendsTextFrames() {
	// We are using a pipe and pretending the websocket handshake
	// already happened over the pipe itself
	client, server := net.Pipe()

	go func() {
		// We use the ReadWriter with recommended buffer sizes
		defer server.Close()
		rw := llws.NewReadWriter(server)

		// We reuse the same header and clear it before usage
		// such that we minimize the heap allocations (the
		// header escapes because the compiler cannot prove
		// that it does not escape inside [io] code).
		var h llws.Header

		for _, msg := range []string{"hello", "websocket", "frame", "world"} {
			// This is the correct order for preparing a server header: clear, then
			// set the fin flag, then the opcode, then the length.
			h.Clear()
			h.SetFlagFIN(true)
			h.SetOpcode(llws.OpcodeText)
			runtimex.PanicOnError0(h.SetLength(uint64(len(msg))))

			// Then you need to write the header and the body and flush.
			runtimex.PanicOnError0(llws.WriteHeader(rw.Writer, &h))
			runtimex.PanicOnError1(rw.WriteString(msg))
			runtimex.PanicOnError0(rw.Flush())
		}

		// Same as above.
		h.Clear()
		h.SetFlagFIN(true)
		h.SetOpcode(llws.OpcodeClose)
		runtimex.PanicOnError0(h.SetLength(0))
		runtimex.PanicOnError0(llws.WriteHeader(rw.Writer, &h))
		runtimex.PanicOnError0(rw.Flush())
	}()

	// We use the ReadWriter with recommended buffer sizes.
	defer client.Close()
	rw := llws.NewReadWriter(client)

	// Same as above: single header with clear before reading
	// to minimize the heap allocations.
	var h llws.Header
	for {
		h.Clear()
		runtimex.PanicOnError0(llws.ReadHeader(rw.Reader, &h))
		if h.Opcode() == llws.OpcodeClose {
			break
		}
		payload := make([]byte, h.Length())
		runtimex.PanicOnError1(io.ReadFull(rw.Reader, payload))
		fmt.Println(string(payload))
	}

	// Output:
	// hello
	// websocket
	// frame
	// world
}

func Example_clientSendsMaskedTextFrames() {
	// We are using a pipe and pretending the websocket handshake
	// already happened over the pipe itself
	client, server := net.Pipe()

	go func() {
		// We use the ReadWriter with recommended buffer sizes
		defer client.Close()
		rw := llws.NewReadWriter(client)

		// We reuse the same header and clear it before usage
		// such that we minimize the heap allocations (the
		// header escapes because the compiler cannot prove
		// that it does not escape inside [io] code).
		var h llws.Header

		for _, msg := range []string{"hello", "websocket", "frame", "world"} {
			// This is the correct order for preparing a client header: clear,
			// then set the fin flag, then the opcode, then the length,
			// and finally the mask (which must come after length because
			// the mask key position depends on the length encoding tier)
			h.Clear()
			h.SetFlagFIN(true)
			h.SetOpcode(llws.OpcodeText)
			runtimex.PanicOnError0(h.SetLength(uint64(len(msg))))

			// Generate a random 4-byte mask key per RFC 6455, Section 5.3
			mask := llws.NewMask()
			h.SetMask(mask)

			// Mask the payload before writing it on the wire
			payload := []byte(msg)
			llws.MaskPayload(payload, mask)

			// Write the header and the masked body and flush
			runtimex.PanicOnError0(llws.WriteHeader(rw.Writer, &h))
			runtimex.PanicOnError1(rw.Writer.Write(payload))
			runtimex.PanicOnError0(rw.Flush())
		}

		// Send a masked close frame
		h.Clear()
		h.SetFlagFIN(true)
		h.SetOpcode(llws.OpcodeClose)
		runtimex.PanicOnError0(h.SetLength(0))
		mask := llws.NewMask()
		h.SetMask(mask)
		runtimex.PanicOnError0(llws.WriteHeader(rw.Writer, &h))
		runtimex.PanicOnError0(rw.Flush())
	}()

	// Server side: read masked frames, unmask, and print
	defer server.Close()
	rw := llws.NewReadWriter(server)

	var h llws.Header
	for {
		h.Clear()
		runtimex.PanicOnError0(llws.ReadHeader(rw.Reader, &h))
		if h.Opcode() == llws.OpcodeClose {
			break
		}

		// Read the masked payload
		payload := make([]byte, h.Length())
		runtimex.PanicOnError1(io.ReadFull(rw.Reader, payload))

		// Extract the mask key and unmask the payload
		mask := runtimex.PanicOnError1(h.Mask())
		llws.MaskPayload(payload, mask)

		fmt.Println(string(payload))
	}

	// Output:
	// hello
	// websocket
	// frame
	// world
}

func Example_handshakeWithSubprotocol() {
	client, server := net.Pipe()

	go func() {
		defer server.Close()
		rw := llws.NewReadWriter(server)

		// Read and validate the client's upgrade request
		req := runtimex.PanicOnError1(llws.ServerReadUpgradeRequest(rw.Reader))

		// The server inspects the requested subprotocols and picks one
		protos := strings.Split(req.Header.Get("Sec-WebSocket-Protocol"), ",")
		chosen := strings.TrimSpace(protos[0])

		// Accept the upgrade with the chosen subprotocol
		runtimex.PanicOnError0(llws.ServerAcceptUpgradeRequest(rw.Writer, req, chosen))

		// From here on, rw is ready for WebSocket frame I/O
	}()

	defer client.Close()
	rw := llws.NewReadWriter(client)

	target := runtimex.PanicOnError1(url.Parse("ws://example.com/path"))
	sp := runtimex.PanicOnError1(llws.ClientUpgrade(rw, target, "example/1.0", []string{"ndt7", "ndt5"}))
	fmt.Println("upgrade successful, subprotocol:", sp)

	// From here on, rw is ready for WebSocket frame I/O

	// Output:
	// upgrade successful, subprotocol: ndt7
}

// Example_fixedSizeDataFlow demonstrates a WebSocket pattern where
// the client and the server agree on a fixed message size in advance
// and then the communication is just sending/receiving the same
// fixed message over and over again. This pattern is not how NDT
// works but it is useful to explore an alternative way in which
// the NDT protocol could potentially work. Benchmarks seem to suggest
// that this pattern is fast as long as the pre-negotiated size is
// lower than the size of the L2 cache.
func Example_fixedSizeDataFlow() {
	const (
		messageSize = 1 << 14
		frameCount  = 4
	)
	sessionMask := [4]byte{0xde, 0xad, 0xbe, 0xef}

	client, server := net.Pipe()

	// Sender (client): handshake, shed bufio, loop conn.Write.
	go func() {
		defer client.Close()
		rw := llws.NewReadWriter(client)
		target := runtimex.PanicOnError1(url.Parse("ws://example.com/"))
		_ = runtimex.PanicOnError1(llws.ClientUpgrade(rw, target, "", nil))

		runtimex.Assert(rw.Reader.Buffered() == 0)
		runtimex.Assert(rw.Writer.Buffered() == 0)
		rw = nil // drop the bufio buffers; the GC will reclaim them

		// Build the masked frame once and reuse across iterations.
		payload := make([]byte, messageSize)
		var buf bytes.Buffer
		runtimex.PanicOnError0(llws.WriteBinaryFrame(&buf, payload, &sessionMask))
		frame := buf.Bytes()

		for range frameCount {
			runtimex.PanicOnError1(client.Write(frame))
		}
	}()

	// Receiver (server): handshake, shed bufio, fast-path read loop.
	defer server.Close()
	rw := llws.NewReadWriter(server)
	req := runtimex.PanicOnError1(llws.ServerReadUpgradeRequest(rw.Reader))
	runtimex.PanicOnError0(llws.ServerAcceptUpgradeRequest(rw.Writer, req, ""))

	runtimex.Assert(rw.Reader.Buffered() == 0)
	runtimex.Assert(rw.Writer.Buffered() == 0)
	rw = nil

	// Header.Slice() returns the exact wire bytes the sender will emit.
	var expectedH llws.Header
	expectedH.SetFlagFIN(true)
	expectedH.SetOpcode(llws.OpcodeBinary)
	runtimex.PanicOnError0(expectedH.SetLength(messageSize))
	expectedH.SetMask(sessionMask)
	expected := append([]byte(nil), expectedH.Slice()...)
	hdrLen := len(expected)

	buf := make([]byte, hdrLen+messageSize)
	for range frameCount {
		runtimex.PanicOnError1(io.ReadFull(server, buf))
		runtimex.Assert(bytes.Equal(buf[:hdrLen], expected))
	}
	fmt.Println("received", frameCount, "fixed-size frames")

	// Output:
	// received 4 fixed-size frames
}
