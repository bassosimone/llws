// SPDX-License-Identifier: GPL-3.0-or-later

package llws

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bassosimone/runtimex"
)

// Conn is a WebSocket connection wrapping a [net.Conn].
//
// This struct is concurrency safe as long as the following conditions are met:
//
//  1. there is at most one goroutine reading from the [*Conn]
//
//  2. there is at most one goroutine writing to the [*Conn]
//
// Note that concurrent goroutines are always allowed to invoke [*Conn.Close].
//
// Use [NewClientConn] or [NewServerConn] to construct a new [*Conn].
type Conn struct {
	// selected subproto.
	subproto string

	// connection delegation.
	cd net.Conn

	// state variables for reading messages.
	br  *bufio.Reader
	hdr *Header

	// state variables for writing prepared messages.
	omask bool
	w     io.Writer

	// state variables for tracking incoming pings.
	//
	// RFC 6455 §5.5.3 says that we MAY respond only to the
	// latest [OpcodePing] we received.
	pingCh   chan struct{}
	pingFlag atomic.Bool
	pingMsg  []byte
	pingMu   sync.Mutex
}

// NewServerConn constructs a server WebSocket connection. We expect you to invoke this function
// after [ServerAcceptUpgradeRequest] has already been invoked.
//
// This function takes immediate ownership of the [net.Conn]:
//
//  1. the [net.Conn] is closed on failure
//
//  2. you must not use the [net.Conn] anymore with the only exception that a previously
//     registered `defer conn.Close` on the [net.Conn] is permissible
//
// We shed the `brw` buffers and read from the [net.Conn] using [NewReader], so that the read
// buffer size does not depend on who performed the upgrade (e.g., [net/http] hijacking gives
// you a 4 KiB reader). To this end, this function fails if:
//
//  1. there are unflushed data in the `brw` write buffer, which typically indicates that
//     you have not used [ServerAcceptUpgradeRequest] to accept the upgrade
//
//  2. there are buffered data in the `brw` read buffer, which indicates that the client sent
//     data before receiving the response, violating RFC 6455 §4.1
//
// Closing the [*Conn] closes the underlying [net.Conn] as a side effect.
func NewServerConn(conn net.Conn, brw *bufio.ReadWriter) (*Conn, error) {
	// Make sure we can safely shed the write buffer.
	if count := brw.Writer.Buffered(); count > 0 {
		conn.Close()
		return nil, fmt.Errorf("llws: %d bytes of unsent data still in the write buffer", count)
	}

	// Make sure we can safely shed the read buffer.
	if count := brw.Reader.Buffered(); count > 0 {
		conn.Close()
		return nil, fmt.Errorf("llws: %d bytes received before sending the upgrade response", count)
	}

	wsconn := &Conn{
		subproto: "", // unused on the server side
		cd:       conn,
		br:       NewReader(conn),
		hdr:      &Header{},
		omask:    false, // the server does not mask its output
		w:        conn,
		pingCh:   make(chan struct{}, 1), // level triggered event
		pingFlag: atomic.Bool{},
		pingMsg:  nil,
		pingMu:   sync.Mutex{},
	}

	return wsconn, nil
}

// NewClientConn performs the WebSocket upgrade described in the [*http.Request] (typically
// created with [NewClientUpgradeRequest]) using the [net.Conn]. This function takes immediate
// ownership of the [net.Conn]:
//
//  1. the [net.Conn] is closed on failure
//
//  2. you must not use the [net.Conn] anymore with the only exception that a previously
//     registered `defer conn.Close` on the [net.Conn] is permissible
//
// Closing the [*Conn] closes the underlying [net.Conn] as a side effect.
func NewClientConn(conn net.Conn, req *http.Request) (*Conn, error) {
	// Send the HTTP request to upgrade.
	//
	// We do not retain the writer since it is completely flushed
	// once we have finished sending the request.
	//
	// Also, our write pattern is prepared-frame based, so it
	// means we do not need a write buffer.
	bw := NewWriter(conn)
	if err := req.Write(bw); err != nil {
		conn.Close()
		return nil, err
	}
	if err := bw.Flush(); err != nil {
		conn.Close()
		return nil, err
	}

	// Receive and parse the response.
	br := NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		conn.Close()
		return nil, err
	}
	resp.Body.Close()
	subproto, err := ClientParseUpgradeResponse(req, resp)
	if err != nil {
		conn.Close()
		return nil, err
	}

	// Return the websocket conn.
	wsconn := &Conn{
		subproto: subproto,
		cd:       conn,
		br:       br,
		hdr:      &Header{},
		omask:    true, // client MUST mask outgoing frames
		w:        conn,
		pingCh:   make(chan struct{}, 1), // level triggered event
		pingFlag: atomic.Bool{},
		pingMsg:  nil,
		pingMu:   sync.Mutex{},
	}
	return wsconn, nil
}

// NegotiatedProtocol returns:
//
//   - for client connections, the WebSocket protocol that was negotiated or an
//     empty string if none was negotiated.
//
//   - for server connections, always an empty string.
func (c *Conn) NegotiatedProtocol() string {
	return c.subproto
}

// NetConn returns the underlying [net.Conn]. This method is here to allow unwrapping
// to the lowest level [net.Conn] for purposes such as setsockopt/getsockopt. You must
// not use the [net.Conn] returned by this method to do I/O.
func (c *Conn) NetConn() net.Conn {
	return c.cd
}

// Close closes the underlying connection. This method does not send an [OpcodeClose] message
// for you to the peer. To do this, send the message manually. Note that, if the underlying
// [net.Conn] is a [*crypto/tls.Conn], closing the connection will entail network operations to
// close the underlying TLS connection first. Invoking this method interrupts concurrent I/O
// operations and, when this method returns, subsequent I/O operations will fail.
func (c *Conn) Close() error {
	return c.cd.Close()
}

// LocalAddr returns the underlying [net.Conn] local address.
func (c *Conn) LocalAddr() net.Addr {
	return c.cd.LocalAddr()
}

// RemoteAddr returns the underlying [net.Conn] remote address.
func (c *Conn) RemoteAddr() net.Addr {
	return c.cd.RemoteAddr()
}

// SetDeadline sets the underlying [net.Conn] deadline.
func (c *Conn) SetDeadline(t time.Time) error {
	return c.cd.SetDeadline(t)
}

// SetReadDeadline sets the underlying [net.Conn] read deadline.
func (c *Conn) SetReadDeadline(t time.Time) error {
	return c.cd.SetReadDeadline(t)
}

// SetWriteDeadline sets the underlying [net.Conn] write deadline.
func (c *Conn) SetWriteDeadline(t time.Time) error {
	return c.cd.SetWriteDeadline(t)
}

// ErrConnUnexpectedOpcode indicates that [*Conn] has seen an unexpected opcode.
//
// The two most common reasons for this error are: (a) the programmer has not respected the
// read protocol described by [*Conn.ReadHeader] and (b) the peer sent the wrong opcode to the
// wire (e.g. it sent [OpcodeContinue] before [OpcodeText] or [OpcodeBinary]).
var ErrConnUnexpectedOpcode = errors.New("llws: conn got an unexpected opcode")

// ReadHeader reads and returns the opcode of the next frame.
//
// On success, the returned opcode is either [OpcodeText] or [OpcodeBinary]. The other
// opcodes are never returned, because we handle them as follows:
//
//   - [OpcodePing]: we read and store its payload (see [*Conn.IncomingPingChan])
//
//   - [OpcodePong]: we read and discard its payload then continue reading headers
//
//   - [OpcodeClose]: we return an error wrapping [io.EOF]
//
//   - any other opcode: we return an error wrapping [ErrConnUnexpectedOpcode]
//
// # Read Protocol
//
// You must invoke [*Conn.ReadHeader] and inspect the opcode. If you want to discard the
// next message (which may consist of several frames), use [*Conn.DiscardMessage]. Otherwise,
// use the [*Conn.ReadMessage] to read the message. While you could potentially also pass
// [io.Discard] to [*Conn.ReadMessage] to discard a message, we provide [*Conn.DiscardMessage]
// as an optimization to avoid unnecessary memory copies. Once either [*Conn.ReadMessage] or
// [*Conn.DiscardMessage] has returned successfully, call [*Conn.ReadHeader] again.
//
// Not following the above protocol means that the following may happen:
//
//  1. panic if the entry assertions for [*Conn.DiscardMessage] or [*Conn.ReadMessage]
//     are not met (opcode must be either [OpcodeText] or [OpcodeBinary])
//
//  2. [ErrConnUnexpectedOpcode] if the [*Conn.ReadHeader] sees [OpcodeContinue].
func (c *Conn) ReadHeader() (uint8, error) {
	for {
		c.hdr.Clear()
		if err := ReadHeader(c.br, c.hdr); err != nil {
			return 0, err
		}

		switch opcode := c.hdr.Opcode(); opcode {
		case OpcodeText, OpcodeBinary:
			return opcode, nil

		case OpcodePing:
			if err := c.readPingPayload(); err != nil {
				return 0, err
			}
			continue

		case OpcodePong:
			if err := c.readPongPayload(); err != nil {
				return 0, err
			}
			continue

		case OpcodeClose:
			return 0, c.readClosePayload()

		default:
			return opcode, fmt.Errorf("%w: %d", ErrConnUnexpectedOpcode, opcode)
		}
	}
}

// DiscardMessage discards the [OpcodeText] or [OpcodeBinary] message (consisting of 1+
// frames) whose initial frame was previously read by [*Conn.ReadHeader].
//
// We handle [OpcodeClose], [OpcodePing], and [OpcodePong] internally as described
// in the [*Conn.ReadHeader] documentation.
//
// We stop reading when we see a header containing the FIN flag.
//
// We return [ErrConnUnexpectedOpcode] if we see continuation frames with [OpcodeText] or
// [OpcodeBinary]: these opcodes are unexpected because continuation frames must always
// use the [OpcodeContinue] opcode according to RFC 6455.
func (c *Conn) DiscardMessage() error {
	runtimex.Assert(c.hdr.Opcode() == OpcodeText || c.hdr.Opcode() == OpcodeBinary)
	for {
		if err := DiscardPayload(c.br, c.hdr); err != nil {
			return err
		}
		if c.hdr.FlagFIN() {
			return nil
		}
		if err := c.nextContinueFrame(); err != nil {
			return err
		}
		runtimex.Assert(c.hdr.Opcode() == OpcodeContinue)
	}
}

func (c *Conn) nextContinueFrame() error {
	for {
		c.hdr.Clear()
		if err := ReadHeader(c.br, c.hdr); err != nil {
			return err
		}

		switch opcode := c.hdr.Opcode(); opcode {
		case OpcodeContinue:
			return nil

		case OpcodePing:
			if err := c.readPingPayload(); err != nil {
				return err
			}
			continue

		case OpcodePong:
			if err := c.readPongPayload(); err != nil {
				return err
			}
			continue

		case OpcodeClose:
			return c.readClosePayload()

		default:
			return fmt.Errorf("%w: %d", ErrConnUnexpectedOpcode, opcode)
		}
	}
}

// ErrMessageTooLarge indicates that [*Conn.ReadMessage] attempted to read a
// message larger than the `maxSize` argument it was passed.
var ErrMessageTooLarge = errors.New("llws: message too large")

// ReadMessage is like [*Conn.DiscardMessage] except that we do not discard the frames
// payload, but rather we accumulate it inside the [io.Writer]. If the payload has a
// mask, we unconditionally apply the mask. This design choice violates the letter of
// the RFC with respect to which party should mask and what should happen when a
// mask is received when it is not expected, but follows Postel's Law.
//
// The `maxSize` parameter limits how large the message could be. We return the
// [ErrMessageTooLarge] if this limit is violated.
//
// If we receive [OpcodeClose] while reading continuation frames we return an error
// wrapping [io.EOF] and the [io.Writer] will contain a partial message.
//
// You can potentially discard payloads passing [io.Discard] to this method, as opposed
// to using [*Conn.DiscardMessage]. However, note that doing this:
//
//  1. causes the frame payload to be copied into a temporary buffer
//
//  2. also causes the payload to be unmasked if needed
//
// Therefore, [*Conn.DiscardMessage] is recommended when performance matters. Honestly, this
// is probably only useful when you are implementing something NDT-like.
func (c *Conn) ReadMessage(w io.Writer, maxSize uint64) error {
	runtimex.Assert(c.hdr.Opcode() == OpcodeText || c.hdr.Opcode() == OpcodeBinary)
	var total uint64
	for {
		if c.hdr.PayloadLen() > maxSize-total {
			return ErrMessageTooLarge
		}
		total += c.hdr.PayloadLen()

		buff, err := c.readFramePayload()
		if err != nil {
			return err
		}
		runtimex.Assert(uint64(buff.Len()) == c.hdr.PayloadLen())

		if _, err := io.Copy(w, buff); err != nil {
			return err
		}

		if c.hdr.FlagFIN() {
			return nil
		}

		if err := c.nextContinueFrame(); err != nil {
			return err
		}
		runtimex.Assert(c.hdr.Opcode() == OpcodeContinue)
	}
}

func (c *Conn) readPingPayload() error {
	buff, err := c.readFramePayload()
	if err != nil {
		return err
	}
	payload := buff.Bytes()

	// post within the critical section to synchronize state
	// updates with respect to the channel
	//
	// we also update the atomic within the critical section
	// for consistency but hasIncomingPing is a lightweight
	// pre-check that only depends on the atomic bool update
	// being visible at the right time
	c.pingMu.Lock()
	select {
	case c.pingCh <- struct{}{}:
	default:
	}
	c.pingFlag.Store(true)
	c.pingMsg = payload
	c.pingMu.Unlock()

	return nil
}

func (c *Conn) hasIncomingPing() bool {
	// unlocked because we want this to be a lightweight check: we do not
	// expect to have many pings, so we should lock the mutex only when we
	// are reasonably certain that there's a pending ping
	return c.pingFlag.Load()
}

// IncomingPingChan returns a channel posted when a pong may be due.
//
// # Ping Handling Strategy
//
// RFC 6455 §5.5.3 says that one MAY elect to respond only to the last ping
// message we received and this implementation does that.
//
// When [*Conn.ReadHeader], [*Conn.DiscardMessage], or [*Conn.ReadMessage] see
// an [OpcodePing], the following happens:
//
//  1. we post on the channel returned by this method
//
//  2. we lock a mutex, store the ping message, and flip an atomic bool to
//     true while still holding the mutex
//
// Once the ping has been recorded, we must send a timely pong. To this end:
//
//  1. if your writer goroutine does not continuously send, you should
//     block on the channel returned by this function, to be unblocked when
//     a pong is due, and, once unblocked, call [*Conn.MaybePong]
//
//  2. if you're sending in a loop [*Conn.WritePreparedFrame] knows
//     about the pong being due, through checking the atomic variable value,
//     and automatically sends the pong
//
// The channel is level triggered so you may get a spurious wakeup when actually
// [*Conn.WritePreparedFrame] has already ponged. This is fine because [*Conn.MaybePong]
// will anyway lock the mutex and perform the more expensive, exact check.
func (c *Conn) IncomingPingChan() <-chan struct{} {
	return c.pingCh
}

func (c *Conn) incomingPing() (data []byte, ok bool) {
	// check and mutate the atomic inside the same critical section
	// so that all these changes become visible together
	c.pingMu.Lock()
	data, ok = c.pingMsg, c.pingFlag.Load()
	c.pingMsg = nil
	c.pingFlag.Store(false)
	c.pingMu.Unlock()
	return
}

func (c *Conn) readPongPayload() error {
	// we do not have a use for pongs yet so we just discard
	return DiscardPayload(c.br, c.hdr)
}

func (c *Conn) readClosePayload() error {
	// because this is a measurement oriented library for now it
	// suffices to return [io.EOF] on close without making it very
	// easy to figure out the reason for closing
	buff, err := c.readFramePayload()
	if err != nil {
		return err
	}
	return fmt.Errorf("%w: %v", io.EOF, buff.Bytes())
}

func (c *Conn) readFramePayload() (*bytes.Buffer, error) {
	var buff bytes.Buffer
	if err := ReadPayload(c.br, c.hdr, &buff); err != nil {
		return nil, err
	}
	payload := buff.Bytes()
	if mask, err := c.hdr.Mask(); err == nil { // Postel's Law
		MaskPayload(payload, mask)
	}
	return &buff, nil
}

// PrepareCloseFrame returns a prepared [OpcodeClose] frame with the given status code.
func (c *Conn) PrepareCloseFrame(statusCode uint16) []byte {
	return c.prepareMessage(OpcodeClose, closeFramePayload(statusCode))
}

// PrepareTextFrame returns a prepared [OpcodeText] frame with the given payload.
func (c *Conn) PrepareTextFrame(payload []byte) []byte {
	return c.prepareMessage(OpcodeText, payload)
}

// PrepareBinaryFrame returns a prepared [OpcodeBinary] frame with the given payload.
func (c *Conn) PrepareBinaryFrame(payload []byte) []byte {
	return c.prepareMessage(OpcodeBinary, payload)
}

func (c *Conn) prepareMessage(opcode uint8, payload []byte) []byte {
	// We use this implementation, as opposed to using doWriteFrame directly, to
	// avoid mutating the payload in place

	var header Header
	header.SetFlagFIN(true)
	header.SetOpcode(opcode)
	runtimex.PanicOnError0(header.SetPayloadLen(uint64(len(payload))))
	if c.omask {
		header.SetMask(NewMask())
	}

	hs := header.Slice()
	runtimex.Assert(len(payload) <= math.MaxInt-len(hs))
	frame := make([]byte, 0, len(hs)+len(payload))
	frame = append(frame, hs...)
	frame = append(frame, payload...)
	if mask, err := header.Mask(); err == nil {
		MaskPayload(frame[len(hs):], mask)
	}

	return frame
}

// MaybePong emits a pong message if one is due.
//
// See also [*Conn.IncomingPingChan].
func (c *Conn) MaybePong() error {
	// We don't bother checking the atomic here since we assume we have
	// been invoked by a writer that was blocked on the channel
	if data, ok := c.incomingPing(); ok {
		if _, err := c.w.Write(c.prepareMessage(OpcodePong, data)); err != nil {
			return err
		}
	}
	return nil
}

// WritePreparedFrame sends the given message. We assume the frame bytes have
// previously been prepared using one of the following methods:
//
//  1. [*Conn.PrepareTextFrame]
//
//  2. [*Conn.PrepareBinaryFrame]
//
//  3. [*Conn.PrepareCloseFrame]
//
// This method also responds to pending pings; see [*Conn.IncomingPingChan].
//
// Note that RFC 6455 §5.3 says we MUST generate a new mask per frame to protect
// against untrusted browser scripts. So, if you repeatedly send a prepared message,
// you're violating RFC 6455, which is acceptable in a context like NDT, where one
// wants to send data as fast as possible w/o the masking overhead.
func (c *Conn) WritePreparedFrame(message []byte) error {
	if c.hasIncomingPing() { // do the lightweight check first
		if err := c.MaybePong(); err != nil {
			return err
		}
	}
	_, err := c.w.Write(message)
	return err
}
