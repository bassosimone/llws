// SPDX-License-Identifier: GPL-3.0-or-later

package llws

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/bassosimone/runtimex"
)

// Errors returned by upgrade functions.
var (
	// ErrMethod indicates the client sent a non-GET request.
	ErrMethod = errors.New("llws: method is not GET")

	// ErrNewClientRequest indicates that we cannot create an *http.Request.
	ErrNewClientRequest = errors.New("llws: cannot create client request")

	// ErrUpgrade indicates a missing or incorrect Upgrade or
	// Connection header.
	ErrUpgrade = errors.New("llws: missing upgrade headers")

	// ErrVersion indicates that Sec-WebSocket-Version is not "13".
	ErrVersion = errors.New("llws: unsupported version")

	// ErrKey indicates a missing or malformed Sec-WebSocket-Key.
	ErrKey = errors.New("llws: invalid key")

	// ErrStatus indicates the server did not respond with 101.
	ErrStatus = errors.New("llws: not 101 Switching Protocols")

	// ErrAccept indicates Sec-WebSocket-Accept does not match.
	ErrAccept = errors.New("llws: accept key mismatch")

	// ErrSubprotocol indicates an invalid Sec-WebSocket-Protocol token.
	ErrSubprotocol = errors.New("llws: invalid subprotocol token")

	// ErrExtensions indicates the server responded with a
	// Sec-WebSocket-Extensions header, but we never request extensions.
	ErrExtensions = errors.New("llws: unrequested extensions")

	// ErrUnrequestedSubprotocol indicates a Sec-WebSocket-Protocol value
	// not present in the client's request.
	ErrUnrequestedSubprotocol = errors.New("llws: unrequested subprotocol")
)

// RFC 6455, Section 4.2.2.
const websocketGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

func acceptKey(clientKey string) string {
	h := sha1.New()
	io.WriteString(h, clientKey)
	io.WriteString(h, websocketGUID)
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// IsUpgradeRequest reports whether req looks like a WebSocket upgrade request.
func IsUpgradeRequest(req *http.Request) bool {
	return req.Method == http.MethodGet &&
		headerContains(req.Header, "Connection", "upgrade") &&
		headerContains(req.Header, "Upgrade", "websocket")
}

// UpgradeOfferedSubprotocols is a list of subprotocols offered by the client.
type UpgradeOfferedSubprotocols []string

func newUpgradeOfferedSubprotocols(req *http.Request) UpgradeOfferedSubprotocols {
	already := make(map[string]bool)
	out := UpgradeOfferedSubprotocols{}
	for _, v := range req.Header.Values("Sec-WebSocket-Protocol") {
		for field := range strings.SplitSeq(v, ",") {
			trimmed := asciiTrimOWS(field)
			if trimmed != "" && isToken(trimmed) && !already[trimmed] {
				out = append(out, trimmed)
				already[trimmed] = true
			}
		}
	}
	return out
}

// Contains returns whether sp appears among the request's Sec-WebSocket-Protocol values.
//
// We use case-sensitive comparison here. The RFC explicitly marks Upgrade (Section 4.2.1,
// item 3) and Connection (item 4) as "treated as an ASCII case-insensitive value" but says
// no such thing for Sec-WebSocket-Protocol (item 8). Subprotocol values are tokens registered
// in the IANA registry (Section 11.5), and the server "MUST" select "one of the values from
// the |Sec-WebSocket-Protocol| field" (Section 4.2.2), implying an exact match.
func (uos UpgradeOfferedSubprotocols) Contains(sp string) bool {
	return slices.Contains(uos, sp)
}

// ServerValidateUpgradeRequest validates req as a WebSocket upgrade request
// (RFC 6455 §4.2.1) and returns the offered subprotocols, filtering out invalid
// subprotocol names (Postel's Law).
func ServerValidateUpgradeRequest(req *http.Request) (UpgradeOfferedSubprotocols, error) {
	if req.Method != http.MethodGet {
		return nil, ErrMethod
	}
	if !headerContains(req.Header, "Connection", "upgrade") {
		return nil, ErrUpgrade
	}
	if !headerContains(req.Header, "Upgrade", "websocket") {
		return nil, ErrUpgrade
	}
	if req.Header.Get("Sec-WebSocket-Version") != "13" {
		return nil, ErrVersion
	}

	key := req.Header.Get("Sec-WebSocket-Key")
	decoded, err := base64.StdEncoding.DecodeString(key)
	if err != nil || len(decoded) != 16 {
		return nil, ErrKey
	}

	return newUpgradeOfferedSubprotocols(req), nil
}

// ServerParseUpgradeRequest validates req as a WebSocket upgrade request
// (RFC 6455 §4.2.1). Call after [http.ReadRequest], before [ServerAcceptUpgradeRequest].
//
// Deprecated: prefer using [ServerValidateUpgradeRequest] instead.
func ServerParseUpgradeRequest(req *http.Request) error {
	_, err := ServerValidateUpgradeRequest(req)
	return err
}

// ServerReadUpgradeRequest combines [http.ReadRequest] and [ServerParseUpgradeRequest].
//
// Deprecated: prefer using [http.ReadRequest] followed by [ServerValidateUpgradeRequest] instead.
func ServerReadUpgradeRequest(br *bufio.Reader) (*http.Request, error) {
	req, err := http.ReadRequest(br)
	if err != nil {
		return nil, err
	}
	if err := ServerParseUpgradeRequest(req); err != nil {
		return nil, err
	}
	return req, nil
}

// ServerAcceptUpgradeRequest writes a 101 Switching Protocols response
// (RFC 6455 §4.2.2). The subprotocol, if non-empty, MUST be in the request's
// Sec-WebSocket-Protocol offer (else [ErrUnrequestedSubprotocol]).
//
// If you use [ServerValidateUpgradeRequest] and [UpgradeOfferedSubprotocols.Contains]
// this function cannot fail because of a subprotocol mismatch and the only
// possible failure mode is an I/O error when writing the response to the socket.
//
// On success, the transport is ready for frame I/O.
func ServerAcceptUpgradeRequest(bw *bufio.Writer, req *http.Request, subprotocol string) error {
	key := req.Header.Get("Sec-WebSocket-Key")
	resp := &http.Response{
		StatusCode: http.StatusSwitchingProtocols,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     http.Header{},
	}
	resp.Header.Set("Upgrade", "websocket")
	resp.Header.Set("Connection", "Upgrade")
	resp.Header.Set("Sec-WebSocket-Accept", acceptKey(key))
	if subprotocol != "" {
		if !isToken(subprotocol) {
			return ErrSubprotocol
		}
		if !clientOfferedSubprotocol(req, subprotocol) {
			return ErrUnrequestedSubprotocol
		}
		resp.Header.Set("Sec-WebSocket-Protocol", subprotocol)
	}
	if err := resp.Write(bw); err != nil {
		return err
	}
	return bw.Flush()
}

// ServerRejectUpgradeRequest writes an HTTP error response with statusCode
// and Sec-WebSocket-Version: 13 (RFC 6455 §4.4).
func ServerRejectUpgradeRequest(bw *bufio.Writer, statusCode int) error {
	resp := &http.Response{
		StatusCode: statusCode,
		Status:     http.StatusText(statusCode),
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     http.Header{},
	}
	resp.Header.Set("Sec-WebSocket-Version", "13")
	resp.Header.Set("Connection", "close")
	if err := resp.Write(bw); err != nil {
		return err
	}
	return bw.Flush()
}

// NewClientUpgradeRequest creates the [*http.Request] to upgrade to WebSocket.
//
// Panics if crypto/rand cannot produce the Sec-WebSocket-Key nonce.
func NewClientUpgradeRequest(
	ctx context.Context, targetURL string, subprotocols []string) (*http.Request, error) {
	var nonce [16]byte
	_ = runtimex.PanicOnError1(io.ReadFull(rand.Reader, nonce[:]))
	key := base64.StdEncoding.EncodeToString(nonce[:])

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrNewClientRequest, err)
	}
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Sec-WebSocket-Key", key)
	req.Header.Set("Sec-WebSocket-Version", "13")

	if len(subprotocols) > 0 {
		for _, sp := range subprotocols {
			if !isToken(sp) {
				return nil, ErrSubprotocol
			}
		}
		req.Header.Set("Sec-WebSocket-Protocol", strings.Join(subprotocols, ", "))
	}

	return req, nil
}

// ClientUpgrade performs the WebSocket client handshake (RFC 6455 §4.1):
// sends an upgrade request, reads the 101 response, validates the accept
// key. Returns the negotiated subprotocol ("" if none). An empty userAgent
// suppresses the User-Agent header. On success, rw is ready for frame I/O.
//
// Panics if crypto/rand cannot produce the Sec-WebSocket-Key nonce.
func ClientUpgrade(rw *bufio.ReadWriter, target *url.URL, userAgent string, subprotocols []string) (string, error) {
	// Prepare and send request
	req, err := NewClientUpgradeRequest(context.Background(), target.String(), subprotocols)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", userAgent)

	if err := req.Write(rw); err != nil {
		return "", err
	}
	if err := rw.Flush(); err != nil {
		return "", err
	}

	// Receive and parse response
	resp, err := http.ReadResponse(rw.Reader, req)
	if err != nil {
		return "", err
	}
	resp.Body.Close()

	return ClientParseUpgradeResponse(req, resp)
}

// ClientParseUpgradeResponse parses an [*http.Response] as the response to
// the [*http.Request] returned by [NewClientUpgradeRequest].
//
// Returns the negotiated subprotocol or an error.
func ClientParseUpgradeResponse(req *http.Request, resp *http.Response) (string, error) {
	if resp.StatusCode != http.StatusSwitchingProtocols {
		return "", ErrStatus
	}
	if !headerContains(resp.Header, "Upgrade", "websocket") {
		return "", ErrUpgrade
	}
	if !headerContains(resp.Header, "Connection", "upgrade") {
		return "", ErrUpgrade
	}
	key := acceptKey(req.Header.Get("Sec-WebSocket-Key"))
	if resp.Header.Get("Sec-WebSocket-Accept") != key {
		return "", ErrAccept
	}

	// RFC 6455, Section 4.1 step 5: reject unrequested extensions.
	if resp.Header.Get("Sec-WebSocket-Extensions") != "" {
		return "", ErrExtensions
	}

	// RFC 6455, Section 4.1 step 6: reject unrequested subprotocol.
	subprotocol := resp.Header.Get("Sec-WebSocket-Protocol")
	if subprotocol != "" && !clientOfferedSubprotocol(req, subprotocol) {
		return "", ErrUnrequestedSubprotocol
	}
	return subprotocol, nil
}

// isToken reports whether s is a valid RFC 9110, Section 5.6.2 token.
func isToken(s string) bool {
	if len(s) == 0 {
		return false
	}
	for _, c := range []byte(s) {
		if c <= 0x20 || c >= 0x7f || strings.ContainsRune(`()<>@,;:\"/[]?={}`, rune(c)) {
			return false
		}
	}
	return true
}

// clientOfferedSubprotocol reports whether sp appears among the
// request's Sec-WebSocket-Protocol values.
func clientOfferedSubprotocol(req *http.Request, sp string) bool {
	return newUpgradeOfferedSubprotocols(req).Contains(sp)
}

func headerContains(h http.Header, key, value string) bool {
	for _, v := range h.Values(key) {
		for field := range strings.SplitSeq(v, ",") {
			if asciiEqualFold(asciiTrimOWS(field), value) {
				return true
			}
		}
	}
	return false
}
