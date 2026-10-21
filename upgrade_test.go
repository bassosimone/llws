// SPDX-License-Identifier: GPL-3.0-or-later

package llws

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// validUpgradeRequest returns a minimal valid WebSocket upgrade request.
//
// The key is the base64 encoding of 16 zero bytes.
func validUpgradeRequest() string {
	return "GET / HTTP/1.1\r\n" +
		"Host: localhost\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Version: 13\r\n" +
		"Sec-WebSocket-Key: AAAAAAAAAAAAAAAAAAAAAA==\r\n" +
		"\r\n"
}

// validUpgradeRequestWithProtocols is like validUpgradeRequest but adds a
// Sec-WebSocket-Protocol offer with the given (comma-separated) values.
func validUpgradeRequestWithProtocols(protocols string) string {
	return "GET / HTTP/1.1\r\n" +
		"Host: localhost\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Version: 13\r\n" +
		"Sec-WebSocket-Key: AAAAAAAAAAAAAAAAAAAAAA==\r\n" +
		"Sec-WebSocket-Protocol: " + protocols + "\r\n" +
		"\r\n"
}

func readerFor(s string) *bufio.Reader {
	return bufio.NewReader(strings.NewReader(s))
}

// mockServer reads a WebSocket upgrade request from conn, builds a valid 101
// response, applies the optional modifier, and writes it back. It is meant
// to run in a goroutine opposite a ClientUpgrade call on a net.Pipe.
func mockServer(conn net.Conn, modify func(*http.Request, *http.Response)) {
	defer conn.Close()
	br := bufio.NewReader(conn)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	key := req.Header.Get("Sec-WebSocket-Key")
	resp := &http.Response{
		StatusCode: http.StatusSwitchingProtocols,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header: http.Header{
			"Upgrade":              {"websocket"},
			"Connection":           {"Upgrade"},
			"Sec-WebSocket-Accept": {acceptKey(key)},
		},
	}
	if modify != nil {
		modify(req, resp)
	}
	bw := bufio.NewWriter(conn)
	resp.Write(bw)
	bw.Flush()
}

func clientPipe() (rw *bufio.ReadWriter, client net.Conn, server net.Conn) {
	client, server = net.Pipe()
	rw = bufio.NewReadWriter(bufio.NewReader(client), bufio.NewWriter(client))
	return
}

func TestAcceptKey(t *testing.T) {
	// RFC 6455, Section 4.2.2 example
	got := acceptKey("dGhlIHNhbXBsZSBub25jZQ==")
	assert.Equal(t, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", got)
}

func TestIsToken(t *testing.T) {
	t.Run("valid tokens", func(t *testing.T) {
		assert.True(t, isToken("websocket"))
		assert.True(t, isToken("chat"))
		assert.True(t, isToken("x-custom.proto"))
		assert.True(t, isToken("a"))
	})

	t.Run("empty string is not a token", func(t *testing.T) {
		assert.False(t, isToken(""))
	})

	t.Run("rejects spaces", func(t *testing.T) {
		assert.False(t, isToken("hello world"))
	})

	t.Run("rejects delimiters", func(t *testing.T) {
		for _, c := range `()<>@,;:\"/[]?={}` {
			assert.False(t, isToken(string(c)), "should reject %q", string(c))
		}
	})

	t.Run("rejects control characters", func(t *testing.T) {
		assert.False(t, isToken("\x00"))
		assert.False(t, isToken("\x1f"))
		assert.False(t, isToken("\t"))
	})

	t.Run("rejects DEL and non-ASCII", func(t *testing.T) {
		assert.False(t, isToken("\x7f"))
		assert.False(t, isToken("\x80"))
		assert.False(t, isToken("\xfe"))
		assert.False(t, isToken("café"))
	})
}

func TestHeaderContains(t *testing.T) {
	t.Run("single value match", func(t *testing.T) {
		h := http.Header{"Connection": {"Upgrade"}}
		assert.True(t, headerContains(h, "Connection", "upgrade"))
	})

	t.Run("comma-separated list", func(t *testing.T) {
		h := http.Header{"Connection": {"keep-alive, Upgrade"}}
		assert.True(t, headerContains(h, "Connection", "upgrade"))
	})

	t.Run("multiple header lines", func(t *testing.T) {
		h := http.Header{"Connection": {"keep-alive", "Upgrade"}}
		assert.True(t, headerContains(h, "Connection", "upgrade"))
	})

	t.Run("no match", func(t *testing.T) {
		h := http.Header{"Connection": {"keep-alive"}}
		assert.False(t, headerContains(h, "Connection", "upgrade"))
	})

	t.Run("missing header", func(t *testing.T) {
		h := http.Header{}
		assert.False(t, headerContains(h, "Connection", "upgrade"))
	})

	t.Run("case-insensitive key lookup", func(t *testing.T) {
		h := http.Header{"Connection": {"Upgrade"}}
		assert.True(t, headerContains(h, "connection", "upgrade"))
	})
}

func TestIsUpgradeRequest(t *testing.T) {
	type testCase struct {
		name       string
		method     string
		connection string
		upgrade    string
		expect     bool
	}
	cases := []testCase{
		{"all correct", "GET", "Upgrade", "websocket", true},
		{"wrong method", "POST", "Upgrade", "websocket", false},
		{"missing connection", "GET", "", "websocket", false},
		{"missing upgrade", "GET", "Upgrade", "", false},
		{"only method correct", "GET", "", "", false},
		{"only connection correct", "POST", "Upgrade", "", false},
		{"only upgrade correct", "POST", "", "websocket", false},
		{"none correct", "POST", "", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := &http.Request{
				Method: tc.method,
				Header: http.Header{},
			}
			if tc.connection != "" {
				req.Header.Set("Connection", tc.connection)
			}
			if tc.upgrade != "" {
				req.Header.Set("Upgrade", tc.upgrade)
			}
			assert.Equal(t, tc.expect, IsUpgradeRequest(req))
		})
	}
}

func TestServerParseUpgradeRequest(t *testing.T) {
	parseValid := func(t *testing.T) *http.Request {
		t.Helper()
		req, err := http.ReadRequest(readerFor(validUpgradeRequest()))
		assert.NoError(t, err)
		return req
	}

	t.Run("valid request succeeds", func(t *testing.T) {
		req := parseValid(t)
		assert.NoError(t, ServerParseUpgradeRequest(req))
	})

	t.Run("rejects POST method", func(t *testing.T) {
		req := parseValid(t)
		req.Method = http.MethodPost
		assert.ErrorIs(t, ServerParseUpgradeRequest(req), ErrMethod)
	})

	t.Run("rejects missing Connection header", func(t *testing.T) {
		req := parseValid(t)
		req.Header.Del("Connection")
		assert.ErrorIs(t, ServerParseUpgradeRequest(req), ErrUpgrade)
	})

	t.Run("rejects missing Upgrade header", func(t *testing.T) {
		req := parseValid(t)
		req.Header.Del("Upgrade")
		assert.ErrorIs(t, ServerParseUpgradeRequest(req), ErrUpgrade)
	})

	t.Run("rejects wrong version", func(t *testing.T) {
		req := parseValid(t)
		req.Header.Set("Sec-WebSocket-Version", "8")
		assert.ErrorIs(t, ServerParseUpgradeRequest(req), ErrVersion)
	})

	t.Run("rejects missing key", func(t *testing.T) {
		req := parseValid(t)
		req.Header.Del("Sec-WebSocket-Key")
		assert.ErrorIs(t, ServerParseUpgradeRequest(req), ErrKey)
	})

	t.Run("rejects key with wrong decoded length", func(t *testing.T) {
		req := parseValid(t)
		req.Header.Set("Sec-WebSocket-Key", "AAAA")
		assert.ErrorIs(t, ServerParseUpgradeRequest(req), ErrKey)
	})

	t.Run("rejects invalid base64 key", func(t *testing.T) {
		req := parseValid(t)
		req.Header.Set("Sec-WebSocket-Key", "!!!invalid!!!")
		assert.ErrorIs(t, ServerParseUpgradeRequest(req), ErrKey)
	})
}

func TestServerReadUpgradeRequest(t *testing.T) {
	t.Run("valid request succeeds", func(t *testing.T) {
		req, err := ServerReadUpgradeRequest(readerFor(validUpgradeRequest()))
		assert.NoError(t, err)
		assert.Equal(t, "/", req.URL.Path)
	})

	t.Run("malformed HTTP returns error", func(t *testing.T) {
		_, err := ServerReadUpgradeRequest(readerFor("NOT HTTP\r\n\r\n"))
		assert.Error(t, err)
	})

	t.Run("propagates parse error", func(t *testing.T) {
		raw := strings.Replace(validUpgradeRequest(), "GET", "POST", 1)
		_, err := ServerReadUpgradeRequest(readerFor(raw))
		assert.ErrorIs(t, err, ErrMethod)
	})
}

func TestServerAcceptUpgradeRequest(t *testing.T) {
	t.Run("writes valid 101 response", func(t *testing.T) {
		req, err := ServerReadUpgradeRequest(readerFor(validUpgradeRequest()))
		assert.NoError(t, err)

		var buf bytes.Buffer
		bw := bufio.NewWriter(&buf)
		err = ServerAcceptUpgradeRequest(bw, req, "")
		assert.NoError(t, err)

		resp, err := http.ReadResponse(bufio.NewReader(&buf), req)
		assert.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusSwitchingProtocols, resp.StatusCode)
		assert.Equal(t, "websocket", resp.Header.Get("Upgrade"))
		assert.Equal(t, "Upgrade", resp.Header.Get("Connection"))
		expectedAccept := acceptKey(req.Header.Get("Sec-WebSocket-Key"))
		assert.Equal(t, expectedAccept, resp.Header.Get("Sec-WebSocket-Accept"))
		assert.Empty(t, resp.Header.Get("Sec-WebSocket-Protocol"))
	})

	t.Run("includes valid subprotocol", func(t *testing.T) {
		req, err := ServerReadUpgradeRequest(readerFor(validUpgradeRequestWithProtocols("chat")))
		assert.NoError(t, err)

		var buf bytes.Buffer
		bw := bufio.NewWriter(&buf)
		err = ServerAcceptUpgradeRequest(bw, req, "chat")
		assert.NoError(t, err)

		resp, err := http.ReadResponse(bufio.NewReader(&buf), req)
		assert.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, "chat", resp.Header.Get("Sec-WebSocket-Protocol"))
	})

	t.Run("picks one from a multi-value offer", func(t *testing.T) {
		req, err := ServerReadUpgradeRequest(readerFor(validUpgradeRequestWithProtocols("chat, json")))
		assert.NoError(t, err)

		var buf bytes.Buffer
		bw := bufio.NewWriter(&buf)
		err = ServerAcceptUpgradeRequest(bw, req, "json")
		assert.NoError(t, err)
	})

	t.Run("rejects subprotocol not in client offer", func(t *testing.T) {
		req, err := ServerReadUpgradeRequest(readerFor(validUpgradeRequest()))
		assert.NoError(t, err)

		var buf bytes.Buffer
		bw := bufio.NewWriter(&buf)
		err = ServerAcceptUpgradeRequest(bw, req, "chat")
		assert.ErrorIs(t, err, ErrUnrequestedSubprotocol)
	})

	t.Run("rejects subprotocol with different casing than offer", func(t *testing.T) {
		req, err := ServerReadUpgradeRequest(readerFor(validUpgradeRequestWithProtocols("chat")))
		assert.NoError(t, err)

		var buf bytes.Buffer
		bw := bufio.NewWriter(&buf)
		err = ServerAcceptUpgradeRequest(bw, req, "CHAT")
		assert.ErrorIs(t, err, ErrUnrequestedSubprotocol)
	})

	t.Run("rejects invalid subprotocol token", func(t *testing.T) {
		req, err := ServerReadUpgradeRequest(readerFor(validUpgradeRequest()))
		assert.NoError(t, err)

		var buf bytes.Buffer
		bw := bufio.NewWriter(&buf)
		err = ServerAcceptUpgradeRequest(bw, req, "not valid")
		assert.ErrorIs(t, err, ErrSubprotocol)
	})

	t.Run("propagates write error", func(t *testing.T) {
		req, err := ServerReadUpgradeRequest(readerFor(validUpgradeRequest()))
		assert.NoError(t, err)

		client, server := net.Pipe()
		client.Close()
		server.Close()
		bw := bufio.NewWriterSize(server, 1)
		// Force a flush failure by writing to a closed pipe
		err = ServerAcceptUpgradeRequest(bw, req, "")
		assert.Error(t, err)
	})
}

func TestServerRejectUpgradeRequest(t *testing.T) {
	t.Run("writes 400 rejection", func(t *testing.T) {
		var buf bytes.Buffer
		bw := bufio.NewWriter(&buf)
		err := ServerRejectUpgradeRequest(bw, http.StatusBadRequest)
		assert.NoError(t, err)

		resp, err := http.ReadResponse(bufio.NewReader(&buf), nil)
		assert.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		assert.Equal(t, "13", resp.Header.Get("Sec-WebSocket-Version"))
		assert.True(t, resp.Close)
	})

	t.Run("writes 403 rejection", func(t *testing.T) {
		var buf bytes.Buffer
		bw := bufio.NewWriter(&buf)
		err := ServerRejectUpgradeRequest(bw, http.StatusForbidden)
		assert.NoError(t, err)

		resp, err := http.ReadResponse(bufio.NewReader(&buf), nil)
		assert.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	})

	t.Run("propagates write error", func(t *testing.T) {
		client, server := net.Pipe()
		client.Close()
		server.Close()
		bw := bufio.NewWriterSize(server, 1)
		err := ServerRejectUpgradeRequest(bw, http.StatusBadRequest)
		assert.Error(t, err)
	})
}

func TestClientUpgrade(t *testing.T) {
	target := &url.URL{Scheme: "ws", Host: "localhost", Path: "/ws"}

	t.Run("query string is parsed correctly by server", func(t *testing.T) {
		targetWithQuery := &url.URL{
			Scheme:   "ws",
			Host:     "localhost",
			Path:     "/ndt/v8/download",
			RawQuery: "duration=3000&cc=bbr",
		}
		rw, client, server := clientPipe()
		defer client.Close()
		go mockServer(server, func(req *http.Request, resp *http.Response) {
			// The server-side http.ReadRequest must see the query
			// in RawQuery, not baked into Path.
			assert.Equal(t, "/ndt/v8/download", req.URL.Path)
			assert.Equal(t, "duration=3000&cc=bbr", req.URL.RawQuery)
			assert.Equal(t, "3000", req.URL.Query().Get("duration"))
			assert.Equal(t, "bbr", req.URL.Query().Get("cc"))
		})

		_, err := ClientUpgrade(rw, targetWithQuery, "test-agent", nil)
		assert.NoError(t, err)
	})

	t.Run("valid handshake succeeds", func(t *testing.T) {
		rw, client, server := clientPipe()
		defer client.Close()
		go mockServer(server, nil)

		sp, err := ClientUpgrade(rw, target, "test-agent", nil)
		assert.NoError(t, err)
		assert.Equal(t, "", sp)
	})

	t.Run("valid handshake with subprotocol", func(t *testing.T) {
		rw, client, server := clientPipe()
		defer client.Close()
		go mockServer(server, func(req *http.Request, resp *http.Response) {
			resp.Header.Set("Sec-WebSocket-Protocol", "chat")
		})

		sp, err := ClientUpgrade(rw, target, "test-agent", []string{"chat"})
		assert.NoError(t, err)
		assert.Equal(t, "chat", sp)
	})

	t.Run("rejects subprotocol with different casing", func(t *testing.T) {
		rw, client, server := clientPipe()
		defer client.Close()
		go mockServer(server, func(_ *http.Request, resp *http.Response) {
			resp.Header.Set("Sec-WebSocket-Protocol", "CHAT")
		})

		_, err := ClientUpgrade(rw, target, "test-agent", []string{"chat"})
		assert.ErrorIs(t, err, ErrUnrequestedSubprotocol)
	})

	t.Run("rejects invalid subprotocol token", func(t *testing.T) {
		var buf bytes.Buffer
		rw := bufio.NewReadWriter(bufio.NewReader(&buf), bufio.NewWriter(&buf))

		_, err := ClientUpgrade(rw, target, "test-agent", []string{"not valid"})
		assert.ErrorIs(t, err, ErrSubprotocol)
	})

	t.Run("rejects non-101 status", func(t *testing.T) {
		rw, client, server := clientPipe()
		defer client.Close()
		go mockServer(server, func(_ *http.Request, resp *http.Response) {
			resp.StatusCode = http.StatusForbidden
		})

		_, err := ClientUpgrade(rw, target, "test-agent", nil)
		assert.ErrorIs(t, err, ErrStatus)
	})

	t.Run("rejects missing Upgrade header", func(t *testing.T) {
		rw, client, server := clientPipe()
		defer client.Close()
		go mockServer(server, func(_ *http.Request, resp *http.Response) {
			resp.Header.Del("Upgrade")
		})

		_, err := ClientUpgrade(rw, target, "test-agent", nil)
		assert.ErrorIs(t, err, ErrUpgrade)
	})

	t.Run("rejects missing Connection header", func(t *testing.T) {
		rw, client, server := clientPipe()
		defer client.Close()
		go mockServer(server, func(_ *http.Request, resp *http.Response) {
			resp.Header.Del("Connection")
		})

		_, err := ClientUpgrade(rw, target, "test-agent", nil)
		assert.ErrorIs(t, err, ErrUpgrade)
	})

	t.Run("rejects wrong accept key", func(t *testing.T) {
		rw, client, server := clientPipe()
		defer client.Close()
		go mockServer(server, func(_ *http.Request, resp *http.Response) {
			resp.Header["Sec-WebSocket-Accept"] = []string{"wrong-key"}
		})

		_, err := ClientUpgrade(rw, target, "test-agent", nil)
		assert.ErrorIs(t, err, ErrAccept)
	})

	t.Run("rejects unrequested extensions", func(t *testing.T) {
		rw, client, server := clientPipe()
		defer client.Close()
		go mockServer(server, func(_ *http.Request, resp *http.Response) {
			resp.Header.Set("Sec-WebSocket-Extensions", "permessage-deflate")
		})

		_, err := ClientUpgrade(rw, target, "test-agent", nil)
		assert.ErrorIs(t, err, ErrExtensions)
	})

	t.Run("rejects unrequested subprotocol when none requested", func(t *testing.T) {
		rw, client, server := clientPipe()
		defer client.Close()
		go mockServer(server, func(_ *http.Request, resp *http.Response) {
			resp.Header.Set("Sec-WebSocket-Protocol", "chat")
		})

		_, err := ClientUpgrade(rw, target, "test-agent", nil)
		assert.ErrorIs(t, err, ErrUnrequestedSubprotocol)
	})

	t.Run("rejects wrong subprotocol", func(t *testing.T) {
		rw, client, server := clientPipe()
		defer client.Close()
		go mockServer(server, func(_ *http.Request, resp *http.Response) {
			resp.Header.Set("Sec-WebSocket-Protocol", "binary")
		})

		_, err := ClientUpgrade(rw, target, "test-agent", []string{"chat", "json"})
		assert.ErrorIs(t, err, ErrUnrequestedSubprotocol)
	})

	t.Run("request write fails on closed connection", func(t *testing.T) {
		client, server := net.Pipe()
		server.Close()
		rw := bufio.NewReadWriter(
			bufio.NewReader(client),
			bufio.NewWriterSize(client, 1),
		)
		defer client.Close()

		_, err := ClientUpgrade(rw, target, "test-agent", nil)
		assert.Error(t, err)
	})

	t.Run("flush fails on closed connection", func(t *testing.T) {
		client, server := net.Pipe()
		server.Close()
		rw := bufio.NewReadWriter(
			bufio.NewReader(client),
			bufio.NewWriterSize(client, 4096),
		)
		defer client.Close()

		_, err := ClientUpgrade(rw, target, "test-agent", nil)
		assert.Error(t, err)
	})

	t.Run("read error when server closes without responding", func(t *testing.T) {
		rw, client, server := clientPipe()
		defer client.Close()
		go func() {
			defer server.Close()
			br := bufio.NewReader(server)
			http.ReadRequest(br)
		}()

		_, err := ClientUpgrade(rw, target, "test-agent", nil)
		assert.Error(t, err)
	})

	t.Run("reader preserves bytes after 101 response", func(t *testing.T) {
		// A valid WebSocket TEXT frame "hello" written immediately after
		// the 101 response, simulating a server that pushes data without
		// waiting. ClientUpgrade must leave these bytes intact in rw.Reader.
		sentinel := []byte{0x81, 0x05, 'h', 'e', 'l', 'l', 'o'}

		rw, client, server := clientPipe()
		defer client.Close()
		go func() {
			defer server.Close()
			br := bufio.NewReader(server)
			req, err := http.ReadRequest(br)
			if err != nil {
				return
			}
			resp := &http.Response{
				StatusCode: http.StatusSwitchingProtocols,
				Proto:      "HTTP/1.1",
				ProtoMajor: 1,
				ProtoMinor: 1,
				Header: http.Header{
					"Upgrade":              {"websocket"},
					"Connection":           {"Upgrade"},
					"Sec-WebSocket-Accept": {acceptKey(req.Header.Get("Sec-WebSocket-Key"))},
				},
			}
			bw := bufio.NewWriter(server)
			resp.Write(bw)
			bw.Flush()
			server.Write(sentinel)
		}()

		_, err := ClientUpgrade(rw, target, "test-agent", nil)
		require.NoError(t, err)

		got := make([]byte, len(sentinel))
		_, err = io.ReadFull(rw.Reader, got)
		require.NoError(t, err)
		assert.Equal(t, sentinel, got)
	})
}
