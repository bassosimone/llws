# Low-Level WebSocket Primitives

[![GoDoc](https://pkg.go.dev/badge/github.com/bassosimone/llws)](https://pkg.go.dev/github.com/bassosimone/llws) [![Build Status](https://github.com/bassosimone/llws/actions/workflows/go.yml/badge.svg)](https://github.com/bassosimone/llws/actions) [![codecov](https://codecov.io/gh/bassosimone/llws/branch/main/graph/badge.svg)](https://codecov.io/gh/bassosimone/llws)

The `llws` Go package provides low-level WebSocket ([RFC 6455](
https://datatracker.ietf.org/doc/html/rfc6455)) framing primitives: frame
header encoding and decoding, payload masking, and the client and server
opening handshake. It also includes a minimal `Conn` implementation designed
to work well in research contexts such as implementing NDT-like protocols.

```Go
import (
	"fmt"
	"io"
	"log"
	"net"
	"net/url"

	"github.com/bassosimone/llws"
)

conn, err := net.Dial("tcp", "127.0.0.1:8080")
if err != nil {
	log.Fatal(err)
}
defer conn.Close()
rw := llws.NewReadWriter(conn)

target := &url.URL{Scheme: "ws", Host: "127.0.0.1:8080", Path: "/echo"}
if _, err := llws.ClientUpgrade(rw, target, "", nil); err != nil {
	log.Fatal(err)
}

mask := llws.NewMask()
if err := llws.WriteTextFrame(rw, []byte("hello"), &mask); err != nil {
	log.Fatal(err)
}
if err := rw.Flush(); err != nil {
	log.Fatal(err)
}

var h llws.Header
if err := llws.ReadHeader(rw.Reader, &h); err != nil {
	log.Fatal(err)
}
payload := make([]byte, h.PayloadLen())
if _, err := io.ReadFull(rw, payload); err != nil {
	log.Fatal(err)
}
fmt.Println(string(payload))
```

## Installation

To add this package as a dependency to your module:

```sh
go get github.com/bassosimone/llws
```

## Development

To run the tests:

```sh
go test -v .
```

To measure test coverage:

```sh
go test -v -cover .
```

## License

```
SPDX-License-Identifier: GPL-3.0-or-later
```

## History

Adapted from [measurement-kit/libndt](https://github.com/measurement-kit/libndt). Includes
code adapted from the Go standard library (`ascii.go`, `ascii_test.go`).
