package proxyproto_test

// This file only defines the external behavior-testing contract for the
// optional PROXY protocol v2 CRC32C integrity policy. It deliberately contains
// no CRC algorithm or verification logic of its own: every operation is
// configured and invoked exclusively through the public production API
// (proxyproto.NewCRC32CPolicy and its methods, proxyproto.NewConn /
// proxyproto.Listener). Production API names, internal representation and
// implementation are not constrained by this convention.

import (
	"bufio"
	"io"
	"net"
	"time"

	"github.com/pires/go-proxyproto"
)

// crc32cContractOperations groups the public operations whose external CRC32C
// behavior the contract exercises. The signatures match the ordinary,
// non-policy public entry points so the same behavior tests can run with the
// policy explicitly enabled or disabled.
type crc32cContractOperations struct {
	read              func(*bufio.Reader) (*proxyproto.Header, error)
	readHeaderTimeout func(net.Conn, *bufio.Reader, time.Duration) (*proxyproto.Header, error)
	parseUDPDatagram  func([]byte) (*proxyproto.Header, []byte, error)
	newConn           func(net.Conn) net.Conn
	accept            func(net.Listener) (net.Conn, error)
	format            func(*proxyproto.Header) ([]byte, error)
	writeTo           func(*proxyproto.Header, io.Writer) (int64, error)
}

// newCRC32CContractOperations returns the contract operations bound to the
// public CRC32C policy. enable=true turns verification (reads) and checksum
// emission (format/write) on; enable=false binds the equivalent default,
// non-verifying behavior.
func newCRC32CContractOperations(enable bool) crc32cContractOperations {
	policy := proxyproto.NewCRC32CPolicy(enable)
	return crc32cContractOperations{
		read:              policy.Read,
		readHeaderTimeout: policy.ReadHeaderTimeout,
		parseUDPDatagram:  policy.ParseUDPDatagram,
		newConn: func(conn net.Conn) net.Conn {
			return policy.NewConn(conn)
		},
		accept: func(listener net.Listener) (net.Conn, error) {
			return policy.NewListener(listener).Accept()
		},
		format:  policy.Format,
		writeTo: policy.WriteTo,
	}
}
