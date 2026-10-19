package proxyproto_test

// External behavior tests for the CRC32C integrity policy driven exclusively
// through crc32cContractOperations (the public production API). No CRC
// algorithm is implemented here: valid wire bytes come from policy.Format,
// failure cases are byte-level corruptions or TLV layout construction.

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/pires/go-proxyproto"
)

// crcContractSlowReader delivers one byte at a time.
type crcContractSlowReader struct {
	data []byte
	pos  int
}

func (r *crcContractSlowReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	p[0] = r.data[r.pos]
	r.pos++
	return 1, nil
}

func crcContractV4Header() *proxyproto.Header {
	return proxyproto.HeaderProxyFromAddrs(2,
		&net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 56324},
		&net.TCPAddr{IP: net.ParseIP("10.0.0.2"), Port: 443},
	)
}

// TestCRC32CContractEnabledRoundTrip exercises format+read across PROXY and
// LOCAL layouts, CRC appended or fixed in place, with all seven operations.
func TestCRC32CContractEnabledRoundTrip(t *testing.T) {
	ops := newCRC32CContractOperations(true)

	t.Run("PROXY appended CRC", func(t *testing.T) {
		h := crcContractV4Header()
		raw, err := ops.format(h)
		if err != nil {
			t.Fatalf("format: %v", err)
		}
		if raw[len(raw)-7] != byte(proxyproto.PP2_TYPE_CRC32C) {
			t.Fatal("no CRC TLV appended")
		}
		parsed, err := ops.read(bufio.NewReader(bytes.NewReader(raw)))
		if err != nil {
			t.Fatalf("enabled read rejected formatted header: %v", err)
		}
		if parsed.Version != 2 || parsed.Command != h.Command ||
			parsed.TransportProtocol != h.TransportProtocol ||
			parsed.SourceAddr.String() != h.SourceAddr.String() ||
			parsed.DestinationAddr.String() != h.DestinationAddr.String() {
			t.Fatalf("parsed header differs: %+v vs %+v", parsed, h)
		}
		tlvs, err := parsed.TLVs()
		if err != nil || len(tlvs) != 1 || tlvs[0].Type != proxyproto.PP2_TYPE_CRC32C {
			t.Fatalf("expected one CRC TLV, got %+v err %v", tlvs, err)
		}
	})

	t.Run("existing legal CRC fixed in place, order preserved", func(t *testing.T) {
		h := crcContractV4Header()
		if err := h.SetTLVs([]proxyproto.TLV{
			{Type: proxyproto.PP2_TYPE_ALPN, Value: []byte("h2")},
			{Type: proxyproto.PP2_TYPE_CRC32C, Value: []byte{0xDE, 0xAD, 0xBE, 0xEF}},
			{Type: proxyproto.PP2_TYPE_AUTHORITY, Value: []byte("example.com")},
		}); err != nil {
			t.Fatal(err)
		}
		raw, err := ops.format(h)
		if err != nil {
			t.Fatalf("format: %v", err)
		}
		parsed, err := ops.read(bufio.NewReader(bytes.NewReader(raw)))
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		tlvs, err := parsed.TLVs()
		if err != nil || len(tlvs) != 3 {
			t.Fatalf("TLVs = %+v, err %v", tlvs, err)
		}
		if tlvs[0].Type != proxyproto.PP2_TYPE_ALPN ||
			tlvs[1].Type != proxyproto.PP2_TYPE_CRC32C ||
			tlvs[2].Type != proxyproto.PP2_TYPE_AUTHORITY {
			t.Fatalf("TLV order not preserved: %+v", tlvs)
		}
		if !bytes.Equal(tlvs[2].Value, []byte("example.com")) {
			t.Fatalf("authority value changed: %q", tlvs[2].Value)
		}
	})

	t.Run("LOCAL UNSPEC with CRC", func(t *testing.T) {
		h := &proxyproto.Header{Version: 2, Command: proxyproto.LOCAL, TransportProtocol: proxyproto.UNSPEC}
		if err := h.SetTLVs([]proxyproto.TLV{
			{Type: proxyproto.PP2_TYPE_NOOP, Value: []byte{0xAA, 0xBB}},
		}); err != nil {
			t.Fatal(err)
		}
		raw, err := ops.format(h)
		if err != nil {
			t.Fatalf("format: %v", err)
		}
		parsed, err := ops.read(bufio.NewReader(bytes.NewReader(raw)))
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if !parsed.Command.IsLocal() || parsed.TransportProtocol != proxyproto.UNSPEC {
			t.Fatalf("unexpected header: %+v", parsed)
		}
	})

	t.Run("writeTo matches format", func(t *testing.T) {
		h := crcContractV4Header()
		raw, err := ops.format(h)
		if err != nil {
			t.Fatal(err)
		}
		var buf bytes.Buffer
		n, err := ops.writeTo(h, &buf)
		if err != nil {
			t.Fatalf("writeTo: %v", err)
		}
		if n != int64(len(raw)) || !bytes.Equal(buf.Bytes(), raw) {
			t.Fatal("writeTo output differs from format")
		}
	})
}

// TestCRC32CContractReadRejections covers checksum mismatch and incomplete
// TLV encodings at the read entry point.
func TestCRC32CContractReadRejections(t *testing.T) {
	enabled := newCRC32CContractOperations(true)
	disabled := newCRC32CContractOperations(false)
	h := crcContractV4Header()
	good, err := enabled.format(h)
	if err != nil {
		t.Fatal(err)
	}

	flip := func(pos int) []byte {
		out := bytes.Clone(good)
		out[pos] ^= 0xFF
		return out
	}
	cases := []struct {
		name string
		wire []byte
	}{
		{"corrupt CRC value", flip(len(good) - 1)},
		{"corrupt address byte", flip(16)},
		{"incomplete trailing TLV", withExtraTLVByte(t, good)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := enabled.read(bufio.NewReader(bytes.NewReader(tc.wire))); err == nil {
				t.Fatal("enabled read must reject the header")
			}
			// Disabled policy never verifies (truncated TLV framing is still
			// tolerated by the default parser, which keeps TLVs opaque).
			if _, err := disabled.read(bufio.NewReader(bytes.NewReader(tc.wire))); err != nil {
				t.Fatalf("disabled read must keep default behavior: %v", err)
			}
		})
	}

	t.Run("no CRC accepted", func(t *testing.T) {
		plain, err := h.Format()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := enabled.read(bufio.NewReader(bytes.NewReader(plain))); err != nil {
			t.Fatalf("header without CRC must be accepted: %v", err)
		}
	})

	t.Run("v1 unchanged", func(t *testing.T) {
		v1 := []byte("PROXY TCP4 1.2.3.4 5.6.7.8 80 443\r\n")
		parsed, err := enabled.read(bufio.NewReader(bytes.NewReader(v1)))
		if err != nil {
			t.Fatalf("v1 header rejected under CRC policy: %v", err)
		}
		if parsed.Version != 1 {
			t.Fatalf("version = %d", parsed.Version)
		}
	})
}

// withExtraTLVByte appends one stray TLV byte and bumps the v2 length field so
// the TLV region is incompletely encoded.
func withExtraTLVByte(t *testing.T, raw []byte) []byte {
	t.Helper()
	if !bytes.Equal(raw[:12], proxyproto.SIGV2) {
		t.Fatal("not a v2 header")
	}
	out := bytes.Clone(raw)
	length := binary.BigEndian.Uint16(out[14:16]) + 1
	binary.BigEndian.PutUint16(out[14:16], length)
	out = append(out, 0x01)
	return out
}

// TestCRC32CContractFragmentedAndAppData verifies byte-by-byte delivery over a
// tiny buffer and that application data is not consumed.
func TestCRC32CContractFragmentedAndAppData(t *testing.T) {
	ops := newCRC32CContractOperations(true)
	h := crcContractV4Header()
	raw, err := ops.format(h)
	if err != nil {
		t.Fatal(err)
	}
	app := []byte("application bytes after header")
	wire := append(raw, app...)

	br := bufio.NewReaderSize(&crcContractSlowReader{data: wire}, 16)
	if _, err := ops.read(br); err != nil {
		t.Fatalf("fragmented read: %v", err)
	}
	rest, err := io.ReadAll(br)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rest, app) {
		t.Fatalf("app data altered: %q", rest)
	}
}

// TestCRC32CContractFormatErrors covers duplicate and illegal CRC TLVs and the
// v1 rejection; headers are not modified by failed or repeated formatting.
func TestCRC32CContractFormatErrors(t *testing.T) {
	enabled := newCRC32CContractOperations(true)
	disabled := newCRC32CContractOperations(false)

	mkHeader := func(tlvs ...proxyproto.TLV) *proxyproto.Header {
		h := crcContractV4Header()
		if err := h.SetTLVs(tlvs); err != nil {
			t.Fatal(err)
		}
		return h
	}
	crcTLV := proxyproto.TLV{Type: proxyproto.PP2_TYPE_CRC32C, Value: []byte{1, 2, 3, 4}}

	for _, tc := range []struct {
		name string
		h    *proxyproto.Header
	}{
		{"duplicate", mkHeader(crcTLV, crcTLV)},
		{"three byte value", mkHeader(proxyproto.TLV{Type: proxyproto.PP2_TYPE_CRC32C, Value: []byte{1, 2, 3}})},
		{"five byte value", mkHeader(proxyproto.TLV{Type: proxyproto.PP2_TYPE_CRC32C, Value: []byte{1, 2, 3, 4, 5}})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tlvsBefore, _ := tc.h.TLVs()
			if _, err := enabled.format(tc.h); err == nil {
				t.Fatal("expected format error")
			}
			tlvsAfter, _ := tc.h.TLVs()
			if len(tlvsBefore) != len(tlvsAfter) {
				t.Fatal("header TLVs modified by failed format")
			}
			// Repeated independent valid formatting still works.
			if _, err := enabled.format(crcContractV4Header()); err != nil {
				t.Fatalf("valid format after failure failed: %v", err)
			}
		})
	}

	t.Run("v1 rejected by enabled, accepted by disabled", func(t *testing.T) {
		h := proxyproto.HeaderProxyFromAddrs(1,
			&net.TCPAddr{IP: net.ParseIP("1.1.1.1"), Port: 1},
			&net.TCPAddr{IP: net.ParseIP("2.2.2.2"), Port: 2},
		)
		if _, err := enabled.format(h); err == nil {
			t.Fatal("enabled format must reject v1")
		}
		if _, err := disabled.format(h); err != nil {
			t.Fatalf("disabled format must behave like Format: %v", err)
		}
	})
}

// TestCRC32CContractUDP covers datagram payload independence, immutability,
// rejection and per-datagram independence.
func TestCRC32CContractUDP(t *testing.T) {
	enabled := newCRC32CContractOperations(true)
	disabled := newCRC32CContractOperations(false)
	payload := []byte("independent udp payload")
	h := crcContractV4Header()
	raw, err := enabled.format(h)
	if err != nil {
		t.Fatal(err)
	}
	dgram := append(raw, payload...)
	snapshot := bytes.Clone(dgram)

	parsed, rest, err := enabled.parseUDPDatagram(dgram)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if parsed.SourceAddr.String() != h.SourceAddr.String() ||
		parsed.DestinationAddr.String() != h.DestinationAddr.String() ||
		!bytes.Equal(rest, payload) {
		t.Fatalf("header/payload mismatch: %+v %q", parsed, rest)
	}
	if !bytes.Equal(dgram, snapshot) {
		t.Fatal("datagram mutated")
	}

	// Each datagram is independent: a corrupt one is rejected, a following
	// valid one succeeds.
	bad := bytes.Clone(dgram)
	bad[len(raw)-2] ^= 0x01
	if _, _, err := enabled.parseUDPDatagram(bad); err == nil {
		t.Fatal("corrupt datagram accepted")
	}
	if _, _, err := enabled.parseUDPDatagram(dgram); err != nil {
		t.Fatalf("valid datagram after corrupt one failed: %v", err)
	}
	// Default behavior unchanged.
	if _, _, err := disabled.parseUDPDatagram(bad); err != nil {
		t.Fatalf("disabled parse must not verify: %v", err)
	}
}

// TestCRC32CContractNewConn covers lazy processing and per-connection
// isolation through the newConn hook over a pipe.
func TestCRC32CContractNewConn(t *testing.T) {
	enabled := newCRC32CContractOperations(true)
	good, err := enabled.format(crcContractV4Header())
	if err != nil {
		t.Fatal(err)
	}
	bad := bytes.Clone(good)
	bad[len(good)-1] ^= 0xFF

	servePipe := func(wire, trailing []byte) (net.Conn, func()) {
		server, client := net.Pipe()
		done := make(chan struct{})
		go func() {
			_, _ = client.Write(wire)
			if len(trailing) > 0 {
				_, _ = client.Write(trailing)
			}
			_ = client.Close()
			close(done)
		}()
		return server, func() {
			_ = server.Close()
			<-done
		}
	}

	server, wait := servePipe(bad, nil)
	c := enabled.newConn(server)
	if _, err := c.Read(make([]byte, 32)); err == nil {
		t.Fatal("invalid CRC must surface an ordinary error on first read")
	}
	if _, err := c.Read(make([]byte, 32)); err == nil {
		t.Fatal("failure must stick for the same connection")
	}
	wait()

	server2, wait2 := servePipe(good, []byte("trailing"))
	c2 := enabled.newConn(server2)
	got, err := io.ReadAll(c2)
	if err != nil {
		t.Fatalf("independent valid connection failed: %v", err)
	}
	if string(got) != "trailing" {
		t.Fatalf("payload = %q", got)
	}
	wait2()
}

// TestCRC32CContractAccept covers the accept hook over a real TCP listener.
func TestCRC32CContractAccept(t *testing.T) {
	enabled := newCRC32CContractOperations(true)
	good, err := enabled.format(crcContractV4Header())
	if err != nil {
		t.Fatal(err)
	}
	bad := bytes.Clone(good)
	bad[len(good)-4] ^= 0x01

	round := func(wire, trailing []byte) error {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = ln.Close() }()

		type res struct {
			c   net.Conn
			err error
		}
		ch := make(chan res, 1)
		go func() {
			c, err := enabled.accept(ln)
			ch <- res{c, err}
		}()

		cli, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = cli.Close() }()
		if _, err := cli.Write(wire); err != nil {
			t.Fatal(err)
		}
		if len(trailing) > 0 {
			if _, err := cli.Write(trailing); err != nil {
				t.Fatal(err)
			}
		}
		r := <-ch
		if r.err != nil {
			t.Fatalf("accept: %v", r.err)
		}
		defer func() { _ = r.c.Close() }()
		buf := make([]byte, 64)
		n, err := r.c.Read(buf)
		if err != nil {
			return err
		}
		if !bytes.Equal(buf[:n], trailing) {
			return io.ErrUnexpectedEOF
		}
		return nil
	}

	if err := round(good, []byte("http")); err != nil {
		t.Fatalf("valid header must be accepted: %v", err)
	}
	if err := round(bad, nil); err == nil {
		t.Fatal("invalid CRC must fail the first read")
	}
}

// TestCRC32CContractReadHeaderTimeout covers the timeout entry point.
func TestCRC32CContractReadHeaderTimeout(t *testing.T) {
	enabled := newCRC32CContractOperations(true)
	good, err := enabled.format(crcContractV4Header())
	if err != nil {
		t.Fatal(err)
	}
	bad := bytes.Clone(good)
	bad[len(good)-1] ^= 0xAA

	check := func(wire []byte, wantErr bool) {
		server, client := net.Pipe()
		go func() {
			_, _ = client.Write(wire)
		}()
		_, err := enabled.readHeaderTimeout(server, bufio.NewReader(server), 5*time.Second)
		_ = server.Close()
		_ = client.Close()
		if wantErr && err == nil {
			t.Fatal("expected verification error")
		}
		if !wantErr && err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}
	check(good, false)
	check(bad, true)
}

// TestCRC32CContractDisabledIsDefault pins behavioral equivalence when the
// policy is off through the hook itself.
func TestCRC32CContractDisabledIsDefault(t *testing.T) {
	ops := newCRC32CContractOperations(false)
	h := crcContractV4Header()
	raw, err := h.Format()
	if err != nil {
		t.Fatal(err)
	}
	// Enabled-emitted header (with a CRC) is accepted wholesale when disabled.
	enabled := newCRC32CContractOperations(true)
	withCRC, err := enabled.format(h)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(raw, withCRC) {
		t.Fatal("test setup: enabled format should add a CRC TLV")
	}
	if _, err := ops.read(bufio.NewReader(bytes.NewReader(withCRC))); err != nil {
		t.Fatalf("disabled read must not verify: %v", err)
	}
	out, err := ops.format(h)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, raw) {
		t.Fatal("disabled format must not add a CRC TLV")
	}
	// No-signature data keeps its ErrNoProxyProtocol on both policies.
	if _, err := ops.read(bufio.NewReader(bytes.NewReader([]byte("plain")))); !errors.Is(err, proxyproto.ErrNoProxyProtocol) {
		t.Fatalf("want ErrNoProxyProtocol, got %v", err)
	}
}
