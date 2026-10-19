package proxyproto

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"io"
	"net"
	"testing"
	"time"
)

// testTB is the subset of testing.T/testing.F the fixtures use.
type testTB interface {
	Helper()
	Fatal(args ...any)
	Fatalf(format string, args ...any)
}

// crc32cRef recomputes the CRC32C the tests expect independently from the
// production verification path. The Castagnoli parameters are pinned by
// TestCRC32CCastagnoliCheckValue.
func crc32cRef(t testTB, b []byte) uint32 {
	t.Helper()
	return crc32.Checksum(b, crc32.MakeTable(crc32.Castagnoli))
}

func TestCRC32CCastagnoliCheckValue(t *testing.T) {
	// RFC 3720 / CRC-32C standard check value for "123456789".
	if got := crc32cRef(t, []byte("123456789")); got != 0xE3069283 {
		t.Fatalf("Castagnoli check value = %08x, want e3069283", got)
	}
}

// oneByteReader delivers at most one byte per Read so every parser refill is
// exercised.
type oneByteReader struct {
	data []byte
	pos  int
}

func (r *oneByteReader) Read(p []byte) (int, error) {
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

// crcBaseV4Header is a fully populated PROXY TCPv4 header without TLVs.
func crcBaseV4Header() *Header {
	return &Header{
		Version:           2,
		Command:           PROXY,
		TransportProtocol: TCPv4,
		SourceAddr:        &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 56324},
		DestinationAddr:   &net.TCPAddr{IP: net.ParseIP("10.0.0.2"), Port: 443},
	}
}

// crcWire renders a v2 header whose TLV region is rawTLVs, which must contain
// exactly one zeroed four-byte CRC TLV; it patches in the independently
// computed checksum and returns the complete, spec-valid wire header.
func crcWire(t testTB, h *Header, rawTLVs []byte) []byte {
	t.Helper()
	h.rawTLVs = bytes.Clone(rawTLVs)
	raw, err := h.Format()
	if err != nil {
		t.Fatalf("Format failed: %v", err)
	}
	crc, err := findCRC32CTLV(rawTLVs)
	if err != nil {
		t.Fatalf("findCRC32CTLV failed: %v", err)
	}
	if !crc.found {
		t.Fatal("test setup: expected a CRC TLV in rawTLVs")
	}
	tlvStart := len(raw) - len(rawTLVs)
	off := tlvStart + crc.valueOffset
	sum := crc32cRef(t, raw) // CRC value bytes are zero in raw.
	binary.BigEndian.PutUint32(raw[off:off+crc32cValueSize], sum)
	// Keep the fixture TLV slice identical to what is now on the wire.
	binary.BigEndian.PutUint32(rawTLVs[crc.valueOffset:crc.valueOffset+crc32cValueSize], sum)
	return raw
}

func crcZeroedTLV() []byte {
	return []byte{byte(PP2_TYPE_CRC32C), 0x00, 0x04, 0x00, 0x00, 0x00, 0x00}
}

// TestCRC32CFormatAppends verifies emission for headers without a CRC TLV:
// one is appended, its value matches an independent computation, and the
// emitted bytes verify under the enabled policy and re-format stably.
func TestCRC32CFormatAppends(t *testing.T) {
	h := crcBaseV4Header()
	if err := h.SetTLVs([]TLV{{Type: PP2_TYPE_ALPN, Value: []byte("h2")}}); err != nil {
		t.Fatal(err)
	}

	out, err := formatVersion2WithCRC32C(h)
	if err != nil {
		t.Fatalf("formatVersion2WithCRC32C: %v", err)
	}

	// The appended CRC TLV must be the tail.
	wantTail := append([]byte{byte(PP2_TYPE_CRC32C), 0x00, 0x04}, make([]byte, 4)...)
	if !bytes.HasSuffix(out[:len(out)-4], wantTail[:3]) {
		t.Fatalf("CRC TLV header not appended at tail: %x", out)
	}
	// Independently validate value and zeroing scope.
	val := binary.BigEndian.Uint32(out[len(out)-4:])
	zeroed := bytes.Clone(out)
	for i := len(out) - 4; i < len(out); i++ {
		zeroed[i] = 0
	}
	if got := crc32cRef(t, zeroed); got != val {
		t.Fatalf("emitted CRC = %08x, independently computed %08x", val, got)
	}

	// Round-trips under verification.
	parsed, err := read(bufio.NewReader(bytes.NewReader(out)), true)
	if err != nil {
		t.Fatalf("enabled Read rejected emitted header: %v", err)
	}
	if parsed.SourceAddr.String() != h.SourceAddr.String() ||
		parsed.DestinationAddr.String() != h.DestinationAddr.String() {
		t.Fatalf("addresses not preserved: %v -> %v / %v -> %v",
			h.SourceAddr, parsed.SourceAddr, h.DestinationAddr, parsed.DestinationAddr)
	}
	// Stable and header not mutated.
	out2, err := formatVersion2WithCRC32C(h)
	if err != nil || !bytes.Equal(out, out2) {
		t.Fatalf("format not stable: %v", err)
	}
	tlvs, _ := h.TLVs()
	if len(tlvs) != 1 || tlvs[0].Type != PP2_TYPE_ALPN {
		t.Fatalf("header TLVs mutated by format: %+v", tlvs)
	}
}

// TestCRC32CFormatPreservesLayout covers the existing-CRC case (value fixed in
// place) across PROXY/LOCAL, IPv4/IPv6/UDP/Unix and UNSPEC, plus non-CRC TLV
// ordering and values.
func TestCRC32CFormatPreservesLayout(t *testing.T) {
	alpn := []byte{byte(PP2_TYPE_ALPN), 0x00, 0x02, 'h', '2'}
	authority := []byte{byte(PP2_TYPE_AUTHORITY), 0x00, 0x0B, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm'}
	crc := crcZeroedTLV()

	// CRC deliberately sits in the middle; its value starts wrong.
	rawTLVs := bytes.Join([][]byte{alpn, crc, authority}, nil)
	rawTLVs[len(alpn)+3] = 0xDE // corrupt first value byte
	rawTLVs[len(alpn)+4] = 0xAD
	rawTLVs[len(alpn)+5] = 0xBE
	rawTLVs[len(alpn)+6] = 0xEF

	cases := []struct {
		name string
		h    *Header
	}{
		{"PROXY TCPv4", crcBaseV4Header()},
		{"PROXY TCPv6", &Header{
			Version: 2, Command: PROXY, TransportProtocol: TCPv6,
			SourceAddr:      &net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 1},
			DestinationAddr: &net.TCPAddr{IP: net.ParseIP("2001:db8::2"), Port: 2},
		}},
		{"PROXY UDPv4", &Header{
			Version: 2, Command: PROXY, TransportProtocol: UDPv4,
			SourceAddr:      &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 1000},
			DestinationAddr: &net.UDPAddr{IP: net.ParseIP("192.0.2.2"), Port: 2000},
		}},
		{"PROXY UnixStream", &Header{
			Version: 2, Command: PROXY, TransportProtocol: UnixStream,
			SourceAddr:      &net.UnixAddr{Net: networkUnix, Name: "/tmp/src.sock"},
			DestinationAddr: &net.UnixAddr{Net: networkUnix, Name: "/tmp/dst.sock"},
		}},
		{"LOCAL TCPv4 full info", &Header{
			Version: 2, Command: LOCAL, TransportProtocol: TCPv4,
			SourceAddr:      &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1},
			DestinationAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8080},
		}},
		{"LOCAL UNSPEC", &Header{
			Version: 2, Command: LOCAL, TransportProtocol: UNSPEC,
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.h.rawTLVs = bytes.Clone(rawTLVs)
			before := bytes.Clone(rawTLVs)

			out, err := formatVersion2WithCRC32C(tc.h)
			if err != nil {
				t.Fatalf("format: %v", err)
			}

			// CRC position preserved: ALPN and AUTHORITY bytes untouched and
			// ordered, CRC TLV still between them.
			tlvRegion := out[len(out)-(len(alpn)+7+len(authority)):]
			if !bytes.Equal(tlvRegion[:len(alpn)], alpn) {
				t.Fatalf("ALPN TLV changed: %x", tlvRegion[:len(alpn)])
			}
			if !bytes.Equal(tlvRegion[len(alpn)+7:], authority) {
				t.Fatalf("AUTHORITY TLV changed: %x", tlvRegion[len(alpn)+7:])
			}
			if tlvRegion[len(alpn)] != byte(PP2_TYPE_CRC32C) {
				t.Fatalf("CRC TLV position not preserved")
			}
			// Value independently correct.
			vOff := len(alpn) + 3
			got := binary.BigEndian.Uint32(tlvRegion[vOff : vOff+4])
			zeroed := bytes.Clone(out)
			globalOff := len(out) - len(tlvRegion) + vOff
			for i := globalOff; i < globalOff+4; i++ {
				zeroed[i] = 0
			}
			if want := crc32cRef(t, zeroed); want != got {
				t.Fatalf("CRC = %08x want %08x", got, want)
			}
			// Caller TLV bytes not mutated.
			if !bytes.Equal(tc.h.rawTLVs, before) {
				t.Fatalf("header rawTLVs mutated by format")
			}
			// Verifies under the enabled policy.
			if _, err := read(bufio.NewReader(bytes.NewReader(out)), true); err != nil {
				t.Fatalf("emitted header failed verification: %v", err)
			}
		})
	}
}

// TestCRC32CFormatErrors covers duplicate, illegal and truncated CRC/TLV
// input, v1 rejection, and uint16 length overflow.
func TestCRC32CFormatErrors(t *testing.T) {
	cases := []struct {
		name    string
		version byte
		rawTLVs []byte
	}{
		{"duplicate CRC", 2, append(crcZeroedTLV(), crcZeroedTLV()...)},
		{"CRC value 3 bytes", 2, []byte{byte(PP2_TYPE_CRC32C), 0x00, 0x03, 0, 0, 0}},
		{"CRC value 5 bytes", 2, []byte{byte(PP2_TYPE_CRC32C), 0x00, 0x05, 0, 0, 0, 0, 0}},
		{"truncated TLV region", 2, []byte{byte(PP2_TYPE_ALPN), 0x00, 0x05, 1, 2}},
		{"truncated TLV header", 2, []byte{0x01, 0x00}},
		{"version 1", 1, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := &Header{Version: tc.version, Command: PROXY, TransportProtocol: TCPv4,
				SourceAddr:      &net.TCPAddr{IP: net.IP{1, 1, 1, 1}, Port: 1},
				DestinationAddr: &net.TCPAddr{IP: net.IP{2, 2, 2, 2}, Port: 2},
				rawTLVs:         tc.rawTLVs}
			if _, err := formatVersion2WithCRC32C(h); err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}

	t.Run("uint16 overflow", func(t *testing.T) {
		h := crcBaseV4Header()
		// NOOP TLV with a 65514-byte value: raw TLV region is 65517 bytes,
		// which formats alone (12+65517 = 65529) but overflows the 16-bit
		// header length once the 7-byte CRC TLV is added (65529+7 = 65536).
		h.rawTLVs = append([]byte{byte(PP2_TYPE_NOOP), 0xFF, 0xEA}, make([]byte, 65514)...)
		if _, err := h.Format(); err != nil {
			t.Fatalf("test setup: base header should format: %v", err)
		}
		if _, err := formatVersion2WithCRC32C(h); !errors.Is(err, errUint16Overflow) {
			t.Fatalf("expected errUint16Overflow, got %v", err)
		}
	})
}

// TestCRC32CReadAcceptAndReject exercises verification at the read layer:
// valid layouts at every CRC position (including TLV-only LOCAL UNSPEC and a
// CRC-only region) pass; bad checksum, non-four-byte values, duplicates and
// truncated encodings fail; missing CRC and unknown TLVs pass.
func TestCRC32CReadAcceptAndReject(t *testing.T) {
	noop := []byte{byte(PP2_TYPE_NOOP), 0x00, 0x02, 0xAA, 0xBB}
	alpn := []byte{byte(PP2_TYPE_ALPN), 0x00, 0x01, 0x01}
	crc := crcZeroedTLV()

	validLayouts := []struct {
		name    string
		h       *Header
		rawTLVs []byte
	}{
		{"CRC first", crcBaseV4Header(), bytes.Join([][]byte{crc, noop, alpn}, nil)},
		{"CRC middle", crcBaseV4Header(), bytes.Join([][]byte{noop, crc, alpn}, nil)},
		{"CRC last", crcBaseV4Header(), bytes.Join([][]byte{noop, alpn, crc}, nil)},
		{"CRC only", crcBaseV4Header(), bytes.Clone(crc)},
		{"LOCAL UNSPEC with CRC", &Header{Version: 2, Command: LOCAL, TransportProtocol: UNSPEC},
			bytes.Join([][]byte{noop, crc}, nil)},
		{"LOCAL TCPv4 full with CRC", &Header{
			Version: 2, Command: LOCAL, TransportProtocol: TCPv4,
			SourceAddr:      &net.TCPAddr{IP: net.IP{127, 0, 0, 1}, Port: 1},
			DestinationAddr: &net.TCPAddr{IP: net.IP{127, 0, 0, 1}, Port: 2},
		}, bytes.Join([][]byte{crc, noop}, nil)},
		{"no CRC, unknown TLVs", crcBaseV4Header(),
			[]byte{0xEA, 0x00, 0x03, 1, 2, 3, 0x04, 0x00, 0x00}},
		{"no CRC at all", crcBaseV4Header(), nil},
		// 0x03 bytes nested inside an SSL-shaped TLV value are top-level data.
		{"nested 0x03 inside other TLV", crcBaseV4Header(), bytes.Join([][]byte{
			{byte(PP2_TYPE_SSL), 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x04, 0xFF},
			crc,
		}, nil)},
	}
	for _, tc := range validLayouts {
		t.Run("valid/"+tc.name, func(t *testing.T) {
			var raw []byte
			if containsTLV(tc.rawTLVs, PP2_TYPE_CRC32C) {
				raw = crcWire(t, tc.h, tc.rawTLVs)
			} else {
				tc.h.rawTLVs = bytes.Clone(tc.rawTLVs)
				var err error
				raw, err = tc.h.Format()
				if err != nil {
					t.Fatal(err)
				}
			}
			h, err := read(bufio.NewReader(bytes.NewReader(raw)), true)
			if err != nil {
				t.Fatalf("header rejected: %v\n%x", err, raw)
			}
			// raw TLVs retained verbatim on the parsed header.
			if !bytes.Equal(h.rawTLVs, tc.rawTLVs) {
				t.Fatalf("raw TLVs not retained:\n got %x\nwant %x", h.rawTLVs, tc.rawTLVs)
			}
		})
	}

	invalidLayouts := []struct {
		name    string
		h       *Header
		rawTLVs []byte
		mutate  func(t *testing.T, raw []byte, tlvStart int)
	}{
		{"wrong checksum", crcBaseV4Header(), bytes.Join([][]byte{noop, crc}, nil),
			func(t *testing.T, raw []byte, tlvStart int) { raw[len(raw)-1] ^= 0xFF }},
		{"address byte flipped", crcBaseV4Header(), bytes.Join([][]byte{crc, noop}, nil),
			func(t *testing.T, raw []byte, tlvStart int) { raw[16] ^= 0xFF }},
		{"CRC value 3 bytes", crcBaseV4Header(),
			[]byte{byte(PP2_TYPE_CRC32C), 0x00, 0x03, 0, 0, 0}, nil},
		{"CRC value 5 bytes", crcBaseV4Header(),
			[]byte{byte(PP2_TYPE_CRC32C), 0x00, 0x05, 0, 0, 0, 0, 0}, nil},
		{"duplicate CRC", crcBaseV4Header(), append(crcZeroedTLV(), crcZeroedTLV()...), nil},
		{"trailing TLV byte", crcBaseV4Header(),
			bytes.Join([][]byte{crc, {0x01}}, nil), nil},
		{"TLV length overruns", crcBaseV4Header(),
			[]byte{byte(PP2_TYPE_ALPN), 0x00, 0x05, 1, 2, 3}, nil},
	}
	for _, tc := range invalidLayouts {
		t.Run("invalid/"+tc.name, func(t *testing.T) {
			var raw []byte
			if tc.mutate != nil {
				raw = crcWire(t, tc.h, tc.rawTLVs)
				tc.mutate(t, raw, len(raw)-len(tc.rawTLVs))
			} else {
				tc.h.rawTLVs = bytes.Clone(tc.rawTLVs)
				var err error
				if raw, err = tc.h.Format(); err != nil {
					t.Fatal(err)
				}
			}
			if h, err := read(bufio.NewReader(bytes.NewReader(raw)), true); err == nil {
				t.Fatalf("expected rejection, got header: %+v\n%x", h, raw)
			}
		})
	}
}

// containsTLV reports whether rawTLVs contains a top-level TLV of typ.
func containsTLV(rawTLVs []byte, typ PP2Type) bool {
	for i := 0; i < len(rawTLVs); {
		if len(rawTLVs)-i < 3 {
			return false
		}
		n := int(binary.BigEndian.Uint16(rawTLVs[i+1 : i+3]))
		if n > len(rawTLVs)-i-3 {
			return false
		}
		if PP2Type(rawTLVs[i]) == typ {
			return true
		}
		i += 3 + n
	}
	return false
}

// TestCRC32CReadFragmentedAndAppData verifies byte-by-byte delivery with a
// tiny buffer and that exactly the header is consumed: following application
// data is returned intact.
func TestCRC32CReadFragmentedAndAppData(t *testing.T) {
	appData := []byte("HTTP/1.1 200 OK\r\n\r\nhello")
	raw := crcWire(t, crcBaseV4Header(), bytes.Join([][]byte{
		{byte(PP2_TYPE_AUTHORITY), 0x00, 0x04, 't', 'e', 's', 't'},
		crcZeroedTLV(),
	}, nil))
	wire := append(raw, appData...)

	for _, bufSize := range []int{16, 256} {
		t.Run("buffer", func(t *testing.T) {
			br := bufio.NewReaderSize(&oneByteReader{data: bytes.Clone(wire)}, bufSize)
			h, err := read(br, true)
			if err != nil {
				t.Fatalf("fragmented read failed: %v", err)
			}
			tlvs, _ := h.TLVs()
			if len(tlvs) != 2 {
				t.Fatalf("TLVs = %+v, want 2", tlvs)
			}
			rest, err := io.ReadAll(br)
			if err != nil {
				t.Fatalf("reading app data: %v", err)
			}
			if !bytes.Equal(rest, appData) {
				t.Fatalf("app data consumed or altered: %q", rest)
			}
		})
	}

	// A corrupted header delivered byte-by-byte is rejected, and the failure is
	// tied to that read only.
	bad := bytes.Clone(raw)
	bad[len(raw)-1] ^= 0xFF
	for _, size := range []int{16, 256} {
		br := bufio.NewReaderSize(&oneByteReader{data: bytes.Clone(bad)}, size)
		if _, err := read(br, true); err == nil {
			t.Fatalf("buffer %d: expected CRC error", size)
		}
		// An independent, valid read still works.
		good := bufio.NewReader(bytes.NewReader(bytes.Clone(raw)))
		if _, err := read(good, true); err != nil {
			t.Fatalf("independent read after failure failed: %v", err)
		}
	}
}

// TestCRC32CDefaultPathsUnchanged pins opt-in behavior: without the policy a
// present CRC TLV is never checked on reads, UDP or connections.
func TestCRC32CDefaultPathsUnchanged(t *testing.T) {
	raw := crcWire(t, crcBaseV4Header(), crcZeroedTLV())
	raw[len(raw)-1] ^= 0xFF // corrupt the checksum

	if h, err := Read(bufio.NewReader(bytes.NewReader(raw))); err != nil {
		t.Fatalf("default Read must not verify CRC, got %v (header %+v)", err, h)
	}
	if _, _, err := ParseUDPDatagram(raw); err != nil {
		t.Fatalf("default ParseUDPDatagram must not verify CRC, got %v", err)
	}

	server, client := net.Pipe()
	defer func() { _ = server.Close() }()
	defer func() { _ = client.Close() }()
	go func() {
		_, _ = client.Write(raw)
		_ = client.Close()
	}()
	c := NewConn(server, WithPolicy(USE), SetReadHeaderTimeout(0))
	buf := make([]byte, 64)
	if _, err := c.Read(buf); err != nil && err != io.EOF {
		t.Fatalf("default NewConn must not verify CRC, got %v", err)
	}
}

// TestCRC32CLocalOpaqueSkip pins that a LOCAL frame whose length does not fit
// its family layout keeps being accepted with its opaque payload discarded,
// even if that payload looks like a CRC TLV.
func TestCRC32CLocalOpaqueSkip(t *testing.T) {
	opaque := []byte{byte(PP2_TYPE_CRC32C), 0x00, 0x04, 0xDE, 0xAD, 0xBE, 0xEF}
	raw := v2Header(byte(LOCAL), byte(TCPv4), opaque) // length 7 < 12 -> opaque skip
	h, err := read(bufio.NewReader(bytes.NewReader(raw)), true)
	if err != nil {
		t.Fatalf("opaque LOCAL frame rejected under CRC policy: %v", err)
	}
	if h.TransportProtocol != UNSPEC || !h.Command.IsLocal() {
		t.Fatalf("expected normalized LOCAL UNSPEC, got cmd=%#x proto=%#x", byte(h.Command), byte(h.TransportProtocol))
	}
	if len(h.rawTLVs) != 0 {
		t.Fatalf("opaque bytes must not be exposed as TLVs: %x", h.rawTLVs)
	}
	// Real connection endpoints keep applying through a Conn.
	server, client := net.Pipe()
	defer func() { _ = server.Close() }()
	defer func() { _ = client.Close() }()
	go func() { _, _ = client.Write(raw) }()
	c := NewConn(server, WithCRC32C())
	defer func() { _ = c.Close() }()
	if c.RemoteAddr() != server.RemoteAddr() {
		t.Fatal("LOCAL must keep the real remote endpoint")
	}
}

// TestCRC32CConnLazyAndIsolated verifies NewConn lazy processing, sticky
// per-connection failure, and independence across connections using one
// policy.
func TestCRC32CConnLazyAndIsolated(t *testing.T) {
	policy := NewCRC32CPolicy(true)
	good := crcWire(t, crcBaseV4Header(), crcZeroedTLV())
	bad := bytes.Clone(good)
	bad[len(good)-2] ^= 0x01

	pipePair := func(wire []byte, trailing []byte) (net.Conn, func()) {
		server, client := net.Pipe()
		done := make(chan struct{})
		go func() {
			_, _ = client.Write(wire)
			if len(trailing) > 0 {
				_, _ = client.Write(trailing)
			}
			// Close the write side so io.ReadAll on the server ends after the
			// application data.
			_ = client.Close()
			close(done)
		}()
		return server, func() {
			_ = server.Close()
			<-done
		}
	}

	// Invalid: lazy (Accept/NewConn cannot fail, parsing happens on first use)
	// and the ordinary error sticks.
	server, wait := pipePair(bad, nil)
	c := policy.NewConn(server, WithPolicy(USE), SetReadHeaderTimeout(0))
	for range 2 {
		buf := make([]byte, 32)
		if _, err := c.Read(buf); err == nil {
			t.Fatal("expected CRC verification error on first read")
		}
	}
	if h := c.ProxyHeader(); h != nil {
		t.Fatalf("ProxyHeader must be nil after verification failure, got %+v", h)
	}
	wait()

	// A failing connection does not poison independent later connections.
	server2, wait2 := pipePair(good, []byte("app-data"))
	c2 := policy.NewConn(server2, WithPolicy(USE), SetReadHeaderTimeout(0))
	got, err := io.ReadAll(c2)
	if err != nil {
		t.Fatalf("independent valid connection failed after prior failure: %v", err)
	}
	if string(got) != "app-data" {
		t.Fatalf("application data = %q", got)
	}
	wait2()
}

// TestCRC32CListener covers Listener.ValidateCRC32C end to end.
func TestCRC32CListener(t *testing.T) {
	good := crcWire(t, crcBaseV4Header(), crcZeroedTLV())
	bad := bytes.Clone(good)
	bad[len(good)-3] ^= 0xFF

	run := func(wire, trailing []byte) error {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = ln.Close() }()
		pl := &Listener{Listener: ln, ValidateCRC32C: true, ConnPolicy: func(ConnPolicyOptions) (Policy, error) {
			return USE, nil
		}}

		type result struct {
			c   net.Conn
			err error
		}
		resCh := make(chan result, 1)
		go func() {
			c, err := pl.Accept()
			resCh <- result{c, err}
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
		res := <-resCh
		if res.err != nil {
			t.Fatalf("Accept: %v", res.err)
		}
		defer func() { _ = res.c.Close() }()
		buf := make([]byte, 64)
		n, err := res.c.Read(buf)
		if err != nil {
			return err
		}
		if string(buf[:n]) != string(trailing) {
			return io.ErrUnexpectedEOF
		}
		return nil
	}

	if err := run(good, []byte("payload")); err != nil {
		t.Fatalf("valid header must be accepted: %v", err)
	}
	if err := run(bad, nil); err == nil {
		t.Fatal("bad checksum must fail the first read")
	}
}

// TestCRC32CReadHeaderTimeout covers the timeout-based public entry point.
func TestCRC32CReadHeaderTimeout(t *testing.T) {
	policy := NewCRC32CPolicy(true)
	good := crcWire(t, crcBaseV4Header(), crcZeroedTLV())
	bad := bytes.Clone(good)
	bad[len(good)-1] ^= 0xFF

	for _, tc := range []struct {
		name string
		wire []byte
		want bool
	}{{"valid", good, true}, {"invalid", bad, false}} {
		server, client := net.Pipe()
		go func() {
			_, _ = client.Write(tc.wire)
		}()
		h, err := policy.ReadHeaderTimeout(server, bufio.NewReader(server), 5*time.Second)
		_ = server.Close()
		_ = client.Close()
		if tc.want && err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if !tc.want && err == nil {
			t.Fatalf("%s: expected verification error, header %+v", tc.name, h)
		}
	}
}

// TestCRC32CUDPPayloadIndependent verifies datagram parsing, payload
// aliasing, caller-buffer immutability, rejection and default behavior.
func TestCRC32CUDPPayloadIndependent(t *testing.T) {
	policy := NewCRC32CPolicy(true)
	payload := []byte("udp application payload")
	base := crcBaseV4Header()
	rawHeader := crcWire(t, base, bytes.Join([][]byte{
		{byte(PP2_TYPE_ALPN), 0x00, 0x01, 0x68},
		crcZeroedTLV(),
	}, nil))
	datagram := append(bytes.Clone(rawHeader), payload...)
	snapshot := bytes.Clone(datagram)

	h, rest, err := policy.ParseUDPDatagram(datagram)
	if err != nil {
		t.Fatalf("datagram rejected: %v", err)
	}
	if !bytes.Equal(rest, payload) {
		t.Fatalf("payload = %q", rest)
	}
	if !bytes.Equal(datagram, snapshot) {
		t.Fatal("ParseUDPDatagram mutated the caller's datagram")
	}
	if h.Command != PROXY || h.TransportProtocol != TCPv4 {
		t.Fatalf("unexpected header cmd=%#x proto=%#x", byte(h.Command), byte(h.TransportProtocol))
	}
	// Header and payload stay independent: payload suffix matches exactly.
	if len(rest) != len(payload) {
		t.Fatal("payload length changed")
	}

	// Corruption rejects without inventing payload.
	bad := bytes.Clone(datagram)
	bad[len(rawHeader)-1] ^= 0xFF
	if h, rest, err := policy.ParseUDPDatagram(bad); err == nil {
		t.Fatalf("bad CRC accepted: header=%+v rest=%q", h, rest)
	}

	// No CRC -> accepted as before.
	plainHdr := crcBaseV4Header()
	plain, err := plainHdr.Format()
	if err != nil {
		t.Fatal(err)
	}
	if _, rest, err := policy.ParseUDPDatagram(append(plain, payload...)); err != nil || !bytes.Equal(rest, payload) {
		t.Fatalf("header without CRC must parse normally: %v %q", err, rest)
	}

	// Disabled policy never checks.
	disabled := NewCRC32CPolicy(false)
	if _, _, err := disabled.ParseUDPDatagram(bad); err != nil {
		t.Fatalf("disabled policy must not verify, got %v", err)
	}
}

// TestCRC32CPolicyDisabledEquivalent pins that the disabled policy delegates
// to default behavior on every entry point.
func TestCRC32CPolicyDisabledEquivalent(t *testing.T) {
	p := NewCRC32CPolicy(false)
	if p.Enabled() {
		t.Fatal("disabled policy reports enabled")
	}
	raw := crcWire(t, crcBaseV4Header(), crcZeroedTLV())
	raw[len(raw)-1] ^= 0xFF // corrupt; must be ignored everywhere

	if h, err := p.Read(bufio.NewReader(bytes.NewReader(raw))); err != nil {
		t.Fatalf("disabled Read: %v (%+v)", err, h)
	}
	if _, _, err := p.ParseUDPDatagram(raw); err != nil {
		t.Fatalf("disabled ParseUDPDatagram: %v", err)
	}
	h := crcBaseV4Header()
	out, err := p.Format(h)
	if err != nil {
		t.Fatalf("disabled Format: %v", err)
	}
	if bytes.Contains(out, []byte{byte(PP2_TYPE_CRC32C)}) {
		t.Fatal("disabled Format must not add a CRC TLV")
	}
	var buf bytes.Buffer
	if n, err := p.WriteTo(h, &buf); err != nil || n != int64(buf.Len()) {
		t.Fatalf("disabled WriteTo: n=%d err=%v", n, err)
	}
}

// TestCRC32CWriteTo verifies the writing entry point emits the same bytes as
// the formatting one.
func TestCRC32CWriteTo(t *testing.T) {
	p := NewCRC32CPolicy(true)
	h := crcBaseV4Header()
	want, err := p.Format(h)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	n, err := p.WriteTo(h, &buf)
	if err != nil {
		t.Fatal(err)
	}
	if n != int64(len(want)) || !bytes.Equal(buf.Bytes(), want) {
		t.Fatalf("WriteTo bytes differ: n=%d want=%d", n, len(want))
	}
}

// TestCRC32CStatelessAcrossOperations reuses one enabled policy across mixed
// success/failure operations; each call is independent.
func TestCRC32CStatelessAcrossOperations(t *testing.T) {
	p := NewCRC32CPolicy(true)
	good := crcWire(t, crcBaseV4Header(), crcZeroedTLV())
	bad := bytes.Clone(good)
	bad[len(good)-1] ^= 0xFF

	for range 3 {
		if _, err := p.Read(bufio.NewReader(bytes.NewReader(bad))); err == nil {
			t.Fatal("bad header unexpectedly accepted")
		}
		if _, err := p.Read(bufio.NewReader(bytes.NewReader(good))); err != nil {
			t.Fatalf("good header rejected after prior failure: %v", err)
		}
		badHdr := &Header{Version: 2, Command: PROXY, TransportProtocol: TCPv4,
			SourceAddr:      &net.TCPAddr{IP: net.IP{1, 1, 1, 1}, Port: 1},
			DestinationAddr: &net.TCPAddr{IP: net.IP{2, 2, 2, 2}, Port: 2},
			rawTLVs:         append(crcZeroedTLV(), crcZeroedTLV()...),
		}
		if _, err := p.Format(badHdr); err == nil {
			t.Fatal("duplicate-CRC header formatted")
		}
		if _, err := p.Format(crcBaseV4Header()); err != nil {
			t.Fatalf("valid format after failure failed: %v", err)
		}
	}
}

// FuzzReadCRC32C holds the enabled-policy invariants under arbitrary input:
// parsing must never panic, and any accepted v2 header must carry a complete
// TLV encoding, format with an emitted/verified CRC, re-parse under the
// policy, and re-format identically.
func FuzzReadCRC32C(f *testing.F) {
	f.Add(v2Header(byte(PROXY), byte(TCPv4), make([]byte, int(lengthV4))))
	f.Add(v2Header(byte(LOCAL), byte(UNSPEC), nil))
	f.Add(v2Header(byte(LOCAL), byte(TCPv4), nil))
	f.Add(crcWire(f, crcBaseV4Header(), crcZeroedTLV()))
	f.Add([]byte("PROXY TCP4 1.2.3.4 5.6.7.8 80 443\r\n"))
	f.Add([]byte("not a proxy header"))

	f.Fuzz(func(t *testing.T, data []byte) {
		h, err := read(bufio.NewReader(bytes.NewReader(data)), true)
		if err != nil || h == nil || h.Version != 2 {
			return
		}
		out, err := formatVersion2WithCRC32C(h)
		if err != nil {
			t.Fatalf("accepted header failed CRC format: %v (%+v)", err, h)
		}
		h2, err := read(bufio.NewReader(bytes.NewReader(out)), true)
		if err != nil {
			t.Fatalf("emitted header failed verification: %v (%x)", err, out)
		}
		out2, err := formatVersion2WithCRC32C(h2)
		if err != nil || !bytes.Equal(out, out2) {
			t.Fatalf("CRC format not stable: %v\n first  %x\n second %x", err, out, out2)
		}
	})
}
