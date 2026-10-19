package proxyproto

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"io"
	"net"
	"time"
)

// crc32cValueSize is the fixed size, in bytes, of a PP2_TYPE_CRC32C value.
const crc32cValueSize = 4

// crc32cTable is the CRC32-Castagnoli table (RFC 4960, Appendix B), the
// algorithm mandated by the PROXY protocol specification for the
// PP2_TYPE_CRC32C TLV.
var crc32cTable = crc32.MakeTable(crc32.Castagnoli)

var (
	// errCRC32CMismatch indicates a present CRC32C TLV does not match the
	// checksum computed over the received header.
	errCRC32CMismatch = errors.New("proxyproto: CRC32C checksum mismatch")
	// errCRC32CDuplicate indicates more than one CRC32C TLV is present.
	errCRC32CDuplicate = errors.New("proxyproto: multiple CRC32C TLVs present")
	// errCRC32CVersion2 indicates CRC32C handling was requested for a header
	// that is not PROXY protocol version 2.
	errCRC32CVersion2 = errors.New("proxyproto: CRC32C TLV is only defined for PROXY protocol version 2")
)

// CRC32CPolicy is the optional, opt-in integrity policy for PROXY protocol
// version 2 headers carrying a PP2_TYPE_CRC32C TLV (spec section 2.2.3).
//
// The zero value and a policy created with NewCRC32CPolicy(false) perform no
// verification: their operations are equivalent to the package-level Read,
// ReadHeaderTimeout, ParseUDPDatagram, NewConn/Listener handling, Format and
// WriteTo, so v1 headers, v2 headers without a CRC32C TLV, unknown TLVs and
// plain connections keep behaving exactly as without the policy.
//
// A policy created with NewCRC32CPolicy(true) verifies a CRC32C TLV before a
// v2 header is accepted, following the spec: the received 32-bit value is set
// aside, the four value bytes are treated as zero and the CRC32C of the whole
// PROXY header is recomputed and compared. A single CRC32C TLV may appear at
// any complete top-level TLV position. A header with a wrong checksum, a
// CRC32C TLV whose value is not four bytes long, more than one CRC32C TLV, or
// an incompletely encoded TLV region is rejected with an ordinary error. A
// header without any CRC32C TLV is processed normally. Connections keep their
// lazy header processing: the error is reported when the header is actually
// handled (first Read/Write/address access), not earlier.
//
// The policy is stateless: operations never share checksum state with each
// other, an operation that fails does not affect later, independent
// operations, and buffers, addresses and TLV values passed by the caller are
// not modified.
type CRC32CPolicy struct {
	verify bool
}

// NewCRC32CPolicy returns the optional PROXY protocol v2 CRC32C integrity
// policy. When verify is true the policy verifies CRC32C TLVs and emits a
// correct CRC32C TLV when formatting; when false its operations are
// equivalent to the default, non-verifying ones.
func NewCRC32CPolicy(verify bool) *CRC32CPolicy {
	return &CRC32CPolicy{verify: verify}
}

// Enabled reports whether CRC32C verification (and emission) is active.
func (p *CRC32CPolicy) Enabled() bool {
	return p != nil && p.verify
}

// Read acts as the package-level Read but verifies the CRC32C TLV of a v2
// header when the policy enables it. Only the bytes of the PROXY header are
// consumed; application data following the header stays available on reader.
func (p *CRC32CPolicy) Read(reader *bufio.Reader) (*Header, error) {
	return read(reader, p.Enabled())
}

// ReadHeaderTimeout acts as the package-level ReadHeaderTimeout but verifies
// the CRC32C TLV of a v2 header when the policy enables it.
func (p *CRC32CPolicy) ReadHeaderTimeout(conn net.Conn, reader *bufio.Reader, timeout time.Duration) (*Header, error) {
	return readHeaderTimeout(conn, reader, timeout, p.Enabled())
}

// ParseUDPDatagram acts as the package-level ParseUDPDatagram but verifies the
// CRC32C TLV of a v2 header when the policy enables it. The returned payload
// stays independent of the check and always aliases the datagram suffix.
func (p *CRC32CPolicy) ParseUDPDatagram(datagram []byte) (*Header, []byte, error) {
	return parseUDPDatagram(datagram, p.Enabled())
}

// NewConn wraps conn as NewConn does, additionally enabling CRC32C
// verification on the returned connection when the policy enables it. Further
// NewConn options are applied after the policy setting.
func (p *CRC32CPolicy) NewConn(conn net.Conn, opts ...func(*Conn)) *Conn {
	if p.Enabled() {
		all := make([]func(*Conn), 0, len(opts)+1)
		all = append(all, WithCRC32C())
		all = append(all, opts...)
		opts = all
	}
	return NewConn(conn, opts...)
}

// NewListener wraps listener in a Listener that applies the policy: accepted
// connections verify their CRC32C TLV when the policy enables it. The returned
// Listener otherwise uses the usual defaults (DefaultPolicy and
// DefaultReadHeaderTimeout); configure its other fields as needed after
// creation.
func (p *CRC32CPolicy) NewListener(listener net.Listener) *Listener {
	l := &Listener{Listener: listener}
	if p.Enabled() {
		l.ValidateCRC32C = true
	}
	return l
}

// Format renders the header as Header.Format does, additionally ensuring a
// valid, four-byte CRC32C TLV is emitted when the policy enables it: an
// existing, legal CRC32C TLV keeps its position and receives the correct
// checksum value; when absent, one is appended. Addresses, command and the
// order and values of all other TLVs are preserved, and the header itself is
// not modified. Duplicate CRC32C TLVs, a CRC32C TLV with a non-four-byte
// value, or an incompletely encoded TLV region are rejected with an error.
func (p *CRC32CPolicy) Format(header *Header) ([]byte, error) {
	if !p.Enabled() {
		return header.Format()
	}
	return formatVersion2WithCRC32C(header)
}

// WriteTo renders the header with the policy's Format and writes it to w,
// mirroring Header.WriteTo.
func (p *CRC32CPolicy) WriteTo(header *Header, w io.Writer) (int64, error) {
	buf, err := p.Format(header)
	if err != nil {
		return 0, err
	}
	return bytes.NewReader(buf).WriteTo(w)
}

// v2Reader is the subset of *bufio.Reader parseVersion2 consumes. The CRC32C
// recording wrapper implements the same interface.
type v2Reader interface {
	io.Reader
	ReadByte() (byte, error)
	Discard(int) (int, error)
}

// crc32cTeeReader records exactly the bytes parseVersion2 consumes from the
// underlying buffered reader, so the checksum can be computed over the exact
// header bytes received. It never reads beyond what the parser requests, so
// application data following the header is never consumed.
type crc32cTeeReader struct {
	r   *bufio.Reader
	raw []byte
}

func (t *crc32cTeeReader) ReadByte() (byte, error) {
	b, err := t.r.ReadByte()
	if err == nil {
		t.raw = append(t.raw, b)
	}
	return b, err
}

func (t *crc32cTeeReader) Read(p []byte) (int, error) {
	n, err := t.r.Read(p)
	if n > 0 {
		t.raw = append(t.raw, p[:n]...)
	}
	return n, err
}

// Discard delegates to the buffered reader without recording the skipped
// bytes. It is only reached on the LOCAL opaque-payload path, whose bytes are
// discarded without TLV interpretation and therefore never checksummed;
// keeping *bufio.Reader.Discard's exact semantics there matters.
func (t *crc32cTeeReader) Discard(n int) (int, error) {
	return t.r.Discard(n)
}

// crc32cLocation identifies the position of the unique CRC32C TLV value inside
// the raw top-level TLV region.
type crc32cLocation struct {
	found       bool
	valueOffset int
}

// findCRC32CTLV walks the raw top-level TLV region exactly once, enforcing
// complete TLV framing. It returns the value offset of the unique CRC32C TLV,
// ErrTruncatedTLV for an incomplete TLV encoding, ErrMalformedTLV for a
// CRC32C TLV whose value is not four bytes long, and errCRC32CDuplicate when
// more than one CRC32C TLV is present. TLV values are never descended into,
// so a 0x03 type byte nested inside another TLV is not treated as CRC32C.
func findCRC32CTLV(rawTLVs []byte) (crc32cLocation, error) {
	var crc crc32cLocation
	for i := 0; i < len(rawTLVs); {
		if len(rawTLVs)-i < 3 {
			return crc32cLocation{}, ErrTruncatedTLV
		}
		tlvLen := int(binary.BigEndian.Uint16(rawTLVs[i+1 : i+3]))
		if tlvLen > len(rawTLVs)-i-3 {
			return crc32cLocation{}, ErrTruncatedTLV
		}
		if PP2Type(rawTLVs[i]) == PP2_TYPE_CRC32C {
			if crc.found {
				return crc32cLocation{}, errCRC32CDuplicate
			}
			if tlvLen != crc32cValueSize {
				return crc32cLocation{}, ErrMalformedTLV
			}
			crc.found = true
			crc.valueOffset = i + 3
		}
		i += 3 + tlvLen
	}
	return crc, nil
}

// verifyCRC32C validates the optional CRC32C TLV against the exact v2 header
// bytes consumed from the wire. rawHeader is the complete header and rawTLVs
// its TLV suffix; neither slice is modified (the checksum bytes are zeroed in
// a private copy). A missing CRC32C TLV accepts the header.
func verifyCRC32C(rawHeader, rawTLVs []byte) error {
	crc, err := findCRC32CTLV(rawTLVs)
	if err != nil {
		return err
	}
	if !crc.found {
		return nil
	}
	valueOffset := len(rawHeader) - len(rawTLVs) + crc.valueOffset
	if valueOffset < 0 || valueOffset+crc32cValueSize > len(rawHeader) {
		return ErrMalformedTLV
	}
	received := binary.BigEndian.Uint32(rawHeader[valueOffset : valueOffset+crc32cValueSize])

	zeroed := make([]byte, len(rawHeader))
	copy(zeroed, rawHeader)
	for i := range crc32cValueSize {
		zeroed[valueOffset+i] = 0
	}
	if crc32.Checksum(zeroed, crc32cTable) != received {
		return errCRC32CMismatch
	}
	return nil
}

// formatVersion2WithCRC32C renders a v2 header with a valid CRC32C TLV
// without modifying the header. An existing legal CRC32C TLV keeps its
// position and receives the correct value; otherwise one is appended after
// all existing TLVs. All non-CRC TLV bytes are preserved verbatim.
func formatVersion2WithCRC32C(header *Header) ([]byte, error) {
	if header.Version != 2 {
		return nil, errCRC32CVersion2
	}

	crc, err := findCRC32CTLV(header.rawTLVs)
	if err != nil {
		return nil, err
	}

	// Work on a private copy of the TLV region so the caller's TLV values are
	// never touched.
	renderedTLVs := make([]byte, 0, len(header.rawTLVs)+3+crc32cValueSize)
	renderedTLVs = append(renderedTLVs, header.rawTLVs...)
	if crc.found {
		for i := range crc32cValueSize {
			renderedTLVs[crc.valueOffset+i] = 0
		}
	} else {
		crc.found = true
		crc.valueOffset = len(renderedTLVs) + 3
		renderedTLVs = append(renderedTLVs, byte(PP2_TYPE_CRC32C), 0x00, crc32cValueSize, 0x00, 0x00, 0x00, 0x00)
	}

	// Shallow-copy the header: addresses are shared read-only while the raw
	// TLV bytes are substituted for the local, CRC-zeroed copy.
	clone := *header
	clone.rawTLVs = renderedTLVs
	out, err := clone.formatVersion2()
	if err != nil {
		return nil, err
	}

	// The TLV region is the tail of the rendered v2 header.
	valueOffset := len(out) - len(renderedTLVs) + crc.valueOffset
	binary.BigEndian.PutUint32(out[valueOffset:valueOffset+crc32cValueSize], crc32.Checksum(out, crc32cTable))
	return out, nil
}
