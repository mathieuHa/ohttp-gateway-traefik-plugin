package bhttp

import "errors"

// MaxVarint is the largest value that can be encoded as a variable-length
// integer (RFC 9000, Section 16).
const MaxVarint = 1<<62 - 1

var errTruncated = errors.New("bhttp: truncated message")

// appendVarint appends the QUIC variable-length encoding of v to b. Values
// larger than MaxVarint are not representable and must be rejected by callers.
func appendVarint(b []byte, v uint64) []byte {
	switch {
	case v < 1<<6:
		return append(b, byte(v))
	case v < 1<<14:
		return append(b, byte(v>>8)|0x40, byte(v))
	case v < 1<<30:
		return append(b, byte(v>>24)|0x80, byte(v>>16), byte(v>>8), byte(v))
	default:
		return append(b,
			byte(v>>56)|0xc0, byte(v>>48), byte(v>>40), byte(v>>32),
			byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
	}
}

// decoder reads the primitive types of RFC 9292 from a byte slice.
type decoder struct {
	buf []byte
	off int
}

func (d *decoder) empty() bool {
	return d.off >= len(d.buf)
}

func (d *decoder) remaining() int {
	return len(d.buf) - d.off
}

func (d *decoder) varint() (uint64, error) {
	if d.empty() {
		return 0, errTruncated
	}
	first := d.buf[d.off]
	length := 1 << (first >> 6)
	if d.remaining() < length {
		return 0, errTruncated
	}
	v := uint64(first & 0x3f)
	for i := 1; i < length; i++ {
		v = v<<8 | uint64(d.buf[d.off+i])
	}
	d.off += length
	return v, nil
}

func (d *decoder) bytes(n uint64) ([]byte, error) {
	if n > uint64(d.remaining()) {
		return nil, errTruncated
	}
	b := d.buf[d.off : d.off+int(n)]
	d.off += int(n)
	return b, nil
}

// lengthPrefixed reads a varint length followed by that many bytes.
func (d *decoder) lengthPrefixed() ([]byte, error) {
	n, err := d.varint()
	if err != nil {
		return nil, err
	}
	return d.bytes(n)
}
