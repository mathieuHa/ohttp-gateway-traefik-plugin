// Package bhttp implements the Binary Representation of HTTP Messages
// (RFC 9292).
//
// Both the known-length and indeterminate-length encodings are decoded,
// including truncated messages and padding. Messages are always encoded using
// the known-length format.
package bhttp

import (
	"errors"
	"fmt"
)

// Framing indicators (RFC 9292, Section 3.3).
const (
	framingKnownLengthRequest          = 0
	framingKnownLengthResponse         = 1
	framingIndeterminateLengthRequest  = 2
	framingIndeterminateLengthResponse = 3
)

var (
	// ErrInvalidFraming is returned when the framing indicator is not valid for
	// the expected message type.
	ErrInvalidFraming = errors.New("bhttp: invalid framing indicator")
	// ErrInvalidPadding is returned when non-zero bytes follow the message.
	ErrInvalidPadding = errors.New("bhttp: non-zero padding")
	// ErrInvalidStatus is returned for status codes outside of 100-599.
	ErrInvalidStatus = errors.New("bhttp: invalid status code")
	// ErrEmptyFieldName is returned when a field line has an empty name.
	ErrEmptyFieldName = errors.New("bhttp: empty field name")
)

// Field is a single header or trailer field line.
type Field struct {
	Name  string
	Value string
}

// Request is a binary HTTP request.
type Request struct {
	Method    string
	Scheme    string
	Authority string
	Path      string
	Header    []Field
	Body      []byte
	Trailer   []Field
}

// InformationalResponse is an interim (1xx) response preceding the final one.
type InformationalResponse struct {
	StatusCode int
	Header     []Field
}

// Response is a binary HTTP response.
type Response struct {
	Informational []InformationalResponse
	StatusCode    int
	Header        []Field
	Body          []byte
	Trailer       []Field
}

// UnmarshalRequest decodes a binary HTTP request.
func UnmarshalRequest(data []byte) (*Request, error) {
	d := &decoder{buf: data}
	framing, err := d.varint()
	if err != nil {
		return nil, err
	}
	var known bool
	switch framing {
	case framingKnownLengthRequest:
		known = true
	case framingIndeterminateLengthRequest:
		known = false
	default:
		return nil, ErrInvalidFraming
	}

	req := &Request{}
	controlData := make([]string, 4)
	for i := range controlData {
		b, err := d.lengthPrefixed()
		if err != nil {
			return nil, err
		}
		controlData[i] = string(b)
	}
	req.Method, req.Scheme, req.Authority, req.Path = controlData[0], controlData[1], controlData[2], controlData[3]

	req.Header, req.Body, req.Trailer, err = d.sections(known)
	if err != nil {
		return nil, err
	}
	return req, nil
}

// UnmarshalResponse decodes a binary HTTP response.
func UnmarshalResponse(data []byte) (*Response, error) {
	d := &decoder{buf: data}
	framing, err := d.varint()
	if err != nil {
		return nil, err
	}
	var known bool
	switch framing {
	case framingKnownLengthResponse:
		known = true
	case framingIndeterminateLengthResponse:
		known = false
	default:
		return nil, ErrInvalidFraming
	}

	resp := &Response{}
	for {
		status, err := d.varint()
		if err != nil {
			return nil, err
		}
		if status < 100 || status > 599 {
			return nil, ErrInvalidStatus
		}
		if status >= 200 {
			resp.StatusCode = int(status)
			break
		}
		// Informational responses always carry a field section.
		fields, err := d.fieldSection(known)
		if err != nil {
			return nil, err
		}
		resp.Informational = append(resp.Informational, InformationalResponse{StatusCode: int(status), Header: fields})
	}

	resp.Header, resp.Body, resp.Trailer, err = d.sections(known)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// sections decodes the header, content and trailer sections that follow the
// control data, honoring truncation (RFC 9292, Section 3.8) and padding.
func (d *decoder) sections(known bool) (header []Field, body []byte, trailer []Field, err error) {
	if d.empty() {
		return nil, nil, nil, nil
	}
	if header, err = d.fieldSection(known); err != nil {
		return nil, nil, nil, err
	}
	if d.empty() {
		return header, nil, nil, nil
	}
	if body, err = d.content(known); err != nil {
		return nil, nil, nil, err
	}
	if d.empty() {
		return header, body, nil, nil
	}
	if trailer, err = d.fieldSection(known); err != nil {
		return nil, nil, nil, err
	}
	for _, b := range d.buf[d.off:] {
		if b != 0 {
			return nil, nil, nil, ErrInvalidPadding
		}
	}
	return header, body, trailer, nil
}

func (d *decoder) fieldSection(known bool) ([]Field, error) {
	if known {
		section, err := d.lengthPrefixed()
		if err != nil {
			return nil, err
		}
		sub := &decoder{buf: section}
		var fields []Field
		for !sub.empty() {
			name, err := sub.lengthPrefixed()
			if err != nil {
				return nil, err
			}
			if len(name) == 0 {
				return nil, ErrEmptyFieldName
			}
			value, err := sub.lengthPrefixed()
			if err != nil {
				return nil, err
			}
			fields = append(fields, Field{Name: string(name), Value: string(value)})
		}
		return fields, nil
	}

	var fields []Field
	for {
		// A zero name length is the Content Terminator ending the section.
		name, err := d.lengthPrefixed()
		if err != nil {
			return nil, err
		}
		if len(name) == 0 {
			return fields, nil
		}
		value, err := d.lengthPrefixed()
		if err != nil {
			return nil, err
		}
		fields = append(fields, Field{Name: string(name), Value: string(value)})
	}
}

func (d *decoder) content(known bool) ([]byte, error) {
	if known {
		body, err := d.lengthPrefixed()
		if err != nil || len(body) == 0 {
			return nil, err
		}
		return body, nil
	}
	var body []byte
	for {
		chunk, err := d.lengthPrefixed()
		if err != nil {
			return nil, err
		}
		if len(chunk) == 0 {
			return body, nil
		}
		body = append(body, chunk...)
	}
}

// Marshal encodes the request using the known-length format.
func (r *Request) Marshal() ([]byte, error) {
	b := appendVarint(nil, framingKnownLengthRequest)
	for _, s := range []string{r.Method, r.Scheme, r.Authority, r.Path} {
		b = appendBytes(b, []byte(s))
	}
	return appendSections(b, r.Header, r.Body, r.Trailer)
}

// Marshal encodes the response using the known-length format.
func (r *Response) Marshal() ([]byte, error) {
	b := appendVarint(nil, framingKnownLengthResponse)
	for _, info := range r.Informational {
		if info.StatusCode < 100 || info.StatusCode > 199 {
			return nil, fmt.Errorf("%w: informational %d", ErrInvalidStatus, info.StatusCode)
		}
		b = appendVarint(b, uint64(info.StatusCode))
		var err error
		if b, err = appendFieldSection(b, info.Header); err != nil {
			return nil, err
		}
	}
	if r.StatusCode < 200 || r.StatusCode > 599 {
		return nil, fmt.Errorf("%w: %d", ErrInvalidStatus, r.StatusCode)
	}
	b = appendVarint(b, uint64(r.StatusCode))
	return appendSections(b, r.Header, r.Body, r.Trailer)
}

func appendSections(b []byte, header []Field, body []byte, trailer []Field) ([]byte, error) {
	var err error
	if b, err = appendFieldSection(b, header); err != nil {
		return nil, err
	}
	b = appendBytes(b, body)
	return appendFieldSection(b, trailer)
}

func appendFieldSection(b []byte, fields []Field) ([]byte, error) {
	var section []byte
	for _, f := range fields {
		if f.Name == "" {
			return nil, ErrEmptyFieldName
		}
		section = appendBytes(section, []byte(f.Name))
		section = appendBytes(section, []byte(f.Value))
	}
	return appendBytes(b, section), nil
}

func appendBytes(b, data []byte) []byte {
	b = appendVarint(b, uint64(len(data)))
	return append(b, data...)
}
