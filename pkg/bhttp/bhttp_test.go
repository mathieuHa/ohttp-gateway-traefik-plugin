package bhttp

import (
	"bytes"
	"encoding/hex"
	"errors"
	"net/http"
	"reflect"
	"testing"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestVarint(t *testing.T) {
	// Examples from RFC 9000, Appendix A.1.
	cases := []struct {
		hex   string
		value uint64
	}{
		{"c2197c5eff14e88c", 151288809941952652},
		{"9d7f3e7d", 494878333},
		{"7bbd", 15293},
		{"25", 37},
	}
	for _, c := range cases {
		d := &decoder{buf: mustHex(t, c.hex)}
		v, err := d.varint()
		if err != nil {
			t.Fatal(err)
		}
		if v != c.value {
			t.Errorf("decode %s = %d, want %d", c.hex, v, c.value)
		}
		if got := hex.EncodeToString(appendVarint(nil, c.value)); got != c.hex {
			t.Errorf("encode %d = %s, want %s", c.value, got, c.hex)
		}
	}
	// Non-minimal encoding is accepted on decode.
	d := &decoder{buf: mustHex(t, "4025")}
	if v, err := d.varint(); err != nil || v != 37 {
		t.Errorf("decode 4025 = %d, %v", v, err)
	}
	// Truncated input.
	d = &decoder{buf: mustHex(t, "9d7f")}
	if _, err := d.varint(); !errors.Is(err, errTruncated) {
		t.Errorf("expected truncated error, got %v", err)
	}
}

// Examples from RFC 9292, Section 5.
const (
	rfcKnownLengthRequest = "0003474554056874747073000a2f68656c6c6f2e747874406c0a757365722d6167656e74346375726c2f372e31362e33206c69626375726c2f372e31362e33204f70656e53534c2f302e392e376c207a6c69622f312e322e3304686f73740f7777772e6578616d706c652e636f6d0f6163636570742d6c616e677561676506656e2c206d690000"

	rfcIndeterminateLengthRequest = "0203474554056874747073000a2f68656c6c6f2e7478740a757365722d6167656e74346375726c2f372e31362e33206c69626375726c2f372e31362e33204f70656e53534c2f302e392e376c207a6c69622f312e322e3304686f73740f7777772e6578616d706c652e636f6d0f6163636570742d6c616e677561676506656e2c206d6900000000000000000000000000"

	rfcIndeterminateLengthResponse = "0340660772756e6e696e670a22736c65657020313522004067046c696e6b233c2f7374796c652e6373733e3b2072656c3d7072656c6f61643b2061733d7374796c65046c696e6b243c2f7363726970742e6a733e3b2072656c3d7072656c6f61643b2061733d7363726970740040c804646174651d4d6f6e2c203237204a756c20323030392031323a32383a353320474d5406736572766572064170616368650d6c6173742d6d6f6469666965641d5765642c203232204a756c20323030392031393a31353a353620474d5404657461671422333461613338372d642d3135363865623030220d6163636570742d72616e6765730562797465730e636f6e74656e742d6c656e67746802353104766172790f4163636570742d456e636f64696e670c636f6e74656e742d747970650a746578742f706c61696e003348656c6c6f20576f726c6421204d7920636f6e74656e7420696e636c75646573206120747261696c696e672043524c462e0d0a0000"

	rfcKnownLengthResponse = "0140c8001d5468697320636f6e74656e7420636f6e7461696e732043524c462e0d0a0d07747261696c65720474657874"
)

func TestDecodeRFCExamples(t *testing.T) {
	wantRequest := &Request{
		Method: "GET", Scheme: "https", Authority: "", Path: "/hello.txt",
		Header: []Field{
			{"user-agent", "curl/7.16.3 libcurl/7.16.3 OpenSSL/0.9.7l zlib/1.2.3"},
			{"host", "www.example.com"},
			{"accept-language", "en, mi"},
		},
	}

	t.Run("known-length request", func(t *testing.T) {
		data := mustHex(t, rfcKnownLengthRequest)
		req, err := UnmarshalRequest(data)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(req, wantRequest) {
			t.Fatalf("got %+v\nwant %+v", req, wantRequest)
		}
		// The last two bytes (empty content and trailers) can be truncated.
		for _, n := range []int{1, 2} {
			req, err = UnmarshalRequest(data[:len(data)-n])
			if err != nil {
				t.Fatalf("truncated by %d: %v", n, err)
			}
			if !reflect.DeepEqual(req, wantRequest) {
				t.Fatalf("truncated by %d: got %+v", n, req)
			}
		}
		// Our encoder produces the exact same bytes.
		encoded, err := wantRequest.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(encoded, data) {
			t.Fatalf("encoded = %x", encoded)
		}
	})

	t.Run("indeterminate-length request", func(t *testing.T) {
		data := mustHex(t, rfcIndeterminateLengthRequest)
		// Up to 12 bytes (padding, content and trailer terminators) can be removed.
		for n := 0; n <= 12; n++ {
			req, err := UnmarshalRequest(data[:len(data)-n])
			if err != nil {
				t.Fatalf("truncated by %d: %v", n, err)
			}
			if !reflect.DeepEqual(req, wantRequest) {
				t.Fatalf("truncated by %d: got %+v", n, req)
			}
		}
	})

	t.Run("indeterminate-length response with informational", func(t *testing.T) {
		resp, err := UnmarshalResponse(mustHex(t, rfcIndeterminateLengthResponse))
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != 200 {
			t.Fatalf("status = %d", resp.StatusCode)
		}
		wantInfo := []InformationalResponse{
			{StatusCode: 102, Header: []Field{{"running", `"sleep 15"`}}},
			{StatusCode: 103, Header: []Field{
				{"link", "</style.css>; rel=preload; as=style"},
				{"link", "</script.js>; rel=preload; as=script"},
			}},
		}
		if !reflect.DeepEqual(resp.Informational, wantInfo) {
			t.Fatalf("informational = %+v", resp.Informational)
		}
		if string(resp.Body) != "Hello World! My content includes a trailing CRLF.\r\n" {
			t.Fatalf("body = %q", resp.Body)
		}
		h := HeaderFromFields(resp.Header)
		if h.Get("Content-Type") != "text/plain" || h.Get("Server") != "Apache" || h.Get("Vary") != "Accept-Encoding" {
			t.Fatalf("header = %v", h)
		}
		if len(resp.Trailer) != 0 {
			t.Fatalf("trailer = %v", resp.Trailer)
		}
	})

	t.Run("known-length response with trailer", func(t *testing.T) {
		data := mustHex(t, rfcKnownLengthResponse)
		resp, err := UnmarshalResponse(data)
		if err != nil {
			t.Fatal(err)
		}
		want := &Response{
			StatusCode: 200,
			Body:       []byte("This content contains CRLF.\r\n"),
			Trailer:    []Field{{"trailer", "text"}},
		}
		if !reflect.DeepEqual(resp, want) {
			t.Fatalf("got %+v", resp)
		}
		encoded, err := want.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(encoded, data) {
			t.Fatalf("encoded = %x", encoded)
		}
	})

	t.Run("truncated request from RFC 9458", func(t *testing.T) {
		req, err := UnmarshalRequest(mustHex(t, "00034745540568747470730b6578616d706c652e636f6d012f"))
		if err != nil {
			t.Fatal(err)
		}
		want := &Request{Method: "GET", Scheme: "https", Authority: "example.com", Path: "/"}
		if !reflect.DeepEqual(req, want) {
			t.Fatalf("got %+v", req)
		}
	})

	t.Run("truncated response from RFC 9458", func(t *testing.T) {
		resp, err := UnmarshalResponse(mustHex(t, "0140c8"))
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != 200 || resp.Header != nil || resp.Body != nil {
			t.Fatalf("got %+v", resp)
		}
	})
}

func TestRoundTrip(t *testing.T) {
	req := &Request{
		Method: "POST", Scheme: "https", Authority: "example.com", Path: "/submit?x=1",
		Header:  []Field{{"content-type", "application/json"}, {"x-dup", "a"}, {"x-dup", "b"}},
		Body:    bytes.Repeat([]byte("x"), 70000),
		Trailer: []Field{{"x-checksum", "abc"}},
	}
	data, err := req.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	got, err := UnmarshalRequest(data)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, req) {
		t.Fatalf("request round trip mismatch")
	}

	resp := &Response{
		Informational: []InformationalResponse{{StatusCode: 103, Header: []Field{{"link", "</a.css>"}}}},
		StatusCode:    404,
		Header:        []Field{{"content-type", "text/plain"}},
		Body:          []byte("not found"),
	}
	data, err = resp.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	// Padding is accepted.
	data = append(data, 0, 0, 0)
	gotResp, err := UnmarshalResponse(data)
	if err != nil {
		t.Fatal(err)
	}
	if gotResp.StatusCode != 404 || string(gotResp.Body) != "not found" || len(gotResp.Informational) != 1 {
		t.Fatalf("response round trip mismatch: %+v", gotResp)
	}
}

func TestDecodeErrors(t *testing.T) {
	valid, err := (&Request{Method: "GET", Scheme: "https", Authority: "a", Path: "/", Body: []byte("hi")}).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string][]byte{
		"empty":              {},
		"response framing":   {0x01},
		"unknown framing":    {0x04},
		"truncated control":  valid[:5],
		"truncated content":  valid[:len(valid)-2],
		"non-zero padding":   append(append([]byte{}, valid...), 0, 1),
		"oversized length":   {0x00, 0x80, 0xff, 0xff, 0xff},
		"empty field name":   {0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00},
		"indeterminate open": {0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 'a', 0x01, 'b'},
	}
	for name, data := range cases {
		if _, err := UnmarshalRequest(data); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}

	respCases := map[string][]byte{
		"request framing": {0x00},
		"status too low":  {0x01, 0x40, 0x63},
		"status too high": {0x01, 0x42, 0x58},
		"missing status":  {0x01},
	}
	for name, data := range respCases {
		if _, err := UnmarshalResponse(data); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}

	if _, err := (&Response{StatusCode: 99}).Marshal(); err == nil {
		t.Error("expected invalid status to fail")
	}
	if _, err := (&Response{StatusCode: 200, Informational: []InformationalResponse{{StatusCode: 200}}}).Marshal(); err == nil {
		t.Error("expected invalid informational status to fail")
	}
	if _, err := (&Request{Header: []Field{{Name: ""}}}).Marshal(); err == nil {
		t.Error("expected empty field name to fail")
	}
}

func TestHeaderConversion(t *testing.T) {
	h := http.Header{}
	h.Add("Content-Type", "text/plain")
	h.Add("X-Multi", "1")
	h.Add("X-Multi", "2")
	h.Add("Connection", "close")
	h.Add("Transfer-Encoding", "chunked")
	fields := FieldsFromHeader(h)
	want := []Field{{"content-type", "text/plain"}, {"x-multi", "1"}, {"x-multi", "2"}}
	if !reflect.DeepEqual(fields, want) {
		t.Fatalf("fields = %v", fields)
	}
	back := HeaderFromFields(append(fields, Field{"keep-alive", "1"}))
	if back.Get("Content-Type") != "text/plain" || len(back.Values("X-Multi")) != 2 || back.Get("Keep-Alive") != "" {
		t.Fatalf("header = %v", back)
	}
}
