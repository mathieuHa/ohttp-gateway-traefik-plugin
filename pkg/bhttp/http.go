package bhttp

import (
	"net/http"
	"sort"
	"strings"
)

// connectionSpecificFields lists fields that only apply to a single connection
// and must not be carried in a binary message (RFC 9292, Section 3.6 and
// RFC 9110, Section 7.6.1).
var connectionSpecificFields = map[string]bool{
	"connection":          true,
	"keep-alive":          true,
	"proxy-connection":    true,
	"te":                  true,
	"trailer":             true,
	"transfer-encoding":   true,
	"upgrade":             true,
	"proxy-authenticate":  true,
	"proxy-authorization": true,
}

// IsConnectionSpecific reports whether a field name is connection-specific.
func IsConnectionSpecific(name string) bool {
	return connectionSpecificFields[strings.ToLower(name)]
}

// FieldsFromHeader converts an http.Header into binary HTTP field lines. Names
// are lowercased, sorted for determinism and connection-specific fields are
// dropped.
func FieldsFromHeader(h http.Header) []Field {
	names := make([]string, 0, len(h))
	for name := range h {
		if !IsConnectionSpecific(name) {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	var fields []Field
	for _, name := range names {
		lower := strings.ToLower(name)
		for _, value := range h[name] {
			fields = append(fields, Field{Name: lower, Value: value})
		}
	}
	return fields
}

// HeaderFromFields converts binary HTTP field lines into an http.Header,
// dropping connection-specific fields.
func HeaderFromFields(fields []Field) http.Header {
	h := make(http.Header, len(fields))
	for _, f := range fields {
		if IsConnectionSpecific(f.Name) {
			continue
		}
		h.Add(f.Name, f.Value)
	}
	return h
}
