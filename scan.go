package main

import (
	"bytes"
	"encoding/base64"
)

type verdict string

const (
	trusts  verdict = "TRUSTS"
	blocked verdict = "BLOCKED"
	none    verdict = ""
)

type result struct {
	anchors []string
	denied  int
}

func (r result) verdict(total int) verdict {
	switch {
	case r.denied == total:
		return blocked
	case len(r.anchors) > 0:
		return trusts
	}
	return none
}

var (
	pemBegin = []byte("-----BEGIN CERTIFICATE-----")
	pemEnd   = []byte("-----END CERTIFICATE-----")
)

func (cat catalog) scan(data []byte) result {
	hay := [][]byte{data}
	if decoded := decodePEMBlocks(data); len(decoded) > 0 {
		hay = append(hay, decoded)
	}
	var r result
	for _, a := range cat.anchors {
		if anyContains(hay, a.key) {
			r.anchors = append(r.anchors, a.name)
		}
	}
	for _, k := range cat.keys {
		for _, m := range k.markers {
			if anyContains(hay, m) {
				r.denied++
				break
			}
		}
	}
	return r
}

func anyContains(hay [][]byte, needle []byte) bool {
	for _, h := range hay {
		if bytes.Contains(h, needle) {
			return true
		}
	}
	return false
}

// decodePEMBlocks finds PEM certificates anywhere in a file, including PEM text compiled into a binary,
// and returns their DER bytes concatenated.
func decodePEMBlocks(data []byte) []byte {
	var out []byte
	for {
		i := bytes.Index(data, pemBegin)
		if i < 0 {
			return out
		}
		data = data[i+len(pemBegin):]
		j := bytes.Index(data, pemEnd)
		if j < 0 {
			return out
		}
		body := bytes.ReplaceAll(data[:j], []byte(`\n`), nil)
		clean := make([]byte, 0, len(body))
		for _, c := range body {
			if c == '+' || c == '/' || c == '=' || (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
				clean = append(clean, c)
			}
		}
		if der, err := base64.StdEncoding.DecodeString(string(clean)); err == nil {
			out = append(out, der...)
		}
		data = data[j+len(pemEnd):]
	}
}
