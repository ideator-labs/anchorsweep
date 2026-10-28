package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func mustCatalog(t *testing.T) catalog {
	t.Helper()
	cat, err := loadCatalog()
	if err != nil {
		t.Fatal(err)
	}
	return cat
}

func TestCatalogShape(t *testing.T) {
	cat := mustCatalog(t)
	if len(cat.anchors) != 4 || len(cat.keys) != 8 {
		t.Fatalf("got %d anchors and %d keys, want 4 and 8", len(cat.anchors), len(cat.keys))
	}
}

func TestPEMInsideBinaryTrusts(t *testing.T) {
	cat := mustCatalog(t)
	var roots []certRecord
	if err := json.Unmarshal(rootsJSON, &roots); err != nil {
		t.Fatal(err)
	}
	blob := "\x00\x7fELF junk\x00" + roots[3].PEM + "\x00more junk"
	r := cat.scan([]byte(blob))
	if r.verdict(len(cat.keys)) != trusts || r.anchors[0] != "emSign ECC Root CA - G3" {
		t.Fatalf("got %+v", r)
	}
}

func TestHexDenylistBlocks(t *testing.T) {
	cat := mustCatalog(t)
	var impacted []certRecord
	if err := json.Unmarshal(impactedJSON, &impacted); err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	for _, c := range impacted {
		b.WriteString(strings.ToLower(c.SPKISHA256) + "\x00")
	}
	if v := cat.scan([]byte(b.String())).verdict(len(cat.keys)); v != blocked {
		t.Fatalf("got %q, want BLOCKED", v)
	}
	if v := cat.scan([]byte(b.String()[:65*4])).verdict(len(cat.keys)); v != none {
		t.Fatalf("partial denylist without roots: got %q, want no finding", v)
	}
}
