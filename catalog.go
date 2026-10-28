package main

import (
	"crypto/sha256"
	"crypto/x509"
	_ "embed"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"
)

//go:embed data/roots.json
var rootsJSON []byte

//go:embed data/impacted.json
var impactedJSON []byte

type certRecord struct {
	Name           string `json:"name"`
	IssuerOperator string `json:"issuer_operator"`
	PEM            string `json:"pem"`
	SHA256         string `json:"sha256"`
	SPKISHA256     string `json:"spki_sha256"`
}

// anchor is a root the compromised intermediates chain to.
// Finding its public key means the artifact can trust those chains.
type anchor struct {
	name string
	key  []byte
}

// compromisedKey is one of the eight leaked intermediate keys.
// Each key exists as two certificates (eMudhra-signed and Sectigo cross-signed).
// Finding a marker for every key means the artifact ships a denylist.
type compromisedKey struct {
	name    string
	markers [][]byte
}

type catalog struct {
	anchors []anchor
	keys    []compromisedKey
}

func loadCatalog() (catalog, error) {
	var roots, impacted []certRecord
	if err := json.Unmarshal(rootsJSON, &roots); err != nil {
		return catalog{}, err
	}
	if err := json.Unmarshal(impactedJSON, &impacted); err != nil {
		return catalog{}, err
	}
	var cat catalog
	for _, r := range roots {
		key, _, err := publicKey(r.PEM)
		if err != nil {
			return catalog{}, fmt.Errorf("root %s: %w", r.Name, err)
		}
		cat.anchors = append(cat.anchors, anchor{name: r.Name, key: key})
	}
	byKey := map[string]int{}
	for _, c := range impacted {
		key, spki, err := publicKey(c.PEM)
		if err != nil {
			return catalog{}, fmt.Errorf("intermediate %s: %w", c.Name, err)
		}
		i, seen := byKey[string(key)]
		if !seen {
			spkiSum := sha256.Sum256(spki)
			i = len(cat.keys)
			byKey[string(key)] = i
			cat.keys = append(cat.keys, compromisedKey{name: c.Name, markers: append([][]byte{key}, hashForms(spkiSum[:])...)})
		}
		certSum, err := hex.DecodeString(c.SHA256)
		if err != nil {
			return catalog{}, err
		}
		cat.keys[i].markers = append(cat.keys[i].markers, hashForms(certSum)...)
	}
	return cat, nil
}

// hashForms covers how denylists embed a SHA-256: raw bytes (Node.js), lowercase hex (Go), uppercase hex.
func hashForms(sum []byte) [][]byte {
	h := hex.EncodeToString(sum)
	return [][]byte{sum, []byte(h), []byte(strings.ToUpper(h))}
}

// publicKey returns the raw subjectPublicKey bytes (EC point or RSAPublicKey DER) and the full SPKI DER.
// The raw key is the one byte string every trust store format keeps verbatim.
func publicKey(certPEM string) ([]byte, []byte, error) {
	blk, _ := pem.Decode([]byte(certPEM))
	if blk == nil {
		return nil, nil, fmt.Errorf("no PEM block")
	}
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return nil, nil, err
	}
	var spki struct {
		Algorithm asn1.RawValue
		Key       asn1.BitString
	}
	if _, err := asn1.Unmarshal(c.RawSubjectPublicKeyInfo, &spki); err != nil {
		return nil, nil, err
	}
	return spki.Key.Bytes, c.RawSubjectPublicKeyInfo, nil
}
