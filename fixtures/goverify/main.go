package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

func certs(path string) []*x509.Certificate {
	b, _ := os.ReadFile(path)
	var out []*x509.Certificate
	for {
		var blk *pem.Block
		blk, b = pem.Decode(b)
		if blk == nil {
			return out
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err == nil {
			out = append(out, c)
		}
	}
}

func main() {
	roots := x509.NewCertPool()
	for _, c := range certs(os.Args[1]) {
		roots.AddCert(c)
	}
	chain := certs(os.Args[2])
	inter := x509.NewCertPool()
	for _, c := range chain[1:] {
		inter.AddCert(c)
	}
	_, err := chain[0].Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter})
	fmt.Println(err)
}
