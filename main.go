// Command anchorsweep finds every copy of a TLS trust store inside files, binaries,
// wheels, tarballs and image layers, and says whether it still trusts the
// compromised eMudhra intermediates (October 2026).
package main

import (
	"flag"
	"fmt"
	"os"
	"path"
	"strings"
)

// bundleNames is what a path-based check looks at: the well-known CA bundle file names.
var bundleNames = map[string]bool{
	"ca-certificates.crt": true, "cert.pem": true, "cacert.pem": true,
	"ca-bundle.crt": true, "tls-ca-bundle.pem": true, "roots.pem": true, "cacerts": true,
}

func main() {
	pathsOnly := flag.Bool("paths-only", false, "only scan files with well-known CA bundle names (what a bundle-path check sees)")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: anchorsweep [--paths-only] PATH...")
		flag.PrintDefaults()
	}
	flag.Parse()
	if flag.NArg() == 0 {
		flag.Usage()
		os.Exit(2)
	}
	cat, err := loadCatalog()
	if err != nil {
		fmt.Fprintln(os.Stderr, "anchorsweep:", err)
		os.Exit(2)
	}

	var scanned, trusting, blocking int
	report := func(name string, data []byte) {
		if *pathsOnly && !bundleNames[path.Base(name[strings.LastIndex(name, "!")+1:])] {
			return
		}
		scanned++
		r := cat.scan(data)
		switch r.verdict(len(cat.keys)) {
		case trusts:
			trusting++
			fmt.Printf("TRUSTS\t%s\troots: %s\n", name, strings.Join(r.anchors, ", "))
		case blocked:
			blocking++
			detail := fmt.Sprintf("denylist covers %d/%d compromised keys", r.denied, len(cat.keys))
			if len(r.anchors) > 0 {
				detail += "; roots still present: " + strings.Join(r.anchors, ", ")
			}
			fmt.Printf("BLOCKED\t%s\t%s\n", name, detail)
		}
	}
	for _, p := range flag.Args() {
		if err := walkPath(p, report); err != nil {
			fmt.Fprintln(os.Stderr, "anchorsweep:", err)
			os.Exit(2)
		}
	}
	fmt.Printf("scanned %d files: %d still trust the compromised chains, %d ship a denylist\n", scanned, trusting, blocking)
	if trusting > 0 {
		os.Exit(1)
	}
}
