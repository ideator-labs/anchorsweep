// goprobe is a tiny HTTPS client that compiles in Go's fallback root bundle,
// the way distroless and scratch images often ship Go programs.
package main

import (
	"fmt"
	"net/http"
	"os"

	_ "golang.org/x/crypto/x509roots/fallback"
)

func main() {
	resp, err := http.Get(os.Args[1])
	if err != nil {
		fmt.Println("REJECTED", err)
		return
	}
	resp.Body.Close()
	fmt.Println("CONNECTED", resp.Status)
}
