# anchorsweep

Find every TLS trust store hiding in a file tree, binary, wheel, tarball or image layer, and say whether it still trusts the compromised eMudhra intermediates.

On October 17, 2026 the private keys of eight eMudhra intermediate CAs turned out to be recoverable from the public certificates ([oss-security](https://www.openwall.com/lists/oss-security/2026/10/20/1), [tracker](https://emudhra.we-have-a-problem.com/)). Browsers block them. A container keeps trusting them until every copy of the roots inside it is fixed. The usual check is a `curl` to a test host, and Chainguard's guide says it plainly: "This test only covers software that reads the system certificate bundle" ([Chainguard](https://support.chainguard.dev/hc/en-us/articles/57499369353755-ACTION-REQUIRED-Update-all-Chainguard-Images-to-remove-eMudhra-Intermediate-CA-Data)).

Node.js, Deno and Go programs carry their own roots compiled into the binary. anchorsweep looks for the roots' public keys in the bytes themselves, so it finds those copies without knowing the file name, the package or the version.

Real output from the demo: a fixed Alpine 3.22.7 rootfs with the Node 22.23.3 binary copied in, plus the Deno 2.9.8 release zip.

```
$ ./anchorsweep .demo/app .cache/deno-2.9.8-x86_64-unknown-linux-gnu.zip
TRUSTS	.demo/app/usr/local/bin/node	roots: emSign ECC Root CA - G3
BLOCKED	.cache/deno-2.9.8-x86_64-unknown-linux-gnu.zip!deno	denylist covers 8/8 compromised keys
scanned 95 files: 1 still trust the compromised chains, 1 ship a denylist
```

Exit 1 if anything still trusts. Exit 0 otherwise.

## What it reports

- `TRUSTS`: the file contains the public key of a root the compromised intermediates chain to (emSign ECC Root CA - G3, AAA Certificate Services, emSign Root TLS CA - G3 or emSign Root CS CA - G3), and no denylist.
- `BLOCKED`: the file contains a marker for all eight compromised keys. That is what the fixed Node.js (raw SPKI hashes), Go 1.27.3 (hex SPKI hashes, present even in a plain `net/http` binary) and Deno (the intermediates' public keys) releases ship. The root may still be present, as in a Go 1.27.3 binary built with an old fallback bundle.
- Nothing printed: no eMudhra root and no denylist in that file.

It opens zip, wheel, jar, tar, tar.gz, tar.xz and Alpine apk (gzip) inputs, nested. It reads PEM blocks anywhere in a file, including PEM text compiled into a binary.

## Try it

```
go build -o anchorsweep .
./anchorsweep /path/to/rootfs-or-files
bash demo.sh          # downloads ~155 MB of real releases, 11 checks
bash demo.sh --break  # bundle-path scan only; 6 checks fail
bash live.sh          # optional, hits Mozilla's public test host with each runtime
```

Needs Go 1.27.3, curl, openssl and network access for the first run. The demo builds two Go probes with Go 1.27.2 through `GOTOOLCHAIN`, which downloads that toolchain once.

## What the demo measured (2026-10-28)

| Artifact | anchorsweep | Independent check |
| --- | --- | --- |
| Alpine minirootfs 3.22.6 | TRUSTS (system bundle) | `openssl verify` accepts the dv-g3b chain |
| Alpine minirootfs 3.22.7 | nothing | `openssl verify` rejects |
| certifi 2026.7.22 / 2026.10.19 | TRUSTS / nothing | |
| Node 22.23.3 / 22.23.4 | TRUSTS / BLOCKED | `tls.rootCertificates` has the root / does not; live: CONNECTED / CERT_REVOKED |
| Deno 2.9.7 / 2.9.8 | TRUSTS / BLOCKED | live: CONNECTED / rejected |
| Go probe, 2026-09-16 fallback bundle, Go 1.27.2 / 1.27.3 | TRUSTS / BLOCKED, root still inside | `x509.Verify`: nil / `no valid chains built`; live: CONNECTED / rejected |
| Alpine 3.22.7 rootfs plus Node 22.23.3 binary | TRUSTS `usr/local/bin/node` | bundle-path scan says clean |

## Limits

- It matches public key bytes. It does not build chains, so a store that holds a root but distrusts it by a mechanism it does not know (OpenSSL trust flags, NSS distrust bits, a separate blocklist file) shows as TRUSTS.
- A denylist counts only when it covers all eight keys. A partial one is ignored.
- It does not pull images from a registry. Export a layer or a rootfs and point it at that.
- Electron, Bun, Java runtimes and Rust binaries using `webpki-roots` were not part of the demo. The same byte match should apply, but it is not verified here.
- The catalog is `data/roots.json` and `data/impacted.json` from the tracker, vendored on 2026-10-28.

For a coding agent picking this up, start with [AGENTS.md](AGENTS.md).
