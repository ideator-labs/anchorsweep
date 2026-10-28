# AGENTS.md

Handoff for a coding agent with no prior context.

## What this is

anchorsweep is a Go CLI. Point it at directories, files and archives. It reports every file that still trusts the compromised eMudhra intermediates (key compromise disclosed 2026-10-17 to 2026-10-20), and every file that ships a denylist for them.

The claim: a container or host can pass the usual `curl https://dv-g3b-emudhra.we-have-a-problem.com/` check and still trust the compromised chains, because Node.js, Deno and Go binaries compile their own roots in. Matching public key bytes finds those copies by content, in any file, and the verdicts agree with what each artifact really does.

## Status

Real, nothing stubbed. `bash demo.sh` runs 11 checks against real published releases pinned by sha256: Alpine minirootfs 3.22.6 and 3.22.7, certifi 2026.7.22 and 2026.10.19, Node 22.23.3 and 22.23.4, Deno 2.9.7 and 2.9.8, the curl CA bundles of 2026-09-25 and 2026-10-20, and two Go programs built from source with Go 1.27.2 and 1.27.3. Last fresh-clone run: 11 passed, 0 failed, exit 0. `bash demo.sh --break` gives 5 passed, 6 failed, exit 1.

Three checks are independent ground truth that do not use anchorsweep: `openssl verify` on the Alpine bundles, `x509.Verify` built with each Go version, and Node's own `tls.rootCertificates`. `live.sh` is optional and needs network. On 2026-10-28 it gave CONNECTED for Node 22.23.3, Deno 2.9.7 and the Go 1.27.2 probe, and rejected for Node 22.23.4, Deno 2.9.8 and the Go 1.27.3 probe.

## Data shape

```
catalog
  anchors []anchor          4 roots from data/roots.json
    name string             e.g. "emSign ECC Root CA - G3"
    key  []byte             raw subjectPublicKey bytes (EC point or RSAPublicKey DER)
  keys []compromisedKey     8 leaked keys from data/impacted.json (16 certs, cross-signs share a key)
    name    string
    markers [][]byte        raw public key, SPKI SHA-256 (raw, hex, HEX), cert SHA-256 (raw, hex, HEX)

result (per file)
  anchors []string          roots whose key bytes appear in the file or in any PEM block decoded from it
  denied  int               how many of the 8 keys have at least one marker in the file

verdict
  BLOCKED  denied == 8, roots may still be present
  TRUSTS   any anchor and denied < 8
  (none)   otherwise, not printed
```

Archive members are named `outer!inner`, nested as deep as needed (limit 6).

## Repo map

- `main.go`: flags (`--paths-only`), output lines, exit codes (1 if any TRUSTS, 2 on error).
- `catalog.go`: embeds `data/*.json` and builds the markers.
- `scan.go`: byte search plus PEM-anywhere decoding, and the verdict rule.
- `walk.go`: directory walk and archive detection by magic bytes (zip, gzip, xz, tar).
- `scan_test.go`: unit tests for the catalog shape, PEM inside a binary blob and a hex denylist.
- `data/roots.json`, `data/impacted.json`: copied from https://emudhra.we-have-a-problem.com/ on 2026-10-28. sha256 119f32cd81a6b5a4e3c4c2df5fe07daa90dc43cafa123a62f0394f1895d92380 (roots) and f67b3abe9b4879f4e91874ed041beccd71257f1db41c588c724ccf12aa90c59e (impacted).
- `fixtures/artifacts.txt`: name, sha256, URL of each downloaded release.
- `fixtures/goprobe`: HTTPS client that imports `golang.org/x/crypto/x509roots/fallback` pinned to the 2026-09-16 bundle.
- `fixtures/goverify`: `x509.Verify` of a chain file against a PEM roots file, used as ground truth.
- `fixtures/dv-g3b-chain.pem`: the chain served by the dv-g3b test host, from the tracker's chains.zip.
- `fetch.sh`, `demo.sh`, `live.sh`.

## Setup, run, verify (fresh clone)

```
git clone https://github.com/ideator-labs/anchorsweep && cd anchorsweep
go version            # needs go1.27.3 or newer on PATH; GOTOOLCHAIN must allow downloads (default)
go test ./...         # ok
bash demo.sh          # first run downloads ~155 MB; ends with "11 passed, 0 failed", exit 0
bash demo.sh --break  # ends with "5 passed, 6 failed", exit 1
bash live.sh          # optional, network
```

Also needs `curl`, `openssl`, `tar` with xz support, `unzip` (live.sh only), `sha256sum`. Linux x86_64, because the Node and Deno releases are linux-x64 binaries that the demo runs.

## Design decisions

- Match the raw public key, not a file name, package or version. That is the one byte string every format keeps: PEM bundles (after decoding), DER in Deno, Java keystores, Go's fallback bundle.
- Decode PEM blocks anywhere in a file. Node compiles its roots in as PEM text, so a raw DER search misses it.
- Treat a full 8/8 denylist as BLOCKED even when the root is still present. Go 1.27.3 rejects the chain with the old bundle (`x509: no valid chains built`, check 8), so calling that file TRUSTS would be a false alarm.
- Do not build chains in Go. The tool is built with Go 1.27.3, whose denylist rejects every compromised chain, so `x509.Verify` inside the tool would always say safe.
- No registry client. Image input is a rootfs directory or a layer tarball. Alpine minirootfs is the official image's root layer, so the demo uses it as one.

## Known limits

- No chain building and no trust-flag parsing. A store that keeps a root but distrusts it through OpenSSL trust settings, NSS distrust bits or a separate blocklist shows as TRUSTS.
- A partial denylist is ignored.
- Whole files are read into memory, capped at 1 GiB per member.
- Not verified on Electron, Bun, Java runtimes, `webpki-roots` Rust binaries or Windows/macOS binaries.
- certifi 2026.10.18 contains no emSign root at all, so the patched-version table on the tracker (2026.10.19) is not the first clean certifi. The demo uses 2026.7.22 as the affected copy.
- `--break` also fails check 6 because the curl bundle files are not named `cacert.pem` in `.cache/`. That is the bundle-name rule working as written, not a scan bug.

## Next steps

1. OCI image input. Read a `docker save` tar or an OCI layout directory and apply layers in order, honoring whiteouts, so a file deleted in a later layer is not reported. Done when: a fixture image whose top layer deletes an old `ca-certificates.crt` reports nothing for it, and the same image without the whiteout reports TRUSTS.
2. Registry pull. `anchorsweep image alpine@sha256:...` fetches layers anonymously. Done when: the Docker Hub digest for alpine 3.22.6 amd64 reports TRUSTS and 3.22.7 reports nothing.
3. Trust-flag awareness. Parse OpenSSL `TRUSTED CERTIFICATE` blocks and Debian `ca-certificates.conf` `!` entries. Done when: a bundle with emSign ECC Root CA - G3 marked rejected reports nothing, with a test.
4. More runtimes. Add fixtures for Bun (1.4.3 vs 1.4.4), Electron (pre and post 44.9.1), a Temurin JRE `cacerts` and a Rust binary with `webpki-roots` 1.0.9 vs 1.0.10. Done when: each pair gives TRUSTS then BLOCKED or nothing, and the verdict matches a live or offline check.
5. JSON output and a GitHub Action. Done when: `--json` emits one object per finding and an Action run fails a PR that adds a TRUSTS file.
6. Generic catalog. Load any incident's roots and compromised certs from a file so the next CA incident needs no code change. Done when: `--catalog other.json` works and the default stays eMudhra.

## Working rules

- Keep `bash demo.sh` the source of truth. A change that alters a verdict must keep all 11 checks passing, and `--break` must still fail.
- Verify against real artifacts. Add a fixture to `fixtures/artifacts.txt` with its sha256, never a hand-made file posing as a release.
- Short sentences, no em-dashes, honest limits in docs.
- Commit as `danielgerlag <daniel@gerlag.ca>`.

## Context and sources

- Disclosure to trust store maintainers: https://www.openwall.com/lists/oss-security/2026/10/20/1
- Tracker, patched versions, roots.json, impacted-intermediates.json, chains.zip: https://emudhra.we-have-a-problem.com/
- Chainguard remediation guide (curl test only covers the system bundle): https://support.chainguard.dev/hc/en-us/articles/57499369353755-ACTION-REQUIRED-Update-all-Chainguard-Images-to-remove-eMudhra-Intermediate-CA-Data
- Cycle.io summary (containers and VMs most likely not patched): https://cycle.io/blog/2026-intermediate-ca-compromise
- Docker on rebuilding images for the CA fix: https://www.docker.com/blog/php2shell-and-emudhra-patched/
- Related tools: Swamp extension `@taylor/emudhra` (version and bundle checks for known tools, https://swamp-club.com/extensions/@taylor/emudhra) and `emsign-trust-scan` (Python scanner for stores and bundles).
