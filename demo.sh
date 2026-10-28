#!/usr/bin/env bash
# Proves: anchorsweep finds trust stores compiled into binaries and packed in archives,
# and its verdict matches what the artifact actually does with a compromised eMudhra chain.
# --break scans only well-known CA bundle paths, which is what a bundle check sees. Checks should fail.
set -uo pipefail
cd "$(dirname "$0")"

MODE=()
if [ "${1:-}" = "--break" ]; then MODE=(--paths-only); echo "BREAK MODE: scanning bundle paths only"; fi

./fetch.sh
go build -o anchorsweep . || exit 2
C=.cache
W=.demo
rm -rf "$W" && mkdir -p "$W/go"

echo "building Go probes: same fallback bundle (2026-09-16), Go 1.27.2 vs 1.27.3"
(cd fixtures/goprobe && GOTOOLCHAIN=go1.27.2 go build -o "../../$W/go/probe-go1.27.2" . && GOTOOLCHAIN=go1.27.3 go build -o "../../$W/go/probe-go1.27.3" .) || exit 2
(cd fixtures/goverify && GOTOOLCHAIN=go1.27.2 go build -o "../../$W/go/verify-go1.27.2" . && GOTOOLCHAIN=go1.27.3 go build -o "../../$W/go/verify-go1.27.3" .) || exit 2

echo "assembling an app image: fixed Alpine 3.22.7 rootfs plus the Node 22.23.3 binary"
mkdir -p "$W/app/usr/local/bin" "$W/a6" "$W/a7" "$W/node3" "$W/node4"
tar -xzf "$C/alpine-minirootfs-3.22.7-x86_64.tar.gz" -C "$W/app"
tar -xzf "$C/alpine-minirootfs-3.22.6-x86_64.tar.gz" -C "$W/a6" ./etc/ssl/certs/ca-certificates.crt
tar -xzf "$C/alpine-minirootfs-3.22.7-x86_64.tar.gz" -C "$W/a7" ./etc/ssl/certs/ca-certificates.crt
tar -xJf "$C/node-v22.23.3-linux-x64.tar.xz" -C "$W/node3" --strip-components=2 node-v22.23.3-linux-x64/bin/node
tar -xJf "$C/node-v22.23.4-linux-x64.tar.xz" -C "$W/node4" --strip-components=2 node-v22.23.4-linux-x64/bin/node
cp "$W/node3/node" "$W/app/usr/local/bin/node"

sweep() { ./anchorsweep "${MODE[@]}" "$@"; }

pass=0; fail=0
check() {
  if [ "$2" = ok ]; then pass=$((pass + 1)); echo "PASS $1"; else fail=$((fail + 1)); echo "FAIL $1"; fi
}
has() { grep -qF -- "$2" <<<"$1" && echo ok || echo no; }
lacks() { grep -qF -- "$2" <<<"$1" && echo no || echo ok; }
both() { [ "$1" = ok ] && [ "$2" = ok ] && echo ok || echo no; }

echo
echo "== sweeping real artifacts"
OUT=$(sweep "$C" "$W/go" 2>&1); echo "$OUT"
echo

check "1 Alpine 3.22.6 image layer trusts emSign ECC Root CA - G3, 3.22.7 does not" \
  "$(both "$(has "$OUT" $'TRUSTS\t.cache/alpine-minirootfs-3.22.6-x86_64.tar.gz!./etc/ssl/certs/ca-certificates.crt\troots: emSign ECC Root CA - G3')" "$(lacks "$OUT" 'alpine-minirootfs-3.22.7')")"

check "2 certifi 2026.7.22 wheel trusts, certifi 2026.10.19 does not" \
  "$(both "$(has "$OUT" $'TRUSTS\t.cache/certifi-2026.7.22-py3-none-any.whl!certifi/cacert.pem')" "$(lacks "$OUT" 'certifi-2026.10.19')")"

check "3 Node 22.23.3 binary trusts (PEM compiled into bin/node), 22.23.4 ships a denylist" \
  "$(both "$(has "$OUT" $'TRUSTS\t.cache/node-v22.23.3-linux-x64.tar.xz!node-v22.23.3-linux-x64/bin/node\troots: emSign ECC Root CA - G3')" "$(has "$OUT" $'BLOCKED\t.cache/node-v22.23.4-linux-x64.tar.xz!node-v22.23.4-linux-x64/bin/node\tdenylist covers 8/8')")"

check "4 Deno 2.9.7 binary trusts AAA and emSign ECC roots (DER compiled in), 2.9.8 ships a denylist" \
  "$(both "$(has "$OUT" $'TRUSTS\t.cache/deno-2.9.7-x86_64-unknown-linux-gnu.zip!deno\troots: AAA Certificate Services, emSign ECC Root CA - G3')" "$(has "$OUT" $'BLOCKED\t.cache/deno-2.9.8-x86_64-unknown-linux-gnu.zip!deno\tdenylist covers 8/8')")"

check "5 Go binary with the old fallback bundle trusts on Go 1.27.2, is blocked on Go 1.27.3 with the root still inside" \
  "$(both "$(has "$OUT" $'TRUSTS\t.demo/go/probe-go1.27.2\troots: emSign ECC Root CA - G3')" "$(has "$OUT" $'BLOCKED\t.demo/go/probe-go1.27.3\tdenylist covers 8/8 compromised keys; roots still present: emSign ECC Root CA - G3')")"

check "6 the curl CA bundle from 2026-09-25 trusts, 2026-10-20 does not" \
  "$(both "$(has "$OUT" $'TRUSTS\t.cache/curl-cacert-2026-09-25.pem')" "$(lacks "$OUT" 'curl-cacert-2026-10-20')")"

echo
echo "== ground truth: does each artifact accept the compromised chain? (offline, no anchorsweep involved)"
CHAIN=fixtures/dv-g3b-chain.pem
sed -n '/END CERTIFICATE/,$p' "$CHAIN" | tail -n +2 > "$W/untrusted.pem"
ov() { openssl verify -CAfile "$1" -untrusted "$W/untrusted.pem" "$CHAIN" >/dev/null 2>&1 && echo accepts || echo rejects; }
A6=$(ov "$W/a6/etc/ssl/certs/ca-certificates.crt"); A7=$(ov "$W/a7/etc/ssl/certs/ca-certificates.crt")
echo "openssl verify with Alpine 3.22.6 bundle: $A6; with 3.22.7 bundle: $A7"
check "7 openssl agrees with the Alpine verdicts" "$( [ "$A6" = accepts ] && [ "$A7" = rejects ] && echo ok || echo no)"

G2=$("$W/go/verify-go1.27.2" "$C/curl-cacert-2026-09-25.pem" "$CHAIN"); G3=$("$W/go/verify-go1.27.3" "$C/curl-cacert-2026-09-25.pem" "$CHAIN")
echo "crypto/x509 Verify against the old bundle: Go 1.27.2 -> ${G2:-<nil>}; Go 1.27.3 -> $G3"
check "8 Go 1.27.2 accepts the chain and Go 1.27.3 rejects it with the same roots, so BLOCKED is right" \
  "$( [ "$G2" = "<nil>" ] && [ "$G3" = "x509: no valid chains built" ] && echo ok || echo no)"

N3=$("$W/node3/node" -p "require('tls').rootCertificates.some(c => c.includes('MIICTjCCAdOgAwIBAgIKPPYHqWhwDtqLhDAKBggqhkjOPQQDAzBr'))")
N4=$("$W/node4/node" -p "require('tls').rootCertificates.some(c => c.includes('MIICTjCCAdOgAwIBAgIKPPYHqWhwDtqLhDAKBggqhkjOPQQDAzBr'))")
echo "tls.rootCertificates includes emSign ECC Root CA - G3: Node 22.23.3 -> $N3; Node 22.23.4 -> $N4"
check "9 Node's own root list agrees with the Node verdicts" "$( [ "$N3" = true ] && [ "$N4" = false ] && echo ok || echo no)"

echo
echo "== the gap: a rebuilt base image that still runs an old runtime"
APP=$(sweep "$W/app" 2>&1); echo "$APP"
BUNDLE=$(./anchorsweep --paths-only "$W/app" 2>&1); echo "bundle-path view: $BUNDLE"
check "10 app image on the fixed Alpine base: bundle paths look clean, anchorsweep finds usr/local/bin/node" \
  "$(both "$(has "$BUNDLE" 'scanned 1 files: 0 still trust')" "$(has "$APP" $'TRUSTS\t.demo/app/usr/local/bin/node')")"

echo
echo "== exit codes"
sweep "$C/alpine-minirootfs-3.22.7-x86_64.tar.gz" "$C/certifi-2026.10.19-py3-none-any.whl" "$C/node-v22.23.4-linux-x64.tar.xz" "$C/deno-2.9.8-x86_64-unknown-linux-gnu.zip" "$W/go/probe-go1.27.3" >/dev/null 2>&1; FIXED=$?
sweep "$C/deno-2.9.7-x86_64-unknown-linux-gnu.zip" >/dev/null 2>&1; OLD=$?
echo "fixed set exit $FIXED; Deno 2.9.7 exit $OLD"
check "11 exit 0 when every copy is fixed, exit 1 when one still trusts" "$( [ "$FIXED" = 0 ] && [ "$OLD" = 1 ] && echo ok || echo no)"

echo
echo "$pass passed, $fail failed"
[ "$fail" = 0 ]
