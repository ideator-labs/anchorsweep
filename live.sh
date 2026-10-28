#!/usr/bin/env bash
# Optional, needs network: runs the old and new runtimes against Mozilla's public test host,
# which serves a chain through a compromised intermediate. Run demo.sh first.
set -uo pipefail
cd "$(dirname "$0")"
U=https://dv-g3b-emudhra.we-have-a-problem.com/
W=.demo
node_try() { "$1" -e "fetch('$U').then(() => console.log('CONNECTED')).catch(e => console.log('REJECTED', e.cause && e.cause.code))"; }
mkdir -p "$W/deno7" "$W/deno8"
unzip -oq .cache/deno-2.9.7-x86_64-unknown-linux-gnu.zip -d "$W/deno7"
unzip -oq .cache/deno-2.9.8-x86_64-unknown-linux-gnu.zip -d "$W/deno8"
deno_try() { "$1" eval "try { await fetch('$U'); console.log('CONNECTED') } catch (e) { console.log('REJECTED', String(e).slice(0, 60)) }"; }
echo "node 22.23.3: $(node_try "$W/node3/node")"
echo "node 22.23.4: $(node_try "$W/node4/node")"
echo "deno 2.9.7:   $(deno_try "$W/deno7/deno")"
echo "deno 2.9.8:   $(deno_try "$W/deno8/deno")"
# Empty system roots so Go falls back to the compiled-in bundle.
echo "go probe 1.27.2: $(SSL_CERT_FILE=/nonexistent SSL_CERT_DIR=/nonexistent "$W/go/probe-go1.27.2" "$U")"
echo "go probe 1.27.3: $(SSL_CERT_FILE=/nonexistent SSL_CERT_DIR=/nonexistent "$W/go/probe-go1.27.3" "$U")"
