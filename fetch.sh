#!/usr/bin/env bash
# Downloads the real published artifacts in fixtures/artifacts.txt into .cache/ and checks each sha256.
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p .cache
grep -v '^#' fixtures/artifacts.txt | while read -r name sum url; do
  f=".cache/$name"
  if [ ! -f "$f" ] || ! echo "$sum  $f" | sha256sum -c --quiet - 2>/dev/null; then
    curl -sSfL -o "$f" "$url"
  fi
  echo "$sum  $f" | sha256sum -c --quiet -
done
echo "fetched $(grep -vc '^#' fixtures/artifacts.txt) artifacts, sha256 verified"
