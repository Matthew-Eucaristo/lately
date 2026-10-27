#!/usr/bin/env bash
# Prepares the demo recording: a fake HOME, a fixed prompt and lately built
# from this checkout. The recording replays demo/sample (generic sample
# events), so no log, report or name from the real Mac appears in any frame.
# A first replay of demo/sample/seen builds the baseline, so the main
# replay can mark what is new.
# Usage: source demo/setup.sh   (from the repository root)
# Remove: rm -rf /tmp/lately-demo
set -e

DEMO="$(cd /tmp && pwd -P)/lately-demo"
rm -rf "$DEMO"
mkdir -p "$DEMO/bin" "$DEMO/home"
go build -trimpath -o "$DEMO/bin/lately" .
cp -R demo/sample "$DEMO/sample"

export HOME="$DEMO/home" PATH="$DEMO/bin:$PATH" PS1='$ ' TZ=UTC LATELY_BASELINE="$DEMO/baseline.json"
cd "$DEMO"
lately --replay sample/seen --since 2d --list >/dev/null || true
set +e
