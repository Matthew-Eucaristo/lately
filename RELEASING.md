# Releasing

Releases are cut by pushing a `v*` tag. The `release` workflow runs the tests and publishes release archives for macOS (arm64, amd64) with GoReleaser, using only the built-in `GITHUB_TOKEN` (no secrets to maintain). Release notes come from the commits since the previous tag; `docs:`, `test:`, `ci:` and `chore:` commits are left out.

The Homebrew formula lives in [Matthew-Eucaristo/homebrew-tap](https://github.com/Matthew-Eucaristo/homebrew-tap) as `Formula/lately.rb` and is bumped by hand, which takes a minute and needs no token.

## One-time setup

- Enable **Settings → Code security → Private vulnerability reporting** (referenced by SECURITY.md).
- The demo GIF is recorded locally from sample data: `brew install vhs`, then `vhs demo/demo.tape`. Check every frame for PII and commit `demo/demo.gif` when the TUI changes.

## Each release

```sh
V=0.1.0
git tag v$V && git push origin v$V
SHA=$(curl -sL https://github.com/Matthew-Eucaristo/lately/archive/refs/tags/v$V.tar.gz | shasum -a 256 | cut -d' ' -f1)
```

In a clone of the tap, create or update `Formula/lately.rb` from `packaging/homebrew/lately.rb` with the new version in `url` and `$SHA` in `sha256`, add a row to the tap README, commit `lately $V`, and push. Then check it:

```sh
brew update
brew upgrade matthew-eucaristo/tap/lately || brew install matthew-eucaristo/tap/lately
brew test lately
brew audit --strict --online matthew-eucaristo/tap/lately
```

When the contract changes, bump `schema_version` only for breaking changes, update `docs/contract.md`, and say so in the release notes. When rule semantics change, bump `rules.Version`.

Before tagging, recapture fixtures on the newest macOS (`go run ./tools/fixtures`), review the diff, and rerun the lens timings in `docs/design.md`.
