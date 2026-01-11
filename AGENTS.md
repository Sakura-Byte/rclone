# Repository Guidelines

## Project Structure & Module Organization
`rclone.go` and the `cmd/rclone` package bootstrap the CLI. Providers and protocol logic live under `backend/`, while reusable filesystem abstractions sit in `fs/` and `lib/`. Virtual filesystem layers are in `vfs/`. Tests commonly mirror their targets inside `fstest/` and `cmdtest/`. End-user docs, release notes, and design write-ups belong in `docs/`, `MANUAL.md`, and `contrib/`. Keep build helpers and scripts within `bin/` or `scripts/` as appropriate.

## Build, Test, and Development Commands
- `go build ./...` — compile rclone with the current module sum.
- `make rclone` — produce a versioned binary and sync it into your `$GOPATH/bin`.
- `go run . version` — verify the binary reports the expected tag.
- `make quicktest` — run fast unit tests with `RCLONE_CONFIG=/notfound`.
- `make test` — execute the full integration suite and capture `test_all.log`.
- `golangci-lint run ./...` — match the CI lint profile locally.

## Coding Style & Naming Conventions
The tree follows standard Go conventions: tabs for indentation, `gofmt`-formatted imports, and CamelCase for exported identifiers. Keep packages small and purpose-driven; new remotes belong under `backend/<name>`. Run `go fmt ./...` before committing and rely on `golangci-lint` for deeper checks. Config or JSON fixtures should use lowercase, hyphenated filenames (e.g., `test-data.json`) and live beside the code they exercise.

## Testing Guidelines
Unit tests live with their packages and should use the `fstest` helpers for remotes. Name tests with the component first, such as `TestS3Multipart`. When a test touches cloud services, gate it behind build tags or environment checks. Use `make quicktest` for rapid validation and `make test` before opening a pull request; the latter uploads logs you can attach to reviews. Add new golden files under `fstest/testdata/` and keep them minimal.

## Commit & Pull Request Guidelines
Adopt the existing short prefix style (`backend/s3: fix multipart retry`) and keep the subject under 70 characters; expand rationale in the body when needed. Reference GitHub issues with `Fixes #1234` when applicable. Pull requests should summarize behavior changes, list manual test coverage, and flag user-visible impacts. Include screenshots or config snippets if the CLI output or docs shift. Sync with `master` via `git fetch upstream && git rebase upstream/master` before requesting review.
