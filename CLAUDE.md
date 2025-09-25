# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Rclone is a command-line program to sync files and directories to and from different cloud storage providers. It's written in Go and supports 70+ cloud storage providers including S3, Google Drive, Dropbox, and many others.

## Architecture

### Core Components

- **`rclone.go`**: Main entry point that imports all backends and commands
- **`fs/`**: Core filesystem abstraction layer
  - `fs/fs.go`: Main filesystem interface definitions
  - `fs/operations/`: Core sync and copy operations
  - `fs/config/`: Configuration management and UI
  - `fs/filter/`: File filtering and inclusion/exclusion rules
  - `fs/accounting/`: Transfer statistics and progress tracking
- **`backend/`**: Cloud storage provider implementations (70+ providers)
  - Each backend (e.g., `s3/`, `drive/`, `dropbox/`) implements the `fs.Fs` interface
- **`cmd/`**: Command-line interface and all rclone commands
  - `cmd/cmd.go`: Command framework and common functionality
  - Individual commands in subdirectories (e.g., `copy/`, `sync/`, `mount/`)
- **`vfs/`**: Virtual file system for mount operations

### Key Patterns

- **Backend Interface**: All storage providers implement `fs.Fs` and `fs.Object` interfaces
- **Command Pattern**: Each rclone command is a separate package under `cmd/`
- **Plugin Architecture**: Backends and commands are imported via `_` imports in `all.go` files
- **Configuration**: Unified config system in `fs/config/` handles all provider authentication

## Development Commands

### Building
```bash
make rclone                    # Build rclone binary
go build -v                    # Basic build
```

### Testing
```bash
make quicktest                 # Fast tests without external dependencies
make test                      # Full integration test suite (requires test backends)
make racequicktest            # Race condition detection tests
make compiletest              # Compilation-only tests
```

### Code Quality
```bash
make check                     # Run linting with golangci-lint
golangci-lint run ./...       # Direct linting (requires golangci-lint installed)
```

### Dependencies
```bash
make build_dep                # Install build dependencies (golangci-lint)
make tidy                     # Clean up go.mod dependencies
make update                   # Update all dependencies
```

### Testing Individual Backends
```bash
# Set backend-specific environment variables first, then:
go test ./backend/s3/         # Test specific backend
go test -run TestIntegration  # Run integration tests
```

### Documentation
```bash
make doc                      # Generate all documentation
make commanddocs             # Generate command documentation
make backenddocs             # Generate backend documentation
```

## Important Files

- **`Makefile`**: Contains all build, test, and release targets
- **`go.mod`**: Go module definition with 100+ dependencies
- **`VERSION`**: Current version number
- **`fs/versiontag.go`**: Version tag for development builds

## Backend Development

When adding a new backend:
1. Create directory under `backend/yourprovider/`
2. Implement `fs.Fs` and `fs.Object` interfaces
3. Add to `backend/all/all.go` imports
4. Add configuration options in the backend constructor
5. Add tests following existing patterns

## Testing Notes

- Use `RCLONE_CONFIG="/notfound"` to avoid using real config during tests
- Integration tests require real cloud storage credentials
- Most tests use the `fstest` package for standardized testing
- Backend tests are in `backend/provider/provider_test.go`

## Configuration

- Config stored in `~/.config/rclone/rclone.conf` by default
- Environment variables: `RCLONE_CONFIG_*` for config overrides
- Use `rclone config` command for interactive setup
- Backend configs defined in each backend's `Options` variable