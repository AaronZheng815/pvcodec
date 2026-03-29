# AGENTS.md

## Project Overview

pvcodec is a protocol verification tool that parses pcap/pcapng packet capture files using Wireshark's tshark. It consists of:
- **Backend**: Go HTTP server (`cmd/pvcodec`, `internal/httpapi`, `internal/tshark`, `internal/model`)
- **Frontend**: React + TypeScript + Vite web UI (`web/`)

## Build/Lint/Test Commands

### Go (Backend)

```bash
# Build all packages
go build ./...

# Run all tests
go test ./...

# Run tests with verbose output
go test -v ./...

# Run tests for a specific package
go test ./internal/tshark
go test ./internal/httpapi

# Run a single test function
go test -v -run TestListPackets ./internal/tshark
go test -v -run TestHealth ./internal/httpapi

# Run tests with coverage
go test -cover ./...

# Format code (standard Go format)
go fmt ./...

# Vet code
go vet ./...
```

### Web (Frontend)

```bash
cd web

# Install dependencies
npm install

# Development server (proxies /api to localhost:8080)
npm run dev

# Build for production
npm run build

# Type check
tsc --noEmit

# Preview production build
npm run preview
```

### Environment Variables

- `PVCODEC_TSHARK_PATH`: Custom path to tshark binary (default: auto-detected)

---

## Code Style Guidelines

### Go Backend

#### General
- Use `gofmt` for formatting (4-space indentation, tabs for indentation, spaces for alignment)
- Follow [Effective Go](https://go.dev/doc/effective_go) conventions
- Keep lines under 100 characters when reasonable

#### Imports
- Standard library imports first, then third-party, then internal
- Use `go fmt` to organize imports automatically
- Group imports with blank lines between groups:
  ```go
  import (
      "bufio"
      "bytes"
      "encoding/json"
      
      "github.com/AaronZheng815/pvcodec/internal/model"
  )
  ```

#### Naming Conventions
- **Packages**: lowercase, single word generally; use `tshark`, not `tshark_lib`
- **Types**: PascalCase (`TShark`, `PacketDetail`, `TreeNode`)
- **Functions/Methods**: PascalCase for exported, camelCase for unexported (`NewServer`, `ListPackets`, `parseSummaryOutput`)
- **Variables**: camelCase; prefer meaningful names over short (`filePath`, not `fp`)
- **Constants**: PascalCase for exported, camelCase for unexported
- **Interfaces**: PascalCase, often with `-er` suffix (`Runner`, `Interface`)
- **Error variables**: `err` prefix for errors, `Err` prefix for sentinel errors

#### Types
- Use struct tags for JSON serialization (e.g., `json:"index"`)
- Prefer explicit struct types over generic `map[string]any` except when deserializing dynamic data
- Use `any` (not `interface{}`) for generic type parameters

#### Error Handling
- Return errors rather than panic for expected failure cases
- Wrap errors with context using `fmt.Errorf("doing thing: %w", err)`
- Use `errors.Is` and `errors.As` for error inspection
- Handle errors explicitly; don't ignore with `_`

#### Functions
- Keep functions focused; if >50 lines, consider splitting
- Unexported helper functions can be lowercase
- Use receiver methods for operations on struct instances

### Testing Conventions
- Test files: `*_test.go` in same package
- Table-driven tests preferred for multiple cases:
  ```go
  func TestDisplayFilter(t *testing.T) {
      tests := []struct {
          protocol string
          want     string
      }{
          {"NGAP", "ngap"},
          {"NAS", "nas-5gs"},
      }
      for _, tt := range tests {
          got := DisplayFilter(tt.protocol)
          if got != tt.want {
              t.Errorf("DisplayFilter(%q) = %q, want %q", tt.protocol, got, tt.want)
          }
      }
  }
  ```
- Use `t.Fatal`/`t.Fatalf` for setup failures, `t.Error`/`t.Errorf` for assertion failures
- Use `t.Cleanup` for resource teardown
- Mock external dependencies via interfaces (e.g., `Runner` interface for tshark execution)

### Frontend (TypeScript/React)

#### TypeScript
- Use `strict` mode (enabled in tsconfig)
- Avoid `any`; use `unknown` when type is truly unknown
- Use explicit types for function parameters and return values
- Use `interface` for object shapes, `type` for unions/primitives

#### React
- Functional components with hooks (no class components)
- Co-locate styles with components (`.tsx` + `.css` files in same directory)
- Use `any` props sparingly; define proper interfaces

#### Naming
- Components: PascalCase (`PacketList`, `CaptureViewer`)
- Files: PascalCase for components (`PacketList.tsx`), camelCase for utilities
- CSS classes: kebab-case (`.packet-list`)

---

## Architecture Notes

### TShark Abstraction
The `tshark.Runner` interface enables testing without requiring actual tshark installation:
```go
type Runner interface {
    Output(name string, args ...string) ([]byte, error)
}
```
Use `NewForTest(runner)` constructor in tests with `fakeRunner` implementations.

### Server Architecture
- `httpapi.Server` is the main HTTP handler
- Routes registered via `routes()` method
- Dependency injection for `TShark` allows testing
- Use `writeJSON(w, status, data)` helper for JSON responses

### Model Package
`internal/model` contains pure data structures shared between packages:
- `PacketSummary`: Summary info for packet list
- `PacketDetail`: Detailed packet info with tree structure
- `TreeNode`: Recursive tree representation for protocol layers
