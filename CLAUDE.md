# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project overview

This repo (Go module `gitlab.com/piccolo_su/vegeta`, product name "TensorSec"/"Navigator") is a
cloud-native security platform: image/host vulnerability scanning, K8s/Docker compliance
(kube-bench/docker-bench/host-bench), runtime intrusion detection, drift prevention, network
policy enforcement, and a web console — deployed as a set of Kubernetes microservices plus a
host-level daemon agent. Code comments/commit messages are frequently in Chinese; match the
existing language when editing a file that is already Chinese.

**Note the import path mismatch**: the module path is `gitlab.com/piccolo_su/vegeta`, not the
directory name `tensornavigator`. `goimports` is configured with local-prefix
`gitlab.com/piccolo_su/vegeta` (see `.golangci.yml`).

## Setup

```bash
git submodule init && git submodule update   # required before anything else
```

Private module hosts are `gitlab.com` and `scm.tensorsecurity.cn` (`GOPRIVATE`); you need SSH
`insteadOf` rewrites for both configured in `.gitconfig` to fetch dependencies (see the
`before_script` in `.gitlab-ci.yml` for the exact rewrite rules used in CI).

## Repository layout

- `cmd/<service>/` — one directory per deployable binary (console, scanner, daemon, clustermanager,
  holmes, kafkaproxy, webhook, node-image, portal, monitor, data, apiscan-job,
  kube-scanner-report, platform-report, migrate, ...). Most follow
  `cmd/<service>/api|service|store|component` (HTTP handlers → business logic → data layer).
- `pkg/` — shared libraries used across binaries: `dal` (data-access layer, Mongo/Postgres),
  `model` (persisted structs), `middleware`, `k8s` (cluster/host info, kubeconfig handling),
  `holmes` (runtime rule engine helpers), `driftprevention`, `fanotify`, `kubemonitor`,
  `logging`, `token`, `response`/`request`, `apperror`.
- `build/<service>/Dockerfile` — one Dockerfile per service, referenced by the matching
  `Makefile` target.
- `configs/<service>/` — per-service runtime config/assets copied into images at build time.
- `test/` — integration-style tests and standalone test helpers outside `pkg`/`cmd`.
- `doc/` — `BuildTestDeploy.md`, `DeployDevEnv.md`, `HowToCreateAService.md`, `Harbor.md`,
  `UseTest.md` (manual API testing via curl), `Troubleshooting.md`.

## Build

Build a specific service via its Makefile target (each target builds the Go binary and then a
Docker image tagged `$(REPOPREFIX)/<service>:$(IMAGE_TAG)`), e.g.:

```bash
make console
make scanner
make daemon      # see "daemon / net-policy" below — has extra native build steps
make cluster-manager
```

Run `make all` to build everything (see the `all` target's prerequisite list in the `Makefile`
for the full set of buildable components). Useful overrides: `REPOPREFIX` (destination image
repo, default `localhost:32000`), `IMAGE_TAG`, `MIRROR_SOURCE` (set to a China mirror when
building there).

Most services build with `CGO_ENABLED=0` and tag `jsoniter`; `daemon`, `node-image`, `portal`,
and `scan_report` build with `CGO_ENABLED=1` because they link native code.

### daemon / net-policy (C++)

`cmd/daemon` is a CGO Go binary plus a standalone C++17 subproject at
`cmd/daemon/net-policy` (an Envoy-style filter chain: `net/` connection/filter plumbing,
`http/` HTTP1+HTTP2 codecs and inspector, `waf/` rule engine, `policy/engine.*`, plus vendored
`libmnl`/`libnfnetlink`/`libnetfilter_conntrack`/`libnetfilter_queue`). It is built independently
with CMake, not `go build`:

```bash
cmake cmd/daemon/net-policy -B heavy_agent
cmake --build heavy_agent
```

(this is what the `heavy-agent` Makefile target and CI do). It requires `fmt`, `glog>=0.6.0`,
`llhttp`, and `GTest` to be installed. `cmd/daemon/net-policy/.clang-format` is authoritative for
formatting in that subtree — run `clang-format` rather than hand-matching style, and prefer
`ctest` (via the CMake build dir) for its GTest-based tests in `net-policy/tests/`.

`make daemon` additionally compiles `bin/ns-mnt` directly with `gcc` from
`cmd/daemon/setns/*.c` (not part of the CMake project).

## Lint

```bash
golangci-lint run ./...
```

Config is in `.golangci.yml` (25m timeout, several `skip-dirs`, `_test.go` files skipped by the
linter itself). Notable enabled linters: `errcheck`, `goimports` (local prefix
`gitlab.com/piccolo_su/vegeta`), `golint`, `staticcheck`, `bodyclose`, `goconst`, `cyclop`
(max-complexity 20), `dupl`, `gocritic`, `gosec`, `lll` (150 cols). `.reviewdog.yml` runs
`golangci-lint` scoped to `cmd/...` in CI review comments.

## Test

Standard unit tests: `go test ./...` (or scope to a package, e.g.
`go test ./pkg/k8s/...`, or a single test with `-run TestName`).

Some tests are gated behind a Go build tag and require external services (Mongo/etc. — see
`doc/UseTest.md` for connection strings used in manual testing):

```go
//go:build ci
// +build ci
```

Run these explicitly with `go test -tags=ci ./...` (e.g. `cmd/scanner/service/api_test.go`).

For `net-policy` C++ tests, build via CMake (above) then run `ctest` from the build directory.

## Architecture notes

- **console** (`cmd/console`) is the central API server: `api/` (gin HTTP handlers, one file per
  domain — assets, attck, drift, iac, imagesec, memshell, etc.) calls into `service/<domain>/`
  (business logic) which calls `pkg/dal` (data access) operating on `pkg/model` structs. Swagger
  docs are generated with `swag init` (`//go:generate swag init` in `main.go`); the binary embeds
  a version string via `-ldflags -X .../cmd.Version=$(VERSION)` and license tier via the
  `LICENSE_SECRET` build tag (`sit`/`release`). The `console` Makefile target also builds the
  `holmes-rules-pack` binary and runs `build_holmes_rules_thr.sh` to produce the runtime rule
  bundle console ships.
- **scanner** performs image/host vulnerability and compliance scanning; **holmes**
  (`cmd/holmes/starter`) is the runtime detection engine consuming rule packs produced above.
- **daemon** is the per-node host agent (fanotify, drift prevention, network policy enforcement
  via the embedded `net-policy` C++ engine, container inspection under `cmd/daemon/{cis,dp,rscan,
  memshell,net-policy}`).
- **clustermanager** / **kafkaproxy** / **webhook** / **monitor** handle multi-cluster
  registration, event streaming, K8s admission webhooks, and health/heartbeat reporting
  respectively.
- Services follow a singleton-service convention for internal packages: an `Init(deps...) error`
  guarded by `sync.Once` plus a `Get() (*T, bool)` accessor, called once at process startup (see
  `doc/HowToCreateAService.md`).
- CI (`.gitlab-ci.yml`) builds each service as an independent job gated by `changes:` rules on
  that service's `cmd/`, `build/`, and `configs/` paths, so a change to one service does not
  trigger rebuilding unrelated images.
