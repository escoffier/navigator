# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

This file scopes to `cmd/daemon` — the per-node host agent binary. See the repo-root
`CLAUDE.md` for module path, submodule setup, and repo-wide build/lint/test conventions; this
file only covers what's specific to the daemon.

## Build

```bash
# from repo root
CGO_ENABLED=1 go build -o bin/daemon cmd/daemon/main.go
gcc -o bin/ns-mnt cmd/daemon/setns/cjson.c cmd/daemon/setns/setmnt.c cmd/daemon/setns/net_info.c \
    cmd/daemon/setns/netebpf_user.c cmd/daemon/setns/bpf.c cmd/daemon/setns/bpf_load.c -lelf -lpthread
```

(equivalent to `make daemon` at repo root, which also builds the `drift-prevention-client`
prerequisite and the Docker image). The `net-policy` C++ subproject (the "heavy-agent") is a
separate CMake build — see the root `CLAUDE.md`'s "daemon / net-policy" section; it is not part
of this `go build`.

## Test

`go test ./...` from this directory covers the Go packages. Test coverage is concentrated in
`memshell/`, `pkg/nodeinfo`, `pkg/microseg`, `pkg/waf`, `pkg/containerassets`, and `cis/pkg/*`
(the CIS benchmark checker internals). `setns/setmnt_test.c` is a standalone C test, not run by
`go test`.

## Architecture

`main.go` is a single long-running process (`Run()` in `main.go`) that wires up independent
subsystems, each gated by its own environment variable and run as a goroutine:

| Env var | Package | Purpose |
|---|---|---|
| `MICROSEG_ENABLED` | `pkg/microseg`, `pkg/waf` | Micro-segmentation network policy + WAF, driven by CRDs (`externalversions` informers) and pushed to the local heavy-agent |
| `CIA_ENABLED` | `dp` | Drift prevention / container image assurance (`dp.NewDriftAssurance`) |
| `RSCAN_ENABLED` | `rscan` | Runtime filesystem/malware scanning |
| `CIS_ENABLED` | `cis` | CIS benchmark checks (nginx/postgres/redis/ssh checkers, `cis/pkg` mirrors kube-bench's internal check/exec/outputter structure) |
| `MEMSHELL_ENABLED` | `memshell` | In-memory webshell detection (rule-driven, see `memshell/ruleReader.go`) |
| `BL_ENABLED` | `learn` | Runtime behavior learning |

Always-on plumbing set up before those toggles: k8s clientset/informers (`pkg/k8s`), a Redis
client + `netflow.NewFlowSession` for connection/flow tracking, an MQ writer
(`gitlab.com/security-rd/go-pkg/mq`), and (if `RTDETECT_UDS_ADDR` is set) a Unix-socket event
stream into `pkg/holmes` feeding the `mozart` rule engine.

### heavy-agent bridge (Go ⇄ C++ net-policy)

`pkg/heavy-agent/client.go` implements a length-prefixed TCP client (`net.Dial("tcp", ...)`,
`eventHeaderLen`-byte header + JSON payload) used to talk to the native `net-policy` process
(built via CMake, see root `CLAUDE.md`). Two independent connections are opened in `main.go`:

- `127.0.0.1:9999` — policy/control channel (`microseg.NewPolicyClient`, `waf.NewWafClient`)
- `127.0.0.1:8888` — event channel (`heavyagent.NewEventProcessor`, handlers registered per
  domain: `"microseg"`, `"waf"`)

`status/server.go` runs an HTTP status endpoint (port 12000) that also holds a reference to the
heavy-agent client, for health/debug purposes.

### Other subsystems

- `setns/` — standalone C/eBPF code (`netebpf_kern.c`/`netebpf_user.c`, `bpf_load.c`) compiled
  directly with `gcc` into the separate `ns-mnt` binary (not linked into the `daemon` Go binary);
  used for namespace/network introspection.
- `compliance/` — host/kube/cri compliance check implementations (distinct from `cis/`, which is
  the CIS-benchmark-style checker framework).
- `pkg/nodeinfo` — container runtime abstraction (Docker/CRI-O/Podman/containerd), pod watchers,
  and pod-resource info shared by most of the above subsystems.
- `pkg/degrade` — reads a ConfigMap (`ivan-degradation-controller`) to toggle feature
  degradation at runtime.
- `global/` — small shared constants/utilities used across daemon subpackages.
