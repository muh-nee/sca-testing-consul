# reachability-fixture

This directory is an isolated Go module (its own `go.mod`, separate from consul's) added to
this repo purely as an SCA test fixture for `datadog-sbom-generator`'s Go reachable-symbols
detector (`pkg/reachability/codefile/golang.go`). It pins two intentionally old, vulnerable
dependency versions and calls some of their advisory-flagged symbols but not others, to give a
mix of reachable, unreachable, and structurally-unmatchable results using only real advisories
(no fictitious CVEs). Advisory/symbol data below was queried directly from `api.osv.dev`.

The detector only matches plain package-level function calls (`pkg.Func(...)`) against exact
import-path + exact function-name pairs; it cannot match dot-qualified method symbols
(`Type.Method`) or unexported symbols.

| Dependency (pinned) | Advisory | Flagged symbols | Called in `main.go`? | Expected verdict |
|---|---|---|---|---|
| `github.com/gin-gonic/gin@v1.5.0` | [GO-2020-0001](https://osv.dev/vulnerability/GO-2020-0001) (fixed 1.6.0) | `Default`, `Logger`, `LoggerWithConfig`, `LoggerWithFormatter`, `LoggerWithWriter` (all plain functions) | Yes — `gin.Default()` | **Reachable** |
| `github.com/miekg/dns@v1.0.3` | [GO-2020-0006](https://osv.dev/vulnerability/GO-2020-0006) (fixed 1.0.4-pre) | `ActivateAndServe`, `ListenAndServe`, `ListenAndServeTLS` (plain) + `Server.ActivateAndServe` etc. (method, unmatchable) | Yes — `dns.ListenAndServe(...)` | **Reachable** |
| `github.com/miekg/dns@v1.0.3` | [GO-2020-0028](https://osv.dev/vulnerability/GO-2020-0028) (fixed 1.0.10) | `NewRR`, `ParseZone`, `ReadRR`, `setTA` (plain) | No — the module only calls `dns.Fqdn(...)`, `dns.NewServeMux()`, `dns.ListenAndServe(...)`, none of which are flagged here | **Unreachable** (dependency present and vulnerable, symbol simply never called) |
| `github.com/miekg/dns@v1.0.3` | [GO-2020-0008](https://osv.dev/vulnerability/GO-2020-0008) (fixed 1.1.25-pre) | `Msg.SetAxfr` etc. (method) + `id` (unexported) | No | **Structurally unreachable** (method/unexported symbols can never match `pkg.Func()` call-site detection) |

## Verifying locally

```bash
cd reachability-fixture
go build ./...
go vet ./...
```

Then run the `datadog-sbom-generator` Go reachability detector against this directory and
confirm the reachable/unreachable verdicts above.
