# Managed dependencies and upstream advisory review

`security/dependency-baselines.json` records the source lineage separately from
the replacement actually compiled into Moto. It is the single security policy
for these three managed dependencies:

| Moto dependency | Compiled source | Original advisory query |
| --- | --- | --- |
| `github.com/refraction-networking/utls` | Exact `github.com/cppla/utls` replacement | Original uTLS require version |
| `github.com/apernet/quic-go` | Exact `github.com/cppla/quic-go` replacement | Official `github.com/quic-go/quic-go v0.63.0` source baseline |
| `golang.org/x/net` | Module plus the pinned HTTP/2 and helper copies under `internal/` | Pinned `golang.org/x/net` source version |

The QUIC baseline is the official source lineage of apernet commit
`a10df75c260cee8161f3261d63a37bd125a6bb2a`, not a fork pseudo-version. The copied
HTTP/2 packages are also invisible under their original package identities to a
normal module-path-based scan. Review relevant Go TLS security fixes as well:
upgrading the Go toolchain does not update the `crypto/tls` code copied into
uTLS. The current uTLS fork includes the Go 1.27.2 TLS security backport; each
future Go TLS fix still needs a separate applicability and backport review.
Querying these modules does not audit the fork patches or prove absence of bugs.

## Checks and evidence

- `make dependency-boundary-check` is offline. Go's own module parser verifies
  the original requires and exact global remote replacements; the check rejects
  local/scoped replacements and duplicate managed module identities. It also
  compares the copied x/net version and archive hash to the importer's constants.
  The regression fixtures use no dependency downloads. Existing `make mod-check`
  continues to verify sums, the module graph and the complete copied-source import.
- `make vuln` retains the ordinary reachable-source `govulncheck ./...` scan.
- `make upstream-vuln` installs the scanner version from the policy and separately
  queries the three original module/version baselines against `https://vuln.go.dev`.
  This requires network access. Query exit status zero alone does not mean no
  advisories: the JSON stream is validated and every returned OSV is a candidate
  requiring review. Empty, malformed, wrong-mode or failed queries fail the gate.
- Every query run creates a fresh directory under `bin/security-advisories/` with
  the policy snapshot, go.mod hash, unchanged raw JSON, stderr, scanner/database
  metadata, raw hashes and summary. CI retains that directory even on failure.
  `make check` and therefore `make ci` and the release verification include both
  the offline boundary and the online upstream check.

An upstream candidate is not a confirmed reachable vulnerability in Moto's fork.
The gate intentionally stops for review and has no blanket ignore list. For each
candidate, retain its ID and original JSON and record the affected package/symbol,
whether the copied/forked code includes it, the upstream fix, the exact backport
commit (if any), and a regression or source comparison supporting the conclusion.
Do not change the recorded source baseline to a newer unaffected version unless
the actual source was updated. A reviewed future exception would need explicit
per-advisory evidence tied to the exact dependency pin; do not silently suppress
candidates or rewrite a report as zero vulnerabilities.

## Updating a dependency

1. Review the actual upstream history and fork patch queue. Publish the exact
   fork commit before selecting its canonical Go pseudo-version. Keep original
   import paths and use one global remote replacement for each managed fork.
2. Update go.mod/go.sum and the policy together. For QUIC, separately confirm
   the official upstream lineage instead of copying the fork's version. For
   copied H2, update the importer version/hash and reproduce the source import.
3. Update `THIRD_PARTY_NOTICES` from the selected source and retain source-file
   copyright notices. Review compatibility and security patches independently.
4. Run the offline boundary, complete module/source verification, relevant
   transport and race regressions, reachable scan and upstream queries. Retain
   exact-version evidence, and review each candidate before release. A clean
   query is only a result for the recorded database snapshot and versions.

This is a targeted dependency guard, not a general provenance or license scanner.
Unrelated modules are not prohibited; normal module, test and review gates still
apply to them. No private configuration, running Moto process or remote service
configuration is read or changed by the dependency checks.
