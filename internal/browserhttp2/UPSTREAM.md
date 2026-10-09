# Pinned HTTP/2 source

The generated Go files in this package and `internal/browserhttpcommon` and
`internal/browserhttpsfv` come from `golang.org/x/net v0.60.0`.
The upstream BSD license is retained in `LICENSE`; every upstream source keeps
its original copyright notice. HPACK remains the upstream module dependency.

Source archive: https://proxy.golang.org/golang.org/x/net/@v/v0.60.0.zip

SHA-256: `052e0453db47a96ae9567503e7c95ea925ab52682cb1cec31250541f7160107e`

Run `python3 internal/browserhttp2/update_upstream.py --check` to reproduce and
verify the complete source import in memory. Pass `--zip <module-cache.zip>` for
offline verification. Omitting `--check` regenerates only the listed upstream
files, preserving Moto's independent profile and tests.

The importer removes the Go 1.27 standard-library wrapper branch and selects
the same upstream HTTP/2 engine on supported Go versions. The standard-library
wrapper does not expose the frame/HPACK customization required here. It retains
all upstream production sources, including server support used by tests, and
all Go-version compatibility files; it does not revive an old transport fork.

The importer adds narrow client hooks: an opt-in `ChromeProfile` flag,
matching receive-window/decoder configuration, an ordered SETTINGS block, and
validated header ordering before HPACK encoding. Raw decoded response fields
are checked against the caller's smaller application limit before net/http
normalizes them; rejection affects only that stream. `chrome_profile.go` owns the
profile. No encrypted or framed network writes are rewritten. Advertised
features stay implemented: push remains disabled, the default 16 KiB maximum
frame size is unchanged, and extended CONNECT is not newly advertised.

The Chrome profile advertises a 256 KiB maximum header list. Moto separately
retains its smaller CONNECT response acceptance limit; that application policy
must not be implemented by lying about the decoder's advertised capacity.

Maintenance: review upstream HTTP/2 and helper security fixes on every Go/x/net
update, update the archive pin, inspect importer hooks, and rerun source
verification plus frame, flow-control, pool, PING, cancellation and race tests.

Staticcheck still checks every package and all Moto profile code. The importer
adds single-declaration/statement `lint:ignore` annotations to a fixed list of
unchanged upstream lines: unused upstream compatibility helpers/constants,
deprecated compatibility fields/interfaces, an upstream redundant range guard,
and equivalent timing expressions. Keeping those lines intact reduces upstream
security-update drift. Each annotation has an exact source anchor and is
verified by `--check`; there is no file-wide or package-wide suppression.
