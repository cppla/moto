#!/usr/bin/env python3
"""Reproduce the pinned x/net HTTP/2 source import and its narrow Moto hooks.

Run with --check to verify without writing. --zip may name an existing module
cache ZIP so verification does not require network access.
"""

import argparse
import hashlib
import io
from pathlib import Path
import subprocess
import urllib.request
import zipfile

VERSION = "v0.60.0"
ZIP_SHA256 = "052e0453db47a96ae9567503e7c95ea925ab52682cb1cec31250541f7160107e"
PREFIX = f"golang.org/x/net@{VERSION}/"
ROOT = Path(__file__).resolve().parents[2]
PACKAGES = {
    "http2/": "internal/browserhttp2/",
    "internal/httpcommon/": "internal/browserhttpcommon/",
    "internal/httpsfv/": "internal/browserhttpsfv/",
}
EXCLUDED = {"server_wrap.go", "transport_wrap.go"}

# These diagnostics concern individual unchanged upstream declarations or
# compatibility expressions. Never apply file/package-wide lint exclusions:
# Moto's profile code and every other line remain checked normally.
UPSTREAM_LINT = {
    "http2/ascii.go": [
        ("func isASCIIPrint(", "U1000"),
        ("func asciiToLower(", "U1000"),
    ],
    "http2/ciphers.go": [
        ("cipher_TLS_FALLBACK_SCSV ", "U1000"),
        ("cipher_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 ", "U1000"),
        ("cipher_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 ", "U1000"),
        ("cipher_TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 ", "U1000"),
        ("cipher_TLS_PSK_WITH_CHACHA20_POLY1305_SHA256 ", "U1000"),
        ("cipher_TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256 ", "U1000"),
        ("cipher_TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256 ", "U1000"),
        ("cipher_TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256 ", "U1000"),
    ],
    "http2/frame.go": [
        ("maxWriteSize uint32", "U1000"),
        ("type streamEnder interface", "U1000"),
    ],
    "http2/http2.go": [("if v < 0 || v > 2147483647 {", "SA4003")],
    "http2/server.go": [
        ("s.TLSConfig.PreferServerCipherSuites = true", "SA1019"),
        ("_ http.CloseNotifier =", "SA1019"),
        ("st.readDeadline = time.AfterFunc(deadline.Sub(time.Now())", "S1024"),
        ("st.readDeadline.Reset(deadline.Sub(time.Now()))", "S1024"),
        ("st.writeDeadline = time.AfterFunc(deadline.Sub(time.Now())", "S1024"),
        ("st.writeDeadline.Reset(deadline.Sub(time.Now()))", "S1024"),
    ],
    "http2/transport.go": [
        ("func (cc *ClientConn) idleState()", "U1000"),
        ("func (cc *ClientConn) isDoNotReuseAndIdle()", "U1000"),
        ("reqCancel:            req.Cancel,", "SA1019"),
        ("errStopReqBodyWriteAndCancel =", "U1000"),
        ("type resAndError struct", "U1000"),
        ("idleTime := time.Now().Sub(cc.lastActive)", "S1012"),
    ],
    "http2/transport_common.go": [
        ("if !state.NegotiatedProtocolIsMutual {", "SA1019"),
    ],
}


def annotate_upstream_lint(path, source):
    reasons = {
        "U1000": "Keep pinned upstream helpers/constants for reproducible security updates; see UPSTREAM.md.",
        "SA4003": "Preserve the pinned upstream range guard verbatim; see UPSTREAM.md.",
        "SA1019": "Retain the pinned upstream compatibility path; see UPSTREAM.md.",
        "S1024": "Preserve the pinned upstream timing expression; see UPSTREAM.md.",
        "S1012": "Preserve the pinned upstream timing expression; see UPSTREAM.md.",
    }
    for prefix, code in UPSTREAM_LINT.get(path, []):
        lines = source.splitlines(keepends=True)
        matches = [i for i, line in enumerate(lines) if line.lstrip().startswith(prefix)]
        if len(matches) != 1:
            raise ValueError(f"upstream lint anchor changed: {path}: {prefix!r}")
        index = matches[0]
        indent = lines[index][:len(lines[index]) - len(lines[index].lstrip())]
        lines.insert(index, f"{indent}//lint:ignore {code} {reasons[code]}\n")
        source = "".join(lines)
    return source


def replace_once(source, old, new):
    if source.count(old) != 1:
        raise ValueError(f"upstream hook changed: {old[:90]!r}")
    return source.replace(old, new, 1)


def transform(path, source):
    source = source.replace("//go:build !(go1.27 && !http2legacy)\n\n", "")
    source = source.replace('"golang.org/x/net/internal/httpcommon"',
                            'httpcommon "moto/internal/browserhttpcommon"')
    source = source.replace('"golang.org/x/net/internal/httpsfv"',
                            'httpsfv "moto/internal/browserhttpsfv"')
    if path == "http2/transport_common.go":
        source = replace_once(source, "type Transport struct {\n", "type Transport struct {\n"
            "\t// ChromeProfile enables Moto's explicit HTTP/2 connection profile.\n"
            "\t// It changes advertised receive limits and matching local state together.\n"
            "\tChromeProfile bool\n\n")
    if path == "http2/transport.go":
        source = replace_once(source, "\tconf := configFromTransport(t)\n", "\tconf := configFromTransport(t)\n"
            "\tif t.ChromeProfile {\n\t\tapplyChromeReceiveConfig(&conf)\n\t}\n")
        source = replace_once(source, "\tcc.fr.MaxHeaderListSize = t.maxHeaderListSize()\n",
            "\tcc.fr.MaxHeaderListSize = t.maxHeaderListSize()\n"
            "\tif t.ChromeProfile {\n\t\tcc.fr.MaxHeaderListSize = chromeMaxHeaderListSize\n\t}\n")
        source = replace_once(source, "\tcc.bw.Write(clientPreface)\n", "\tif t.ChromeProfile {\n"
            "\t\tinitialSettings = chromeInitialSettings()\n\t}\n\n\tcc.bw.Write(clientPreface)\n")
        source = replace_once(source,
            "\tres, err := encodeRequestHeaders(req, cs.requestedGzip, cc.peerMaxHeaderListSize, func(name, value string) {\n",
            "\tencode := encodeRequestHeaders\n\tif cc.t.ChromeProfile {\n\t\tencode = encodeChromeRequestHeaders\n\t}\n"
            "\tres, err := encode(req, cs.requestedGzip, cc.peerMaxHeaderListSize, func(name, value string) {\n")
        source = replace_once(source, "\tif !cs.firstByte {\n",
            "\tif cc := rl.cc; cc.t.ChromeProfile && chromeResponseHeadersTooLarge(f, cc.t.maxHeaderListSize()) {\n"
            "\t\trl.endStreamError(cs, StreamError{StreamID: f.StreamID, Code: ErrCodeProtocol, Cause: errChromeResponseHeaderListSize})\n"
            "\t\treturn nil\n\t}\n\tif !cs.firstByte {\n")
    return annotate_upstream_lint(path, source)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--zip", type=Path)
    args = parser.parse_args()
    if args.zip:
        data = args.zip.read_bytes()
    else:
        with urllib.request.urlopen(f"https://proxy.golang.org/golang.org/x/net/@v/{VERSION}.zip", timeout=30) as response:
            data = response.read()
    if hashlib.sha256(data).hexdigest() != ZIP_SHA256:
        raise SystemExit("upstream ZIP SHA-256 mismatch")
    outputs = {}
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        for source_dir, destination in PACKAGES.items():
            for entry in archive.namelist():
                if not entry.startswith(PREFIX + source_dir):
                    continue
                name = entry[len(PREFIX + source_dir):]
                if "/" in name or not name.endswith(".go") or name.endswith("_test.go") or name in EXCLUDED:
                    continue
                transformed = transform(source_dir + name, archive.read(entry).decode()).encode()
                outputs[destination + name] = subprocess.run(
                    ["gofmt"], input=transformed, stdout=subprocess.PIPE, check=True
                ).stdout
        for destination in PACKAGES.values():
            outputs[destination + "LICENSE"] = archive.read(PREFIX + "LICENSE")
    errors = []
    for name, content in outputs.items():
        target = ROOT / name
        if args.check:
            if not target.exists() or target.read_bytes() != content:
                errors.append(name)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
    if errors:
        raise SystemExit("generated source differs: " + ", ".join(errors))
    print(f"{'Verified' if args.check else 'Imported'} {len(outputs)} pinned upstream files ({VERSION})")


if __name__ == "__main__":
    main()
