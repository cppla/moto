GO ?= go
PYTHON ?= python3
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT ?= $(shell git rev-parse HEAD 2>/dev/null || echo unknown)
BUILD_DATE ?= $(shell git show -s --format=%cI HEAD 2>/dev/null || echo unknown)
STATICCHECK_VERSION ?= v0.7.0
GOVULNCHECK_VERSION ?= v1.7.0
ACTIONLINT_VERSION ?= v1.7.7
CROSS_BUILD_DIR ?= bin/cross
LDFLAGS := -s -w -buildid= -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.buildDate=$(BUILD_DATE)

.PHONY: build check ci fmt-check workflow-check mod-check test race fault-test vet staticcheck vuln config-check bench-check bench-smoke cross-build

build:
	mkdir -p bin
	CGO_ENABLED=0 $(GO) build -trimpath -buildvcs=false -ldflags "$(LDFLAGS)" -o bin/moto .

fmt-check:
	test -z "$$(gofmt -l .)"

workflow-check:
	$(GO) run github.com/rhysd/actionlint/cmd/actionlint@$(ACTIONLINT_VERSION) .github/workflows/*.yml

mod-check:
	$(GO) mod verify
	$(GO) mod tidy -diff

test:
	$(GO) test ./...

race:
	$(GO) test -race ./...

fault-test:
	$(GO) test -race ./controller -shuffle=on -count=10 -run 'Test(ConcurrentReload|ReloadRules|RouteHealth|RaceBoostTargets|CachedBoost|FreshBoost|BoostProtocolCanary|DialBulkhead|Prewarm|ActiveHealth|HTTP3|.*ProtocolPenalty|SelectTargetsExcluding|.*TLS|.*ProxyProtocol|ServerClose)'

vet:
	$(GO) vet ./...

staticcheck:
	$(GO) run honnef.co/go/tools/cmd/staticcheck@$(STATICCHECK_VERSION) ./...

vuln:
	$(GO) run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...

config-check:
	$(GO) run . --config config/setting.json --check-config

bench-check:
	$(PYTHON) -c 'import py_compile, tempfile; cache = tempfile.TemporaryDirectory(); py_compile.compile("test/bench.py", cfile=cache.name + "/bench.pyc", doraise=True); py_compile.compile("test/bulk_relay_bench.py", cfile=cache.name + "/bulk_relay_bench.pyc", doraise=True); py_compile.compile("test/moto-route-watch.py", cfile=cache.name + "/moto-route-watch.pyc", doraise=True)'
	$(PYTHON) test/moto_route_watch_test.py

bench-smoke:
	$(PYTHON) test/bench.py --self-contained --mode normal -c 4 -t 12 --warmup 4 --timeout 2 --min-success-rate 100 --min-warm-throughput-ratio 0.02 --max-warm-p95-ms 500
	$(PYTHON) test/bench.py --self-contained --mode regex -c 4 -t 12 --warmup 4 --timeout 2 --min-success-rate 100 --min-warm-throughput-ratio 0.02 --max-warm-p95-ms 500
	$(PYTHON) test/bench.py --self-contained --mode boost -c 4 -t 12 --warmup 4 --timeout 2 --min-success-rate 100 --min-warm-throughput-ratio 0.02 --max-warm-p95-ms 500
	$(PYTHON) test/bench.py --self-contained --mode roundrobin -c 4 -t 12 --warmup 4 --timeout 2 --min-success-rate 100 --min-warm-throughput-ratio 0.02 --max-warm-p95-ms 500
	$(PYTHON) test/bulk_relay_bench.py --direction both --concurrency 1 --connections 1 --bytes-per-direction 1MiB --warmup-bytes 64KiB --timeout 30 --min-success-rate 100

cross-build:
	mkdir -p $(CROSS_BUILD_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -trimpath -buildvcs=false -o $(CROSS_BUILD_DIR)/moto-linux-amd64 .
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -trimpath -buildvcs=false -o $(CROSS_BUILD_DIR)/moto-linux-arm64 .
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 $(GO) build -trimpath -buildvcs=false -o $(CROSS_BUILD_DIR)/moto-darwin-arm64 .
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 $(GO) build -trimpath -buildvcs=false -o $(CROSS_BUILD_DIR)/moto-windows-amd64.exe .

check: fmt-check workflow-check mod-check test race fault-test vet staticcheck vuln config-check bench-check bench-smoke

ci: check cross-build
