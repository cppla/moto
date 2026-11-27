# syntax=docker/dockerfile:1@sha256:ecfaec9ed6d810b56388c508f4121597bfbba70d41a6dfeee4d8cad5f295fc32

FROM golang:1.27.4-alpine@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280 AS build

WORKDIR /src
RUN apk add --no-cache ca-certificates
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
COPY config ./config
COPY controller ./controller
COPY internal ./internal
COPY utils ./utils
COPY LICENSE THIRD_PARTY_NOTICES ./

ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown
RUN CGO_ENABLED=0 go build -trimpath -buildvcs=false \
    -ldflags="-s -w -buildid= -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.buildDate=${BUILD_DATE}" \
    -o /out/moto . && \
    mkdir -p /out/work

FROM scratch

COPY --from=build /out/moto /moto
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /src/LICENSE /licenses/moto/LICENSE
COPY --from=build /src/THIRD_PARTY_NOTICES /licenses/moto/THIRD_PARTY_NOTICES
COPY --from=build --chown=65532:65532 /out/work /work

USER 65532:65532
WORKDIR /work
STOPSIGNAL SIGTERM
ENTRYPOINT ["/moto"]
CMD ["--config", "/etc/moto/setting.json"]
