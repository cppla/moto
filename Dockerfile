# syntax=docker/dockerfile:1@sha256:ecfaec9ed6d810b56388c508f4121597bfbba70d41a6dfeee4d8cad5f295fc32

FROM golang:1.25.13-alpine@sha256:1e0126852075c9c60731c8ba49088448b91f63e2aed97ca9d1a9791622a05946 AS build

WORKDIR /src
RUN apk add --no-cache ca-certificates
COPY go.mod go.sum ./
RUN go mod download
COPY . .

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
