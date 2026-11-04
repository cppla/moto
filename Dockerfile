# syntax=docker/dockerfile:1@sha256:ecfaec9ed6d810b56388c508f4121597bfbba70d41a6dfeee4d8cad5f295fc32

FROM golang:1.27.3-alpine@sha256:d200d2dd76b03a99b52651fd1325aff7dcd35422c35c01bac56571b0507f3deb AS build

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
