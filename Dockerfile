# syntax=docker/dockerfile:1

FROM --platform=$BUILDPLATFORM golang:1.26.11-bookworm@sha256:dc40a13b61304647ed7e5d581d246b86413dfc29d63c6d018310feb93cd98fc0 AS build

ARG TARGETARCH
ARG TARGETVARIANT

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . ./
RUN CGO_ENABLED=0 GOOS=linux GOARCH="$TARGETARCH" GOARM="${TARGETVARIANT#v}" \
    go build -trimpath -ldflags="-s -w" -o /out/airlock-host ./cmd/airlock-host \
    && cp /etc/passwd /out/passwd \
    && cp /etc/group /out/group \
    && printf 'airlock-host:x:65532:65532::/var/lib/airlock-host:/usr/sbin/nologin\n' >> /out/passwd \
    && printf 'airlock-host:x:65532:\n' >> /out/group \
    && install --directory --mode 0700 /out/state

FROM debian:bookworm-slim@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251

ARG VERSION
ARG REVISION

LABEL org.opencontainers.image.title="Airlock Connector Host" \
      org.opencontainers.image.description="Runtime for Airlock connectors" \
      org.opencontainers.image.source="https://github.com/airlockrun/connectorhost" \
      org.opencontainers.image.version="$VERSION" \
      org.opencontainers.image.revision="$REVISION" \
      org.opencontainers.image.licenses="Apache-2.0"

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/passwd /etc/passwd
COPY --from=build /out/group /etc/group
COPY --from=build --chown=65532:65532 /out/state/ /var/lib/airlock-host/
COPY --from=build /out/airlock-host /usr/local/bin/airlock-host
COPY THIRD_PARTY_NOTICES.md /usr/share/doc/airlock-host/THIRD_PARTY_NOTICES.md

ENV HOME=/var/lib/airlock-host
USER 65532:65532
VOLUME ["/var/lib/airlock-host"]
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/bin/airlock-host", "--state-dir", "/var/lib/airlock-host"]
CMD ["serve"]
