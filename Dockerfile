ARG SCANNER_VERSION=1.1.3
ARG BASE=alpine:3.15

#### scanner-builder
FROM golang:1.18.0-alpine3.15 as builder

RUN apk --no-cache add git

ENV CGO_ENABLED=0

WORKDIR /go/src/
ADD go.mod go.sum /go/src/
RUN go mod download

ADD main.go /go/src/
RUN go build -o /scan -ldflags="-s -w" .

#### scanner-binary
FROM ${BASE} as binary-amd64
ARG SCANNER_VERSION
ADD https://github.com/projectdiscovery/dnsx/releases/download/v${SCANNER_VERSION}/dnsx_${SCANNER_VERSION}_linux_amd64.zip /scanner.zip

FROM ${BASE} as binary-armv7
ARG SCANNER_VERSION
ADD https://github.com/projectdiscovery/dnsx/releases/download/v${SCANNER_VERSION}/dnsx_${SCANNER_VERSION}_linux_armv6.zip /scanner.zip

FROM ${BASE} as binary-arm64
ARG SCANNER_VERSION
ADD https://github.com/projectdiscovery/dnsx/releases/download/v${SCANNER_VERSION}/dnsx_${SCANNER_VERSION}_linux_arm64.zip /scanner.zip

FROM binary-${TARGETARCH}${TARGETVARIANT} as binary
RUN unzip /scanner.zip

#### final

FROM ${BASE}
RUN apk add --no-cache ca-certificates

COPY --from=builder /scan /usr/local/bin/scan
COPY --from=binary /dnsx /usr/local/bin/dnsx

ENTRYPOINT ["/usr/local/bin/scan"]
