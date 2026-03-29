FROM golang:1.25-bookworm AS build
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    git \
    tzdata \
    ca-certificates \
    build-essential

WORKDIR /go/src/app
ENV CGO_ENABLED=0 GOOS=linux GOARCH=amd64
COPY . .
ARG VERSION=dev
RUN go build -ldflags "-X main.Version=${VERSION}" -o /go/bin/rediver-semgrep

FROM semgrep/semgrep:1.99 AS final
COPY --from=build /go/bin/rediver-semgrep /usr/bin/rediver-semgrep
ENTRYPOINT ["/usr/bin/rediver-semgrep"]
