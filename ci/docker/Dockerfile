FROM golang:1.18 as builder

WORKDIR /workspace

COPY check-certs.go /workspace/check-certs.go

COPY pkg /workspace/pkg

COPY go.mod /workspace/go.mod

COPY go.sum /workspace/go.sum

RUN go build -o check-certs check-certs.go

FROM ubuntu:focal-20220426 as runner

RUN apt-get update && apt-get install -y --no-install-recommends curl && \
    apt-get remove --purge -y && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /workspace/check-certs /app/check-certs

ENTRYPOINT ["/app/check-certs"]
