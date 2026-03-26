FROM golang:1.25.1 AS builder

WORKDIR /app

COPY go.mod ./
COPY go.sum ./

RUN go mod download

COPY main.go ./

RUN CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -o vulnerable-app main.go

FROM debian:12

WORKDIR /app

COPY --from=builder /app/vulnerable-app .

RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*

EXPOSE 8080

USER root

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8080/ || exit 1

CMD ["./vulnerable-app"]
