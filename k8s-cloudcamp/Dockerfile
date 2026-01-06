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

EXPOSE 8080

USER root

CMD ["./vulnerable-app"]
