# Build stage
FROM golang:1.22-alpine AS builder

WORKDIR /app
RUN apk add --no-cache git ca-certificates

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /bastion ./cmd/bastion

# Final stage – minimal non-root image
FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata \
    && adduser -D -u 1000 bastion

WORKDIR /app
COPY --from=builder /bastion .
COPY configs/config.yaml ./configs/config.yaml

USER bastion
EXPOSE 8080

ENTRYPOINT ["./bastion"]
CMD ["configs/config.yaml"]
