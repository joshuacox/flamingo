# Build stage
FROM golang:1.24-alpine AS builder

WORKDIR /build

# Install git and ca-certificates for dependencies
RUN apk add --no-cache git ca-certificates tzdata

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Build statically linked binary
ARG VERSION="0.0.0"
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w -X 'github.com/atredispartners/flamingo/cmd.Version=${VERSION}'" \
    -o /flamingo main.go

# Runtime stage
FROM alpine:3.21

RUN apk add --no-cache ca-certificates tzdata \
    && adduser -D -u 65532 -g 65532 flamingo \
    && mkdir -p /var/log/flamingo \
    && chown -R flamingo:flamingo /var/log/flamingo

COPY --from=builder /flamingo /bin/flamingo

USER flamingo:flamingo
WORKDIR /home/flamingo

ENTRYPOINT ["/bin/flamingo"]
