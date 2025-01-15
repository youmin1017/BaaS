FROM golang:1.23.4-alpine AS base

FROM base AS builder

WORKDIR /app

COPY go.mod go.sum ./

RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -o /app/auth

FROM base AS production

WORKDIR /app

COPY --from=builder /app/auth /app/auth

EXPOSE 8888
CMD ["/app/auth"]
