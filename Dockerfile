FROM golang:1.23-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
COPY web ./web
# CI passes the git tag here (--build-arg VERSION=v0.1.0); it ends up in
# main.version and is logged on startup.
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -mod=readonly -trimpath \
      -ldflags="-s -w -X main.version=${VERSION}" -o /perch .

# debian-slim (glibc) so the WSL-injected nvidia-smi binary can execute;
# alpine/musl cannot run it
FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /perch /usr/local/bin/perch
# /app is the working directory an optional .env bind-mount lands in
WORKDIR /app
EXPOSE 3535
ENTRYPOINT ["perch"]
