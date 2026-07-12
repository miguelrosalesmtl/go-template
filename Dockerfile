# --- Build stage ---
FROM golang:1.26 AS build

WORKDIR /src

# Copy the manifests alone first, so this layer -- and the dependency download --
# is cached and only re-runs when go.mod or go.sum actually change. Copying the
# whole source first would invalidate it on every edit.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# CGO_ENABLED=0 produces a static binary with no libc dependency, which is what
# lets it run on the distroless base below.
# -s -w strips the symbol table and DWARF info: a smaller image, and nothing of
# value lost in production.
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /out/server ./cmd/server

# --- Runtime stage ---
# distroless/static has no shell, no package manager, and no busybox -- there is
# essentially nothing for an attacker who achieves RCE to pivot with.
FROM gcr.io/distroless/static-debian12:nonroot

WORKDIR /app
COPY --from=build /out/server /app/server

# The migrations are compiled into the binary (see migrations/embed.go), so they
# are NOT copied here. `server migrate up` works from the binary alone.

USER nonroot:nonroot
EXPOSE 8080

ENTRYPOINT ["/app/server"]
