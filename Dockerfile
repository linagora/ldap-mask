# syntax=docker/dockerfile:1

# See DESIGN.md §7 for why the Go version is pinned exactly.
FROM golang:1.26.8 AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ENV CGO_ENABLED=0
RUN go build -trimpath -ldflags="-s -w" -o /ldap-mask .

# Runtime stage: see DESIGN.md §7 for the choice of base image.
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /ldap-mask /ldap-mask

USER nonroot

EXPOSE 1636

ENTRYPOINT ["/ldap-mask"]
CMD ["--config", "/etc/ldap-mask/config.yaml"]
