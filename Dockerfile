FROM golang:latest
RUN mkdir /app
COPY . /app/
WORKDIR /app
RUN CGO_ENABLED=0 go build -ldflags="-X 'main.build=$(date -Iminutes)'" -o server -a cmd/server.go

FROM gcr.io/distroless/static:nonroot
# COPY --from=0 /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
# COPY --from=0 /etc/passwd /etc/passwd
COPY --from=0 /app/server /
# USER nobody
ENTRYPOINT ["/server"]