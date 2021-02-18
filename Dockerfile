FROM golang:latest
RUN mkdir /app
COPY . /app/
WORKDIR /app
RUN CGO_ENABLED=0 go build -ldflags="-X 'main.build=$(date -Iminutes)'" -o server -a cmd/server.go

FROM gcr.io/distroless/static:nonroot
COPY --from=0 /app/server /
ENTRYPOINT ["/server"]