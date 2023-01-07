FROM golang:1.19.4-alpine

RUN apk add llvm clang linux-headers libbpf-dev tcpdump bpftool

ADD . /app

WORKDIR /app

RUN go mod download
RUN go generate
RUN go build
RUN mv zebra-bpf-dplane-example /usr/bin/zebra-bpf-dplane-example
