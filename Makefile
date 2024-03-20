CLANG ?= clang
CFLAGS := -O2 -g -Wall

build: generate
	cd cmd/xdp && \
	go build -o ../../bin/xdp .

generate: export BPF_CLANG := $(CLANG)
generate: export BPF_CFLAGS := $(CFLAGS)
generate:
	go generate ./...
