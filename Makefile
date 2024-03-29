# CLANG ?= clang
# CFLAGS := -O2 -g -Wall

# build: generate
# 	cd cmd/xdp && \
# 	go build -o ../../bin/xdp .

# generate: export BPF_CLANG := $(CLANG)
# generate: export BPF_CFLAGS := $(CFLAGS)
# generate:
# 	go generate ./...


# build: generate
# 	cd cmd/trace && \
# 	go build -o ../../bin/trace .

# generate: export BPF_CLANG := $(CLANG)
# generate: export BPF_CFLAGS := $(CFLAGS)
# generate:
# 	go generate ./...

# build: generate
# 	cd cmd/tracepoint && \
# 	go build -o ../../bin/tracepoint .

# generate: export BPF_CLANG := $(CLANG)
# generate: export BPF_CFLAGS := $(CFLAGS)
# generate:
# 	go generate ./...



# build: generate
# 	cd cmd/sockops && \
# 	go build -o ../../bin/sockops .

# generate: export BPF_CLANG := $(CLANG)
# generate: export BPF_CFLAGS := $(CFLAGS)
# generate:
# 	go generate ./...


build: generate
	cd cmd/tc && \
	go build -o ../../bin/tc .

generate: export BPF_CLANG := $(CLANG)
generate: export BPF_CFLAGS := $(CFLAGS)
generate:
	go generate ./...