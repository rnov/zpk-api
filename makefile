# Variables
PROTO_DIR := ./pkg/api
GRPC_DIR := ./pkg/http/grpc/zkp
PROTO_FILES := $(wildcard $(PROTO_DIR)/*.proto)
PB_GO_FILES := $(patsubst $(PROTO_DIR)/%.proto,$(GRPC_DIR)/%.pb.go,$(PROTO_FILES))
PROVER_BINARY := prover
VERIFIER_BINARY := verifier

# Protoc Compiler
PROTOC := protoc

# Docker Compose
DC := docker-compose

.PHONY: all clean proto build up down build-local up-local down-local

all: build up

all-local: proto build-local up-local

proto: $(PB_GO_FILES)

$(GRPC_DIR)/%.pb.go: $(PROTO_DIR)/%.proto
	$(PROTOC) --proto_path=$(PROTO_DIR) --go_out=$(GRPC_DIR) --go_opt=paths=source_relative --go-grpc_out=$(GRPC_DIR) --go-grpc_opt=paths=source_relative $<

build:
	$(DC) build

up:
	$(DC) up -d

down:
	$(DC) down

build-local:
	go build -tags=expo -o $(PROVER_BINARY) cmd/client/main.go
	go build -tags=expo -o $(VERIFIER_BINARY) cmd/server/main.go

up-local:
	./$(PROVER_BINARY) &
	./$(VERIFIER_BINARY) &

test-local:
	go test ./... --tags=expo

down-local:
	-@pgrep $(PROVER_BINARY) > /dev/null && pkill -f $(PROVER_BINARY) || echo "Prover service not running"
	-@pgrep $(VERIFIER_BINARY) > /dev/null && pkill -f $(VERIFIER_BINARY) || echo "Verifier service not running"

clean:
	rm -f $(PB_GO_FILES) $(PROVER_BINARY) $(VERIFIER_BINARY)
