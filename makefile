# Variables
PROTO_DIR := ./pkg/api
GRPC_DIR := ./pkg/http/grpc/zkp
PROTO_FILES := $(wildcard $(PROTO_DIR)/*.proto)
PB_GO_FILES := $(patsubst $(PROTO_DIR)/%.proto,$(GRPC_DIR)/%.pb.go,$(PROTO_FILES))

# Protoc Compiler
PROTOC := protoc

.PHONY: all clean

all: $(PB_GO_FILES)

$(GRPC_DIR)/%.pb.go: $(PROTO_DIR)/%.proto
	$(PROTOC) --proto_path=$(PROTO_DIR) --go_out=$(GRPC_DIR) --go_opt=paths=source_relative --go-grpc_out=$(GRPC_DIR) --go-grpc_opt=paths=source_relative $<

clean:
	rm -f $(PB_GO_FILES)

# works
#  protoc --proto_path=. --go_out=./pkg --go_opt=paths=source_relative --go-grpc_out=./pkg/http/grpc --go-grpc_opt=paths=source_relative auth.proto