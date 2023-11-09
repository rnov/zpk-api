# Use a base Go image
FROM golang:1.21 as builder

# Install protoc
RUN apt-get update && apt-get install -y protobuf-compiler

# Install the Go gRPC plugin
RUN go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.28
RUN go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.2

# Set the working directory inside the container
WORKDIR /app

# Copy only the necessary files
COPY go.mod go.sum ./
RUN go mod download
COPY pkg/ pkg/
COPY cmd/ cmd/
COPY config/docker/ config/
# Add any other directories or files you need

# Generate Go files from proto
RUN protoc --proto_path=. --go_out=./pkg --go_opt=paths=source_relative \
           --go-grpc_out=./pkg/http/grpc --go-grpc_opt=paths=source_relative \
           ./pkg/api/auth.proto

# Build the command inside the container
RUN go build -tags=expo -o prover cmd/client/main.go

# Final stage
FROM golang:1.21
WORKDIR /app
COPY --from=builder /app/prover .
COPY --from=builder /app/config/config.yaml ./config/

# Run the executable
CMD ["./prover"]
