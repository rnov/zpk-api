# ZKP-API

Made with :blue_heart: by rnov.

ZKP-API is an implementation of the Chaum–Pedersen Protocol, a zero-knowledge proof system. 
It consists of two main components: a client (prover) and a server (verifier). These components communicate over gRPC to generate and validate one-time passwords (OTPs) for secure login processes.

The prover component also exposes an HTTP server that facilitates `/register` and `/login` operations.

## Quick Start

### Using Docker

To build and start the services using Docker Compose:

```sh
make all
```

In `tools/request/calls.sh` with `./call.sh register` and `./call.sh login`
you can make calls directly.

### Locally:

#### Prerequisites

Before you begin, ensure you have met the following requirements:

* You have installed the latest version of [Go](https://golang.org/dl/).
* You have installed [Docker](https://www.docker.com/get-started)
  and [Docker Compose](https://docs.docker.com/compose/install/) (for Docker targets).
* You have installed [Protocol Buffers Compiler](https://grpc.io/docs/protoc-installation/).

#### Makefile Usage

The Makefile provides a set of directives to facilitate the building and managing of the project both locally and as
Docker containers.

### Generating Protobuf Go Files

To generate Go files from the `.proto` definitions, build locally the binaries and run them run:

```sh
make all-local
```

## Project Structure and Design

The project's structure largely adheres to the [golang-standards/project-layout](https://github.com/golang-standards/project-layout), which, while not official, is a widely accepted convention for organizing Go projects.

### Key Directories:

- `cmd`: Contains the main applications for the project.
- `pkg`: Houses all the logic intended for public use. Notably:
  - `storage`: Defines the storage interface and its implementations.
  - `zkp`: Contains the Chaum-Pedersen protocol implementations.
  - `app`: Manages the business logic for both the client (prover) and server (verifier) applications. It utilizes other packages within `pkg` but is not imported by them.

### Application Design:

- **Dependency Injection**: The project employs dependency injection through composition, a common pattern in Go. Interfaces are used instead of concrete structures, facilitating mocking and enabling polymorphism.
- **Onion Architecture**: The design is onion-oriented (akin to hexagonal architecture), achieved through dependency injection. Inner layers provide interfaces to outer layers without knowledge of their consumers, allowing for flexible business model exposure to different handlers (e.g:HTTP/gRPC).
  -  In the code it can be seen in `pkg/app`, in either `prover` or `verifier`, both import `pkg/storage` interface in their
     structs and expose the service interface `Auth` to the handlers, either http (prover) or grpc (verifier).
- **ZKP Chaum-Pedersen Implementation**:
  - The implementation uses `big.Int` for mathematical operations.
  - As a proof of concept (PoC), certain variables that would typically be generated at runtime are statically defined.
  - It is important to note that the elliptic curve implementation is currently not functioning as expected and fails to evaluate correctly.

### Implementation notes:
  * In both zkp implementations at the beginning of each file there is the following: `//go:build expo` || `//go:build curve` this is a tag for compile build,
    as of now all the builds provided here are with `expo`.
  * Most of the code has detailed comments that usually would not be needed in such detail.
    There is also plenty of comments as `note:` that would not be needed under different circumstances.
  * Added tests in the most critical and relevant part of the code.
  * Spent about 40% of the time trying to figure out the issue with the elliptic curve implementation, at this point
    it is either something very small or just a std lib issue. A good amount of the code of the elliptic curve has been left out.