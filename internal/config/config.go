package config

type GRPCServer struct {
	Network string `yaml:"network"`
	Address string `yaml:"address"`
}

// fixme might no need to be used
type ZKP struct {
	G int64 `yaml:"g"`
	H int64 `yaml:"h"`
}

type GRPCClient struct {
	Target string `yaml:"target"`
}

type Server struct {
	GRPCServer
}

type Client struct {
	GRPCClient
}
