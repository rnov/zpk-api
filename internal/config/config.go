package config

type GRPCServer struct {
	Network string `yaml:"network"`
	Address string `yaml:"address"`
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
