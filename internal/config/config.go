package config

type GRPCServer struct {
	Network string `yaml:"network"`
	Address string `yaml:"address"`
}

type ZKP struct {
	G int64 `yaml:"g"`
	H int64 `yaml:"h"`
}

type GRPCClient struct {
	Target string `yaml:"target"`
}

type Server struct {
	GRPCServer
	ZKP
}

type Client struct {
	GRPCClient
	ZKP
}
