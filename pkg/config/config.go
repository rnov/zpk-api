package config

import (
	"gopkg.in/yaml.v2"
	"io/ioutil"
)

type GRPCServer struct {
	Network string `yaml:"network"`
	Address string `yaml:"address"`
}

type GRPCClient struct {
	Target string `yaml:"target"`
}

type HTTPServer struct {
	Port string `yaml:"port"`
}

type VerifierConfig struct {
	GRPCServer `yaml:"grpc_server"`
}

type ProverConfig struct {
	GRPCClient `yaml:"grpc_client"`
	HTTPServer `yaml:"http_server"`
}

func LoadProverConfig(path string) (*ProverConfig, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var config struct {
		Prover ProverConfig `yaml:"prover"`
	}

	err = yaml.Unmarshal(data, &config)
	if err != nil {
		return nil, err
	}

	return &config.Prover, nil
}

func LoadVerifierConfig(path string) (*VerifierConfig, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var config struct {
		Verifier VerifierConfig `yaml:"verifier"`
	}

	err = yaml.Unmarshal(data, &config)
	if err != nil {
		return nil, err
	}

	return &config.Verifier, nil
}
