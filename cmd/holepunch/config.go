package main

import (
	"encoding/json"
	"fmt"
	"golang.org/x/crypto/ssh"
	"io/ioutil"
	"os"
	"strings"
)

type SshServer struct {
	Address            string `json:"address"`
	Username           string `json:"username"`
	PrivateKeyFilePath string `json:"private_key_file_path"`
}

type Configuration struct {
	// remote SSH server
	SshServer SshServer `json:"ssh_server"`
	Forwards  []Forward `json:"forwards"`
}

type Forward struct {
	// local service to be forwarded
	Local Endpoint `json:"local"`
	// remote forwarding port (on remote SSH server network)
	Remote Endpoint `json:"remote"`
}

type Endpoint struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}

func (endpoint *Endpoint) String() string {
	return fmt.Sprintf("%s:%d", endpoint.Host, endpoint.Port)
}

func readConfig() (*Configuration, error) {
	confFile, err := os.Open("holepunch.json")
	if err != nil {
		return nil, err
	}
	defer confFile.Close()

	conf := &Configuration{}
	jsonDecoder := json.NewDecoder(confFile)
	jsonDecoder.DisallowUnknownFields()
	if err := jsonDecoder.Decode(conf); err != nil {
		return nil, err
	}

	return conf, nil
}

func isWebsocketAddress(address string) bool {
	return strings.HasPrefix(address, "ws://") || strings.HasPrefix(address, "wss://")
}

func signerFromPrivateKeyFile(file string) (ssh.Signer, error) {
	buffer, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("Cannot read SSH public key file %s", file)
	}

	key, err := ssh.ParsePrivateKey(buffer)
	if err != nil {
		return nil, fmt.Errorf("Cannot parse SSH public key file %s", file)
	}

	return key, nil
}
