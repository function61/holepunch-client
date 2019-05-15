package main

import (
	"fmt"
	"github.com/function61/gokit/jsonfile"
	"golang.org/x/crypto/ssh"
	"io/ioutil"
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
	conf := &Configuration{}
	return conf, jsonfile.Read("holepunch.json", conf, true)
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
