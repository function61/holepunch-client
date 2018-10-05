package main

import (
	"encoding/json"
	"fmt"
	"github.com/function61/pi-security-module/pkg/systemdinstaller"
	"golang.org/x/crypto/ssh"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"time"
)

type SshServer struct {
	Username           string   `json:"username"`
	PrivateKeyFilePath string   `json:"private_key_file_path"`
	Endpoint           Endpoint `json:"endpoint"`
}

type Configuration struct {
	// remote SSH server
	SshServer SshServer `json:"ssh_server"`
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

func handleClient(client net.Conn, conf *Configuration) {
	defer client.Close()

	log.Printf("handleClient: accepted %s", client.RemoteAddr())

	remote, err := net.Dial("tcp", conf.Local.String())
	if err != nil {
		log.Printf("handleClient: dial INTO local service error: %s", err.Error())
		return
	}

	chDone := make(chan bool)

	// Start remote -> local data transfer
	go func() {
		_, err := io.Copy(client, remote)
		if err != nil {
			log.Printf("handleClient: error while copy remote->local: %s", err)
		}
		chDone <- true
	}()

	// Start local -> remote data transfer
	go func() {
		_, err := io.Copy(remote, client)
		if err != nil {
			log.Printf("handleClient: error while copy local->remote: %s", err)
		}
		chDone <- true
	}()

	<-chDone

	log.Printf("handleClient: closed")
}

func publicKeyFromPrivateKeyFile(file string) (ssh.AuthMethod, error) {
	buffer, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("Cannot read SSH public key file %s", file)
	}

	key, err := ssh.ParsePrivateKey(buffer)
	if err != nil {
		return nil, fmt.Errorf("Cannot parse SSH public key file %s", file)
	}

	return ssh.PublicKeys(key), nil
}

func connectToSshAndServe(conf *Configuration, auth ssh.AuthMethod) error {
	log.Printf("connectToSshAndServe: connecting")

	sshConfig := &ssh.ClientConfig{
		User:            conf.SshServer.Username,
		Auth:            []ssh.AuthMethod{auth},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	// Connect to SSH remote server using serverEndpoint
	serverConn, err := ssh.Dial("tcp", conf.SshServer.Endpoint.String(), sshConfig)
	if err != nil {
		return err
	}

	log.Printf("connectToSshAndServe: connected")

	// Listen on remote server port
	listener, err := serverConn.Listen("tcp", conf.Remote.String())
	if err != nil {
		return err
	}
	defer listener.Close()

	// handle incoming connections on reverse forwarded tunnel
	for {
		log.Printf("connectToSshAndServe: waiting for incoming connections")

		client, err := listener.Accept()
		if err != nil {
			return err
		}

		go handleClient(client, conf)
	}
}

func main() {
	if len(os.Args) != 2 {
		log.Printf("Usage: %s run | write-systemd-file", os.Args[0])
		return
	}

	cmd := os.Args[1]

	if cmd == "run" {
		confFile, err := os.Open("holepunch.json")
		if err != nil {
			panic(err)
		}

		conf := &Configuration{}
		if err := json.NewDecoder(confFile).Decode(conf); err != nil {
			panic(err)
		}

		confFile.Close()

		sshAuth, errSshPrivateKey := publicKeyFromPrivateKeyFile(conf.SshServer.PrivateKeyFilePath)
		if errSshPrivateKey != nil {
			panic(errSshPrivateKey)
		}

		for {
			err := connectToSshAndServe(conf, sshAuth)

			log.Printf("connectToSshAndServe failed: %s", err.Error())

			time.Sleep(5 * time.Second)
		}
	} else if cmd == "write-systemd-file" {
		if err := systemdinstaller.InstallSystemdServiceFile("holepunch", []string{"run"}, "Holepunch reverse tunnel"); err != nil {
			log.Printf("Error: %s", err.Error())
		}
	} else {
		log.Printf("Unknown command: %s", cmd)
	}
}
