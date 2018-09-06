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

type Configuration struct {
	// local service to be forwarded
	Local Endpoint `json:"local"`
	// remote SSH server
	Server Endpoint `json:"server"`
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
	remote, err := net.Dial("tcp", conf.Local.String())
	if err != nil {
		log.Printf("Dial INTO local service error: %s", err.Error())
		return
	}

	defer client.Close()
	chDone := make(chan bool)

	// Start remote -> local data transfer
	go func() {
		_, err := io.Copy(client, remote)
		if err != nil {
			log.Println(fmt.Sprintf("error while copy remote->local: %s", err))
		}
		chDone <- true
	}()

	// Start local -> remote data transfer
	go func() {
		_, err := io.Copy(remote, client)
		if err != nil {
			log.Println(fmt.Sprintf("error while copy local->remote: %s", err))
		}
		chDone <- true
	}()

	<-chDone

	log.Printf("handleClient: closed")
}

func publicKeyFile(file string) ssh.AuthMethod {
	buffer, err := ioutil.ReadFile(file)
	if err != nil {
		log.Fatalln(fmt.Sprintf("Cannot read SSH public key file %s", file))
		return nil
	}

	key, err := ssh.ParsePrivateKey(buffer)
	if err != nil {
		log.Fatalln(fmt.Sprintf("Cannot parse SSH public key file %s", file))
		return nil
	}
	return ssh.PublicKeys(key)
}

func runOnce(conf *Configuration) error {
	sshConfig := &ssh.ClientConfig{
		User: "root",
		Auth: []ssh.AuthMethod{
			publicKeyFile("id_ecdsa"),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	// Connect to SSH remote server using serverEndpoint
	serverConn, err := ssh.Dial("tcp", conf.Server.String(), sshConfig)
	if err != nil {
		return err
	}

	// Listen on remote server port
	listener, err := serverConn.Listen("tcp", conf.Remote.String())
	if err != nil {
		return err
	}
	defer listener.Close()

	// handle incoming connections on reverse forwarded tunnel
	for {
		client, err := listener.Accept()
		if err != nil {
			return err
		}

		go handleClient(client, conf)
	}

	return nil
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

		for {
			err := runOnce(conf)

			log.Printf("runOnce failed: %s", err.Error())

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
