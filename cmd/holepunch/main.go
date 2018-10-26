package main

import (
	"fmt"
	"github.com/function61/gokit/bidipipe"
	"github.com/function61/gokit/systemdinstaller"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
	"log"
	"net"
	"os"
	"time"
)

var version = "dev" // replaced dynamically at build time

func handleClient(client net.Conn, forward Forward) {
	defer client.Close()
	defer log.Printf("handleClient: closed")

	log.Printf("handleClient: accepted %s", client.RemoteAddr())

	remote, err := net.Dial("tcp", forward.Local.String())
	if err != nil {
		log.Printf("handleClient: dial INTO local service error: %s", err.Error())
		return
	}

	if err := bidipipe.Pipe(client, "client", remote, "remote"); err != nil {
		log.Printf("handleClient: %s", err.Error())
	}
}

func connectToSshAndServe(conf *Configuration, auth ssh.AuthMethod) error {
	log.Printf("connectToSshAndServe: connecting")

	sshConfig := &ssh.ClientConfig{
		User:            conf.SshServer.Username,
		Auth:            []ssh.AuthMethod{auth},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	// Connect to SSH remote server using serverEndpoint
	sshClient, err := ssh.Dial("tcp", conf.SshServer.Endpoint.String(), sshConfig)

	defer sshClient.Close()

	log.Printf("connectToSshAndServe: connected")

	for _, forward := range conf.Forwards {
		// TODO: errors when Accept() fails later?
		if err := forwardOnePort(forward, sshClient); err != nil {
			// closes SSH connection even if one forward Listen() fails
			return err
		}
	}

	select {}
}

func forwardOnePort(forward Forward, sshClient *ssh.Client) error {
	// Listen on remote server port
	listener, err := sshClient.Listen("tcp", forward.Remote.String())
	if err != nil {
		return err
	}

	go func() {
		defer listener.Close()

		log.Printf("forwardOnePort: listening remote %s", forward.Remote.String())

		// handle incoming connections on reverse forwarded tunnel
		for {
			client, err := listener.Accept()
			if err != nil {
				log.Printf("forwardOnePort: Accept(): %s", err)
				return
			}

			go handleClient(client, forward)
		}
	}()

	return nil
}

func run() error {
	conf, err := readConfig()
	if err != nil {
		return err
	}

	privateKey, err := signerFromPrivateKeyFile(conf.SshServer.PrivateKeyFilePath)
	if err != nil {
		return err
	}

	sshAuth := ssh.PublicKeys(privateKey)

	for {
		err := connectToSshAndServe(conf, sshAuth)

		log.Printf("connectToSshAndServe failed: %s", err.Error())

		time.Sleep(5 * time.Second)
	}
}

func main() {
	rootCmd := &cobra.Command{
		Use:     os.Args[0],
		Short:   "Self-contained SSH reverse tunnel",
		Version: version,
	}

	rootCmd.AddCommand(&cobra.Command{
		Use:   "connect",
		Short: "Connect to remote SSH server to make a persistent reverse tunnel",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			if err := run(); err != nil {
				panic(err)
			}
		},
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "write-systemd-file",
		Short: "Install unit file to start this on startup",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			systemdHints, err := systemdinstaller.InstallSystemdServiceFile("holepunch", []string{"connect"}, "Holepunch reverse tunnel")
			if err != nil {
				log.Fatalf("Error: %s", err.Error())
			}

			fmt.Println(systemdHints)
		},
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "print-pubkey",
		Short: "Prints public key, in SSH authorized_keys format",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			conf, err := readConfig()
			if err != nil {
				panic(err)
			}

			key, err := signerFromPrivateKeyFile(conf.SshServer.PrivateKeyFilePath)
			if err != nil {
				panic(err)
			}

			fmt.Println(string(ssh.MarshalAuthorizedKey(key.PublicKey())))
		},
	})

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
