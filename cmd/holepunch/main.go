package main

import (
	"context"
	"fmt"
	"github.com/function61/gokit/backoff"
	"github.com/function61/gokit/bidipipe"
	"github.com/function61/gokit/dynversion"
	"github.com/function61/gokit/logex"
	"github.com/function61/gokit/ossignal"
	"github.com/function61/gokit/systemdinstaller"
	"github.com/function61/gokit/tcpkeepalive"
	"github.com/function61/holepunch-server/pkg/wsconnadapter"
	"github.com/gorilla/websocket"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"
)

var (
	rootLogger              = logex.StandardLogger()
	handleClientLog         = logex.Levels(logex.Prefix("handleClient", rootLogger))
	connectToSshAndServeLog = logex.Levels(logex.Prefix("connectToSshAndServe", rootLogger))
	forwardOnePortLog       = logex.Levels(logex.Prefix("forwardOnePort", rootLogger))
	mainLoopLog             = logex.Levels(logex.Prefix("mainLoop", rootLogger))
)

func handleClient(client net.Conn, forward Forward) {
	defer client.Close()

	handleClientLog.Info.Printf("%s connected", client.RemoteAddr())
	defer handleClientLog.Info.Println("closed")

	remote, err := net.Dial("tcp", forward.Local.String())
	if err != nil {
		handleClientLog.Error.Printf("dial INTO local service error: %s", err.Error())
		return
	}

	if err := bidipipe.Pipe(client, "client", remote, "remote"); err != nil {
		handleClientLog.Error.Println(err.Error())
	}
}

func connectToSshAndServe(ctx context.Context, conf *Configuration, auth ssh.AuthMethod) error {
	connectToSshAndServeLog.Info.Println("connecting")

	sshConfig := &ssh.ClientConfig{
		User:            conf.SshServer.Username,
		Auth:            []ssh.AuthMethod{auth},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	var sshClient *ssh.Client
	var errConnect error

	if isWebsocketAddress(conf.SshServer.Address) {
		sshClient, errConnect = connectSshWebsocket(ctx, conf.SshServer.Address, sshConfig)
	} else {
		sshClient, errConnect = connectSshRegularTcp(ctx, conf.SshServer.Address, sshConfig)
	}
	if errConnect != nil {
		return errConnect
	}

	defer sshClient.Close()
	defer connectToSshAndServeLog.Info.Println("disconnecting")

	connectToSshAndServeLog.Info.Println("connected; starting to forward ports")

	listenerStopped := make(chan error, len(conf.Forwards))

	for _, forward := range conf.Forwards {
		if err := forwardOnePort(forward, sshClient, listenerStopped); err != nil {
			// closes SSH connection even if one forward Listen() fails
			return err
		}
	}

	select {
	case <-ctx.Done():
		return nil
	case listenerFirstErr := <-listenerStopped:
		// assumes all the other listeners failed too so no teardown necessary
		return listenerFirstErr
	}
}

//    blocking flow: calls Listen() on the SSH connection, and if succeeds returns non-nil error
// nonblocking flow: if Accept() call fails, stops goroutine and returns error on ch listenerStopped
func forwardOnePort(forward Forward, sshClient *ssh.Client, listenerStopped chan<- error) error {
	// Listen on remote server port
	listener, err := sshClient.Listen("tcp", forward.Remote.String())
	if err != nil {
		return err
	}

	go func() {
		defer listener.Close()

		forwardOnePortLog.Info.Printf("listening remote %s", forward.Remote.String())

		// handle incoming connections on reverse forwarded tunnel
		for {
			client, err := listener.Accept()
			if err != nil {
				listenerStopped <- fmt.Errorf("Accept(): %s", err.Error())
				return
			}

			go handleClient(client, forward)
		}
	}()

	return nil
}

func mainLoop() error {
	conf, err := readConfig()
	if err != nil {
		return err
	}

	privateKey, err := signerFromPrivateKeyFile(conf.SshServer.PrivateKeyFilePath)
	if err != nil {
		return err
	}

	sshAuth := ssh.PublicKeys(privateKey)

	// 0ms, 100 ms, 200 ms, 400 ms, 800 ms, 1600 ms, 2000 ms, 2000 ms...
	backoffTime := backoff.ExponentialWithCappedMax(100*time.Millisecond, 2*time.Second)

	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		mainLoopLog.Info.Printf("got %s; stopping", <-ossignal.InterruptOrTerminate())

		cancel()
	}()

	for {
		err := connectToSshAndServe(ctx, conf, sshAuth)
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		mainLoopLog.Error.Println(err.Error())

		time.Sleep(backoffTime())
	}
}

func main() {
	rootCmd := &cobra.Command{
		Use:     os.Args[0],
		Short:   "Self-contained SSH reverse tunnel",
		Version: dynversion.Version,
	}

	rootCmd.AddCommand(&cobra.Command{
		Use:   "connect",
		Short: "Connect to remote SSH server to make a persistent reverse tunnel",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			if err := mainLoop(); err != nil {
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
				panic(err)
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

	rootCmd.AddCommand(&cobra.Command{
		Use:   "lint",
		Short: "Validates syntax of your config file",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			if _, err := readConfig(); err != nil {
				panic(err)
			}
		},
	})

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func connectSshRegularTcp(ctx context.Context, addr string, sshConfig *ssh.ClientConfig) (*ssh.Client, error) {
	dialer := net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: tcpkeepalive.DefaultDuration,
	}

	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}

	return sshClientForConn(conn, addr, sshConfig)
}

// addr looks like "ws://example.com/_ssh"
func connectSshWebsocket(ctx context.Context, addr string, sshConfig *ssh.ClientConfig) (*ssh.Client, error) {
	emptyHeaders := http.Header{}
	wsConn, _, err := websocket.DefaultDialer.DialContext(ctx, addr, emptyHeaders)
	if err != nil {
		return nil, err
	}

	if err := tcpkeepalive.Enable(wsConn.UnderlyingConn().(*net.TCPConn), tcpkeepalive.DefaultDuration); err != nil {
		return nil, fmt.Errorf("tcpkeepalive: %s", err.Error())
	}

	// even though we have a solid connection already, for some reason NewClientConn() requires
	// address. perhaps it's uses for handshake and/or host key verification, so we shouldn't
	// just give it a dummy value
	wsUrl, err := url.Parse(addr)
	if err != nil {
		return nil, err
	}

	return sshClientForConn(wsconnadapter.New(wsConn), wsUrl.Hostname(), sshConfig)
}

func sshClientForConn(conn net.Conn, addr string, sshConfig *ssh.ClientConfig) (*ssh.Client, error) {
	sconn, chans, reqs, err := ssh.NewClientConn(conn, addr, sshConfig)
	if err != nil {
		return nil, err
	}

	return ssh.NewClient(sconn, chans, reqs), nil
}
