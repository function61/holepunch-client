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
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"
)

func handleClient(client net.Conn, forward Forward, logger *log.Logger) {
	defer client.Close()

	logl := logex.Levels(logger)

	logl.Info.Printf("%s connected", client.RemoteAddr())
	defer logl.Info.Println("closed")

	remote, err := net.Dial("tcp", forward.Local.String())
	if err != nil {
		logl.Error.Printf("dial INTO local service error: %s", err.Error())
		return
	}

	if err := bidipipe.Pipe(client, "client", remote, "remote"); err != nil {
		logl.Error.Println(err.Error())
	}
}

func connectToSshAndServe(
	ctx context.Context,
	conf *Configuration,
	auth ssh.AuthMethod,
	logger *log.Logger,
	makeLogger loggerFactory,
) error {
	logl := logex.Levels(logger)

	logl.Info.Println("connecting")

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
	defer logl.Info.Println("disconnecting")

	logl.Info.Println("connected; starting to forward ports")

	listenerStopped := make(chan error, len(conf.Forwards))

	for _, forward := range conf.Forwards {
		if err := forwardOnePort(
			forward,
			sshClient,
			listenerStopped,
			makeLogger("forwardOnePort"),
			makeLogger,
		); err != nil {
			// closes SSH connection if even one forward Listen() fails
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
func forwardOnePort(
	forward Forward,
	sshClient *ssh.Client,
	listenerStopped chan<- error,
	logger *log.Logger,
	mkLogger loggerFactory,
) error {
	logl := logex.Levels(logger)

	// Listen on remote server port
	listener, err := sshClient.Listen("tcp", forward.Remote.String())
	if err != nil {
		return err
	}

	go func() {
		defer listener.Close()

		logl.Info.Printf("listening remote %s", forward.Remote.String())

		// handle incoming connections on reverse forwarded tunnel
		for {
			client, err := listener.Accept()
			if err != nil {
				listenerStopped <- fmt.Errorf("Accept(): %s", err.Error())
				return
			}

			go handleClient(client, forward, mkLogger("handleClient"))
		}
	}()

	return nil
}

func mainInternal(ctx context.Context, logger *log.Logger) error {
	conf, err := readConfig()
	if err != nil {
		return err
	}

	privateKey, err := signerFromPrivateKeyFile(conf.SshServer.PrivateKeyFilePath)
	if err != nil {
		return err
	}

	sshAuth := ssh.PublicKeys(privateKey)

	// 0ms, 100 ms, 200 ms, 400 ms, ...
	backoffTime := backoff.ExponentialWithCappedMax(100*time.Millisecond, 5*time.Second)

	for {
		err := connectToSshAndServe(
			ctx,
			conf,
			sshAuth,
			logex.Prefix("connectToSshAndServe", logger),
			mkLoggerFactory(logger))
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		logex.Levels(logger).Error.Println(err.Error())

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
			logger := logex.StandardLogger()

			exitIfError(mainInternal(
				ossignal.InterruptOrTerminateBackgroundCtx(logger),
				logger))
		},
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "write-systemd-file",
		Short: "Install unit file to start this on startup",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			service := systemdinstaller.SystemdServiceFile(
				"holepunch",
				"Reverse tunnel",
				systemdinstaller.Args("connect"),
				systemdinstaller.Docs(
					"https://github.com/function61/holepunch-client",
					"https://function61.com/"))

			exitIfError(systemdinstaller.Install(service))

			fmt.Println(systemdinstaller.GetHints(service))
		},
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "print-pubkey",
		Short: "Prints public key, in SSH authorized_keys format",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			conf, err := readConfig()
			exitIfError(err)

			key, err := signerFromPrivateKeyFile(conf.SshServer.PrivateKeyFilePath)
			exitIfError(err)

			fmt.Println(string(ssh.MarshalAuthorizedKey(key.PublicKey())))
		},
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "lint",
		Short: "Validates syntax of your config file",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			_, err := readConfig()
			exitIfError(err)
		},
	})

	exitIfError(rootCmd.Execute())
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

type loggerFactory func(prefix string) *log.Logger

func mkLoggerFactory(rootLogger *log.Logger) loggerFactory {
	return func(prefix string) *log.Logger {
		return logex.Prefix(prefix, rootLogger)
	}
}

func exitIfError(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
