package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/function61/gokit/app/backoff"
	"github.com/function61/gokit/io/bidipipe"
	"github.com/function61/gokit/log/logex"
	"github.com/function61/holepunch-server/pkg/wsconnadapter"
	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"
)

// almost same as connectToSshAndServe(), but with retry logic (and config setup)
func connectToSshAndServeWithRetries(ctx context.Context, logger *log.Logger) error {
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

		if err != nil {
			logex.Levels(logger).Error.Println(err.Error())
		}

		// check (non-blocking) if user requested stop
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		time.Sleep(backoffTime())
	}
}

// connect once to the SSH server. if the connection breaks, we return error and the caller
// will try to re-connect
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

	// always disconnect when function returns
	defer sshClient.Close()
	defer logl.Info.Println("disconnecting")

	logl.Info.Println("connected; starting to forward ports")

	// each listener in reverseForwardOnePort() can return one error, so make sure channel
	// has enough buffering so even if we return from here, the goroutines won't block trying
	// to return an error
	listenerStopped := make(chan error, len(conf.Forwards))

	for _, forward := range conf.Forwards {
		// TODO: "if any fails, tear down all workers" -style error handling would be better
		// handled with https://pkg.go.dev/golang.org/x/sync/errgroup?tab=doc
		if err := reverseForwardOnePort(
			forward,
			sshClient,
			listenerStopped,
			makeLogger("reverseForwardOnePort"),
			makeLogger,
		); err != nil {
			// closes SSH connection if even one forward Listen() fails
			return err
		}
	}

	// we're connected and have succesfully started listening on all reverse forwards, wait
	// for either user to ask us to stop or any of the listeners to error
	select {
	case <-ctx.Done(): // cancel requested
		return nil
	case listenerFirstErr := <-listenerStopped:
		// one or more of the listeners encountered an error. react by closing the connection
		// assumes all the other listeners failed too so no teardown necessary
		select {
		case <-ctx.Done(): // pretty much errors are to be expected if cancellation triggered
			return nil
		default:
			return listenerFirstErr
		}
	}
}

//    blocking flow: calls Listen() on the SSH connection, and if succeeds returns non-nil error
// nonblocking flow: if Accept() call fails, stops goroutine and returns error on ch listenerStopped
func reverseForwardOnePort(
	forward Forward,
	sshClient *ssh.Client,
	listenerStopped chan<- error,
	logger *log.Logger,
	mkLogger loggerFactory,
) error {
	logl := logex.Levels(logger)

	// reverse listen on remote server port
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

			// handle the connection in another goroutine, so we can support multiple concurrent
			// connections on the same port
			go handleReverseForwardConn(client, forward, mkLogger("handleReverseForwardConn"))
		}
	}()

	return nil
}

func handleReverseForwardConn(client net.Conn, forward Forward, logger *log.Logger) {
	defer client.Close()

	logl := logex.Levels(logger)

	logl.Info.Printf("%s connected", client.RemoteAddr())
	defer logl.Info.Println("closed")

	remote, err := net.Dial("tcp", forward.Local.String())
	if err != nil {
		logl.Error.Printf("dial INTO local service error: %s", err.Error())
		return
	}

	// pipe data in both directions:
	// - client => remote
	// - remote => client
	//
	// - in effect, we act as a proxy between the reverse tunnel's client and locally-dialed
	//   remote endpoint.
	// - the "client" and "remote" strings we give Pipe() is just for error&log messages
	// - this blocks until either of the parties' socket closes (or breaks)
	if err := bidipipe.Pipe(
		bidipipe.WithName("client", client),
		bidipipe.WithName("remote", remote),
	); err != nil {
		logl.Error.Println(err.Error())
	}
}

func connectSshRegularTcp(ctx context.Context, addr string, sshConfig *ssh.ClientConfig) (*ssh.Client, error) {
	dialer := net.Dialer{
		Timeout: 10 * time.Second,
	}

	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}

	return sshClientForConn(conn, addr, sshConfig)
}

// addr looks like "ws://example.com/_ssh" (or wss://..)
func connectSshWebsocket(ctx context.Context, addr string, sshConfig *ssh.ClientConfig) (*ssh.Client, error) {
	emptyHeaders := http.Header{}
	wsConn, _, err := websocket.DefaultDialer.DialContext(ctx, addr, emptyHeaders)
	if err != nil {
		return nil, err
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
