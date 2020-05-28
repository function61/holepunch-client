package main

import (
	"context"
	"fmt"
	"github.com/function61/gokit/bidipipe"
	"github.com/function61/gokit/logex"
	"github.com/function61/holepunch-server/pkg/wsconnadapter"
	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"
	"log"
	"net"
	"net/http"
	"net/url"
	"time"
)

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
func reverseForwardOnePort(
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

	if err := bidipipe.Pipe(client, "client", remote, "remote"); err != nil {
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
