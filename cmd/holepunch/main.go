package main

import (
	"context"
	"fmt"
	"github.com/function61/gokit/backoff"
	"github.com/function61/gokit/dynversion"
	"github.com/function61/gokit/logex"
	"github.com/function61/gokit/ossignal"
	"github.com/function61/gokit/systemdinstaller"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
	"log"
	"os"
	"time"
)

func logic(ctx context.Context, logger *log.Logger) error {
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

			exitIfError(logic(
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
