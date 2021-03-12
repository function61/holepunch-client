package main

import (
	"fmt"
	"os"

	"github.com/function61/gokit/app/dynversion"
	"github.com/function61/gokit/log/logex"
	"github.com/function61/gokit/os/osutil"
	"github.com/function61/gokit/os/systemdinstaller"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
)

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

			osutil.ExitIfError(connectToSshAndServeWithRetries(
				osutil.CancelOnInterruptOrTerminate(logger),
				logger))
		},
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "write-systemd-file",
		Short: "Install unit file to start this on startup",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			service := systemdinstaller.Service(
				"holepunch",
				"Reverse tunnel",
				systemdinstaller.Args("connect"),
				systemdinstaller.Docs(
					"https://github.com/function61/holepunch-client",
					"https://function61.com/"))

			osutil.ExitIfError(systemdinstaller.Install(service))

			fmt.Println(systemdinstaller.EnableAndStartCommandHints(service))
		},
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "print-pubkey",
		Short: "Prints public key, in SSH authorized_keys format",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			conf, err := readConfig()
			osutil.ExitIfError(err)

			key, err := signerFromPrivateKeyFile(conf.SshServer.PrivateKeyFilePath)
			osutil.ExitIfError(err)

			fmt.Println(string(ssh.MarshalAuthorizedKey(key.PublicKey())))
		},
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "lint",
		Short: "Validates syntax of your config file",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			_, err := readConfig()
			osutil.ExitIfError(err)
		},
	})

	osutil.ExitIfError(rootCmd.Execute())
}
