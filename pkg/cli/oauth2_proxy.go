package cli

import (
	"net"
	"net/http"

	"github.com/projectcontour/contour-authserver/pkg/auth"
	"github.com/projectcontour/contour-authserver/pkg/config"
	"github.com/spf13/cobra"

	ctrl "sigs.k8s.io/controller-runtime"
)

//NewOIDCConnect - start server as OIDC and take in 'config' file as parameter...
func NewOAuth2Proxy() *cobra.Command {
	cmd := cobra.Command{
		Use:   "oauth2-proxy Auth Server [OPTIONS]",
		Short: "Run a OAuth2 Proxy authentication server",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			log := ctrl.Log.WithName("auth.oauth2-proxy")

			cfgFile, err := cmd.Flags().GetString("config")
			if err != nil {
				return ExitError{EX_CONFIG, err}
			}

			cfg, err := config.NewOAuth2ProxyConfig(cfgFile)
			if err != nil {
				return ExitError{EX_CONFIG, err}
			}

			log.Info("init oauth2-proxy auth... ")

			authOAuth2 := &auth.OAuth2Proxy{
				Log:        log,
				HTTPClient: http.DefaultClient,
				Config:     cfg,
			}

			listener, err := net.Listen("tcp", authOAuth2.Config.Address)
			if err != nil {
				return ExitError{EX_CONFIG, err}
			}

			srv, err := DefaultServer(cmd)
			if err != nil {
				return ExitErrorf(EX_CONFIG, "invalid TLS configuration: %s", err)
			}

			auth.RegisterServer(srv, authOAuth2)

			log.Info("started serving", "address", authOAuth2.Config.Address)
			return auth.RunServer(ctrl.SetupSignalHandler(), listener, srv)
		},
	}

	cmd.Flags().String("config", "", "Path to config file ( Yaml format ).")
	cmd.Flags().String("tls-cert-path", "", "Path to the TLS server certificate.")
	cmd.Flags().String("tls-ca-path", "", "Path to the TLS CA certificate bundle.")
	cmd.Flags().String("tls-key-path", "", "Path to the TLS server key.")

	return &cmd
}
