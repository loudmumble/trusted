package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/loudmumble/trusted/pkg/c2"
	"github.com/spf13/cobra"
)

var c2Cmd = &cobra.Command{
	Use:   "c2",
	Short: "Command and Control server",
	Long: `Launch HTTP/HTTPS C2 listeners, manage implant sessions, and generate stager/implant configs.

Examples:
  trusted c2 --bind 0.0.0.0 --port 8080 --protocol http
  trusted c2 --bind 0.0.0.0 --port 8443 --protocol https
  trusted c2 --generate-stager --output stager.json --c2-url https://c2.example.com:8443
  trusted c2 --implant-type cert-auth --upn admin@corp.local --c2-url https://c2.example.com:8443`,
	RunE: func(cmd *cobra.Command, args []string) error {
		genStager, _ := cmd.Flags().GetBool("generate-stager")
		implantType, _ := cmd.Flags().GetString("implant-type")

		if implantType != "" {
			return runGenerateImplant(cmd, implantType)
		}
		if genStager {
			return runGenerateStager(cmd)
		}
		return runC2Server(cmd)
	},
}

func runC2Server(cmd *cobra.Command) error {
	bind, _ := cmd.Flags().GetString("bind")
	port, _ := cmd.Flags().GetInt("port")
	protocol, _ := cmd.Flags().GetString("protocol")
	certFile, _ := cmd.Flags().GetString("cert")
	keyFile, _ := cmd.Flags().GetString("key")

	if bind == "" {
		bind = "0.0.0.0"
	}
	if port == 0 {
		port = 8080
	}
	if protocol == "" {
		protocol = "http"
	}

	listener := &c2.Listener{
		BindAddress: bind,
		Port:        port,
		Protocol:    protocol,
		CertFile:    certFile,
		KeyFile:     keyFile,
	}

	return listener.Start()
}

func runGenerateStager(cmd *cobra.Command) error {
	output, _ := cmd.Flags().GetString("output")
	c2URL, _ := cmd.Flags().GetString("c2-url")

	if c2URL == "" {
		return fmt.Errorf("--c2-url is required for stager generation")
	}
	if output == "" {
		output = "stager.json"
	}

	stager := c2.GenerateStagerConfig(c2URL)
	data, err := json.MarshalIndent(stager, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal stager config: %w", err)
	}

	if err := os.WriteFile(output, data, 0600); err != nil {
		return fmt.Errorf("write stager: %w", err)
	}

	fmt.Printf("[+] Stager configuration written to %s\n", output)
	fmt.Printf("    C2 URL: %s\n", c2URL)
	fmt.Printf("    Stager ID: %s\n", stager.ID)
	return nil
}

func runGenerateImplant(cmd *cobra.Command, implantType string) error {
	c2URL, _ := cmd.Flags().GetString("c2-url")
	upn, _ := cmd.Flags().GetString("upn")
	output, _ := cmd.Flags().GetString("output")

	if c2URL == "" {
		return fmt.Errorf("--c2-url is required")
	}

	switch implantType {
	case "cert-auth":
		if upn == "" {
			return fmt.Errorf("--upn is required for cert-auth implant type")
		}
		if output == "" {
			output = "./cert-auth-implant"
		}
		_, err := c2.GenerateCertAuthImplant(c2URL, upn, output)
		return err
	default:
		return fmt.Errorf("unknown implant type: %s (supported: cert-auth)", implantType)
	}
}

func init() {
	rootCmd.AddCommand(c2Cmd)

	c2Cmd.Flags().String("bind", "0.0.0.0", "Bind address for the C2 listener")
	c2Cmd.Flags().Int("port", 8080, "Port for the C2 listener")
	c2Cmd.Flags().String("protocol", "http", "Protocol: http or https")
	c2Cmd.Flags().String("cert", "", "TLS certificate file (for HTTPS)")
	c2Cmd.Flags().String("key", "", "TLS private key file (for HTTPS)")
	c2Cmd.Flags().Bool("generate-stager", false, "Generate a stager configuration file")
	c2Cmd.Flags().String("implant-type", "", "Generate implant config (cert-auth)")
	c2Cmd.Flags().String("upn", "", "UPN for cert-auth implant")
	c2Cmd.Flags().String("output", "", "Output file/directory path")
	c2Cmd.Flags().String("c2-url", "", "C2 callback URL")
}
