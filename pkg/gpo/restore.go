package gpo

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type BackupEntry struct {
	GPOGUID    string    `json:"gpo_guid"`
	GPOName    string    `json:"gpo_name"`
	Timestamp  time.Time `json:"timestamp"`
	BackupPath string    `json:"backup_path"`
	Action     string    `json:"action"`
	Changes    []string  `json:"changes"`
}

type BackupManifest struct {
	Entries []BackupEntry `json:"entries"`
}

type RestoreEntry struct {
	GPOGUID    string `json:"gpo_guid"`
	BackupPath string `json:"backup_path"`
	Action     string `json:"action"`
}

func BackupGPO(gpoGUID, gpoPath, backupDir string) (string, error) {
	if backupDir == "" {
		backupDir = "gpo_backups"
	}

	backupPath := filepath.Join(backupDir, gpoGUID)
	if err := os.MkdirAll(backupPath, 0700); err != nil {
		return "", fmt.Errorf("create backup dir: %w", err)
	}

	if err := copyDir(gpoPath, backupPath); err != nil {
		return "", fmt.Errorf("copy GPO files: %w", err)
	}

	entry := BackupEntry{
		GPOGUID:    gpoGUID,
		Timestamp:  time.Now(),
		BackupPath: backupPath,
		Action:     "backup",
	}

	manifestPath := filepath.Join(backupDir, "manifest.json")
	manifest := loadManifest(manifestPath)
	manifest.Entries = append(manifest.Entries, entry)

	manifestData, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal manifest: %w", err)
	}

	if err := os.WriteFile(manifestPath, manifestData, 0600); err != nil {
		return "", fmt.Errorf("write manifest: %w", err)
	}

	return backupPath, nil
}

func RestoreGPO(gpoGUID, sysvolPath, backupDir string) error {
	if backupDir == "" {
		backupDir = "gpo_backups"
	}

	backupPath := filepath.Join(backupDir, gpoGUID)
	if _, err := os.Stat(backupPath); os.IsNotExist(err) {
		return fmt.Errorf("backup not found for GPO: %s", gpoGUID)
	}

	gpoPath := findGPOPath(gpoGUID, sysvolPath)
	if gpoPath == "" {
		return fmt.Errorf("GPO path not found for GUID: %s", gpoGUID)
	}

	if err := os.RemoveAll(gpoPath); err != nil {
		return fmt.Errorf("remove current GPO: %w", err)
	}

	if err := copyDir(backupPath, gpoPath); err != nil {
		return fmt.Errorf("restore GPO files: %w", err)
	}

	entry := BackupEntry{
		GPOGUID:    gpoGUID,
		Timestamp:  time.Now(),
		BackupPath: backupPath,
		Action:     "restore",
	}

	manifestPath := filepath.Join(backupDir, "manifest.json")
	manifest := loadManifest(manifestPath)
	manifest.Entries = append(manifest.Entries, entry)

	manifestData, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal manifest: %w", err)
	}

	return os.WriteFile(manifestPath, manifestData, 0600)
}

func CleanupGPO(gpoGUID, sysvolPath, backupDir string) error {
	gpoPath := findGPOPath(gpoGUID, sysvolPath)
	if gpoPath == "" {
		return nil
	}

	cleanupPatterns := []string{
		filepath.Join(gpoPath, "Machine", "Preferences", "ScheduledTasks"),
		filepath.Join(gpoPath, "Machine", "Preferences", "Groups"),
		filepath.Join(gpoPath, "Machine", "Preferences", "Registry"),
		filepath.Join(gpoPath, "Machine", "Preferences", "Files"),
		filepath.Join(gpoPath, "Machine", "Preferences", "Services"),
		filepath.Join(gpoPath, "Machine", "Scripts"),
		filepath.Join(gpoPath, "Machine", "Files"),
		filepath.Join(gpoPath, "Machine", "Microsoft", "Windows NT", "SecEdit"),
		filepath.Join(gpoPath, "User", "Preferences"),
		filepath.Join(gpoPath, "User", "Scripts"),
	}

	for _, pattern := range cleanupPatterns {
		os.RemoveAll(pattern)
	}

	entry := BackupEntry{
		GPOGUID:   gpoGUID,
		Timestamp: time.Now(),
		Action:    "cleanup",
		Changes:   []string{"removed injected configurations"},
	}

	manifestPath := filepath.Join(backupDir, "manifest.json")
	manifest := loadManifest(manifestPath)
	manifest.Entries = append(manifest.Entries, entry)

	manifestData, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal manifest: %w", err)
	}

	return os.WriteFile(manifestPath, manifestData, 0600)
}

func ListBackups(backupDir string) ([]BackupEntry, error) {
	if backupDir == "" {
		backupDir = "gpo_backups"
	}

	manifestPath := filepath.Join(backupDir, "manifest.json")
	manifest := loadManifest(manifestPath)

	var backups []BackupEntry
	for _, entry := range manifest.Entries {
		if entry.Action == "backup" {
			backups = append(backups, entry)
		}
	}

	return backups, nil
}

func loadManifest(path string) BackupManifest {
	data, err := os.ReadFile(path)
	if err != nil {
		return BackupManifest{}
	}

	var manifest BackupManifest
	json.Unmarshal(data, &manifest)
	return manifest
}

func copyDir(src, dst string) error {
	srcInfo, err := os.Stat(src)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(dst, srcInfo.Mode()); err != nil {
		return err
	}

	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		srcPath := filepath.Join(src, entry.Name())
		dstPath := filepath.Join(dst, entry.Name())

		if entry.IsDir() {
			if err := copyDir(srcPath, dstPath); err != nil {
				return err
			}
		} else {
			if err := copyFile(srcPath, dstPath); err != nil {
				return err
			}
		}
	}

	return nil
}

func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}

	info, err := os.Stat(src)
	if err != nil {
		return err
	}

	return os.WriteFile(dst, data, info.Mode())
}

func ExportAuditLog(backupDir, outputPath string) error {
	if backupDir == "" {
		backupDir = "gpo_backups"
	}

	manifestPath := filepath.Join(backupDir, "manifest.json")
	manifest := loadManifest(manifestPath)

	var sb strings.Builder
	sb.WriteString("# GPO Audit Log\n\n")
	sb.WriteString(fmt.Sprintf("Generated: %s\n\n", time.Now().Format("2006-01-02 15:04:05")))

	for _, entry := range manifest.Entries {
		sb.WriteString(fmt.Sprintf("## %s — %s\n", entry.Action, entry.GPOGUID))
		sb.WriteString(fmt.Sprintf("- Time: %s\n", entry.Timestamp.Format("2006-01-02 15:04:05")))
		if entry.GPOName != "" {
			sb.WriteString(fmt.Sprintf("- Name: %s\n", entry.GPOName))
		}
		if entry.BackupPath != "" {
			sb.WriteString(fmt.Sprintf("- Backup: %s\n", entry.BackupPath))
		}
		if len(entry.Changes) > 0 {
			sb.WriteString("- Changes:\n")
			for _, change := range entry.Changes {
				sb.WriteString(fmt.Sprintf("  - %s\n", change))
			}
		}
		sb.WriteString("\n")
	}

	return os.WriteFile(outputPath, []byte(sb.String()), 0600)
}
