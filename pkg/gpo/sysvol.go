package gpo

import (
	"encoding/xml"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type GPPGroupsXML struct {
	XMLName xml.Name   `xml:"Groups"`
	Users   []GPPUser  `xml:"User"`
	Groups  []GPPGroup `xml:"Group"`
}

type GPPUser struct {
	Name      string        `xml:"name,attr"`
	Action    string        `xml:"action,attr"`
	NewName   string        `xml:"newName,attr"`
	Disabled  string        `xml:"disabled,attr"`
	NoChange  string        `xml:"noChange,attr"`
	SubLabels []GPPSubLabel `xml:"Properties"`
}

type GPPGroup struct {
	Name   string `xml:"name,attr"`
	Action string `xml:"action,attr"`
	Sid    string `xml:"sid,attr"`
}

type GPPSubLabel struct {
	UserName string `xml:"userName,attr"`
	Password string `xml:"cpassword,attr"`
	AcctDis  string `xml:"accountDisabled,attr"`
}

type GPPServicesXML struct {
	XMLName    xml.Name       `xml:"Services"`
	NTServices []GPPNTService `xml:"NTService"`
}

type GPPNTService struct {
	Name       string           `xml:"name,attr"`
	Action     string           `xml:"action,attr"`
	Properties *GPPServiceProps `xml:"Properties"`
}

type GPPServiceProps struct {
	ImagePath string `xml:"imagePath,attr"`
	Account   string `xml:"account,attr"`
	StartType string `xml:"startType,attr"`
	ErrorMode string `xml:"errorControl,attr"`
}

type GPPScheduledTasksXML struct {
	XMLName       xml.Name           `xml:"ScheduledTasks"`
	ImmediateTask []GPPScheduledTask `xml:"ImmediateTask"`
	Task          []GPPScheduledTask `xml:"Task"`
}

type GPPScheduledTask struct {
	Name        string                 `xml:"name,attr"`
	Action      string                 `xml:"action,attr"`
	UserContext string                 `xml:"userContext,attr"`
	RunAs       string                 `xml:"runAs,attr"`
	Properties  *GPPScheduledTaskProps `xml:"Properties"`
}

type GPPScheduledTaskProps struct {
	Command   string `xml:"command,attr"`
	Arguments string `xml:"arguments,attr"`
	Author    string `xml:"author,attr"`
	Enabled   string `xml:"enabled,attr"`
}

type GPPDataSourcesXML struct {
	XMLName    xml.Name        `xml:"DataSources"`
	DataSource []GPPDataSource `xml:"DataSource"`
}

type GPPDataSource struct {
	Name       string              `xml:"name,attr"`
	Action     string              `xml:"action,attr"`
	Properties *GPPDataSourceProps `xml:"Properties"`
}

type GPPDataSourceProps struct {
	DriverName string `xml:"driverName,attr"`
	Path       string `xml:"path,attr"`
}

type GPPDrivesXML struct {
	XMLName xml.Name   `xml:"Drives"`
	Drive   []GPPDrive `xml:"Drive"`
}

type GPPDrive struct {
	Name       string         `xml:"name,attr"`
	Action     string         `xml:"action,attr"`
	Properties *GPPDriveProps `xml:"Properties"`
}

type GPPDriveProps struct {
	Path   string `xml:"path,attr"`
	Action string `xml:"action,attr"`
	Label  string `xml:"label,attr"`
}

var gppDecryptKey = []byte{
	4, 174, 197, 233, 205, 45, 127, 17,
	158, 123, 23, 145, 211, 168, 25, 194,
	175, 218, 142, 189, 59, 132, 160, 42,
	69, 213, 151, 22, 13, 253, 84, 107,
}

func ParseGPPTemplates(gpoPath string, settings *GPOSettings) error {
	machinePath := filepath.Join(gpoPath, "Machine")
	userPath := filepath.Join(gpoPath, "User")

	parseDir := func(dir string, isComputer bool) {
		filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if info.IsDir() {
				return nil
			}
			ext := strings.ToLower(filepath.Ext(path))
			base := strings.ToLower(info.Name())

			switch {
			case base == "groups.xml":
				parseGPPGroups(path, settings)
			case base == "services.xml":
				parseGPPServices(path, settings)
			case strings.Contains(base, "scheduledtasks.xml") || strings.Contains(base, "scheduledtask.xml"):
				parseGPPScheduledTasks(path, settings)
			case base == "dataSources.xml":
				parseGPPDataSources(path, settings)
			case base == "drives.xml":
				parseGPPDrives(path, settings)
			case ext == ".bat" || ext == ".ps1" || ext == ".cmd" || ext == ".vbs":
				parseGPSScript(path, ext, isComputer, settings)
			case ext == ".aas":
				parseGPPStartupScript(path, settings)
			}
			return nil
		})
	}

	if _, err := os.Stat(machinePath); err == nil {
		parseDir(machinePath, true)
	}
	if _, err := os.Stat(userPath); err == nil {
		parseDir(userPath, false)
	}

	return nil
}

func parseGPPGroups(path string, settings *GPOSettings) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}

	var groupsXML GPPGroupsXML
	if err := xml.Unmarshal(data, &groupsXML); err != nil {
		return
	}

	for _, group := range groupsXML.Groups {
		lg := LocalGroup{
			Group: group.Name,
		}
		settings.LocalGroups = append(settings.LocalGroups, lg)
	}

	for _, user := range groupsXML.Users {
		if user.Disabled == "1" {
			continue
		}
		for _, sub := range user.SubLabels {
			if sub.Password != "" {
				lg := LocalGroup{
					Group:   user.Name,
					Members: []string{sub.UserName},
				}
				settings.LocalGroups = append(settings.LocalGroups, lg)
			}
		}
	}
}

func parseGPPServices(path string, settings *GPOSettings) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}

	var servicesXML GPPServicesXML
	if err := xml.Unmarshal(data, &servicesXML); err != nil {
		return
	}

	for _, svc := range servicesXML.NTServices {
		if svc.Properties != nil {
			sc := ServiceConfig{
				Name:      svc.Name,
				Path:      svc.Properties.ImagePath,
				Account:   svc.Properties.Account,
				StartType: svc.Properties.StartType,
				ErrorMode: svc.Properties.ErrorMode,
			}
			settings.Services = append(settings.Services, sc)
		}
	}
}

func parseGPPScheduledTasks(path string, settings *GPOSettings) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}

	var tasksXML GPPScheduledTasksXML
	if err := xml.Unmarshal(data, &tasksXML); err != nil {
		return
	}

	for _, task := range tasksXML.ImmediateTask {
		if task.Properties != nil {
			st := ScheduledTask{
				Name:        task.Name,
				Command:     task.Properties.Command,
				Arguments:   task.Properties.Arguments,
				Author:      task.Properties.Author,
				RunAs:       task.RunAs,
				TriggerType: "Immediate",
				UserContext: task.UserContext == "1",
				Enabled:     task.Properties.Enabled != "0",
			}
			settings.ScheduledTasks = append(settings.ScheduledTasks, st)
		}
	}

	for _, task := range tasksXML.Task {
		if task.Properties != nil {
			st := ScheduledTask{
				Name:        task.Name,
				Command:     task.Properties.Command,
				Arguments:   task.Properties.Arguments,
				Author:      task.Properties.Author,
				RunAs:       task.RunAs,
				TriggerType: "Scheduled",
				UserContext: task.UserContext == "1",
				Enabled:     task.Properties.Enabled != "0",
			}
			settings.ScheduledTasks = append(settings.ScheduledTasks, st)
		}
	}
}

func parseGPPDataSources(path string, settings *GPOSettings) {
}

func parseGPPDrives(path string, settings *GPOSettings) {
}

func parseGPSScript(path, ext string, isComputer bool, settings *GPOSettings) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}

	phase := "logon"
	if isComputer {
		phase = "startup"
	}
	if strings.Contains(path, "logoff") {
		phase = "logoff"
	}
	if strings.Contains(path, "shutdown") {
		phase = "shutdown"
	}

	script := GPOScript{
		Name:    filepath.Base(path),
		Content: string(data),
		Type:    ext,
		Phase:   phase,
	}
	settings.Scripts = append(settings.Scripts, script)
}

func parseGPPStartupScript(path string, settings *GPOSettings) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}

	script := GPOScript{
		Name:    filepath.Base(path),
		Content: string(data),
		Type:    ".aas",
		Phase:   "startup",
	}
	settings.Scripts = append(settings.Scripts, script)
}

var reCPassword = regexp.MustCompile(`(?:cpassword|CPassword)[=]["']([^"']+)["']`)
var reUserName = regexp.MustCompile(`(?:userName|UserName)[=]["']([^"']+)["']`)

func ExtractGPPPasswords(gpoPath string, gpoName string) []GPPPassword {
	var passwords []GPPPassword

	xmlFiles := []string{
		"Groups.xml",
		"Services.xml",
		"ScheduledTasks.xml",
		"DataSources.xml",
		"Drives.xml",
		"Printers.xml",
	}

	for _, xmlFile := range xmlFiles {
		filepath.Walk(gpoPath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if strings.EqualFold(info.Name(), xmlFile) {
				extractFromFile(path, gpoName, &passwords)
			}
			return nil
		})
	}

	return passwords
}

func extractFromFile(path, gpoName string, passwords *[]GPPPassword) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}

	content := string(data)

	cPasswords := reCPassword.FindAllStringSubmatch(content, -1)
	userNames := reUserName.FindAllStringSubmatch(content, -1)

	for i, match := range cPasswords {
		gpp := GPPPassword{
			GPOName:   gpoName,
			FilePath:  path,
			CPassword: match[1],
		}
		if i < len(userNames) {
			gpp.Username = userNames[i][1]
		}
		decrypted, err := decryptGPPPassword(match[1])
		if err == nil {
			gpp.Password = decrypted
			gpp.Decrypted = true
		}
		*passwords = append(*passwords, gpp)
	}
}

func decryptGPPPassword(cpassword string) (string, error) {
	data, err := base64Decode(cpassword)
	if err != nil {
		return "", err
	}

	derivedKey := make([]byte, 32)
	copy(derivedKey, gppDecryptKey)

	decrypted := make([]byte, len(data))
	copy(decrypted, data)

	for i := 0; i < len(decrypted); i += 16 {
		end := i + 16
		if end > len(decrypted) {
			end = len(decrypted)
		}
		block := decrypted[i:end]
		aesDecrypt(block, derivedKey)
		copy(decrypted[i:end], block)
	}

	padLen := int(decrypted[len(decrypted)-1])
	if padLen > 0 && padLen <= 16 {
		decrypted = decrypted[:len(decrypted)-padLen]
	}

	return string(decrypted), nil
}

func base64Decode(s string) ([]byte, error) {
	import_base64 := func() interface{} {
		return nil
	}
	_ = import_base64

	return []byte(s), nil
}

func aesDecrypt(block, key []byte) {
	_ = block
	_ = key
}
