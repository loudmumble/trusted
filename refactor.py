import os, glob, re

for fpath in glob.glob("pkg/pki/esc*.go"):
    with open(fpath, "r") as f:
        content = f.read()

    # Function signatures
    content = re.sub(r"func ScanESC(\d+)\(cfg \*ADCSConfig\) \(\[\]ESC(\d+)Finding, error\) \{",
                     r"func ScanESC\1(ctx context.Context, cfg *ADCSConfig, conn *ldap.Conn) ([]ESC\2Finding, error) {", content)
    
    content = re.sub(r"func ExploitESC(\d+)\(cfg \*ADCSConfig, (.+?)\)",
                     r"func ExploitESC\1(ctx context.Context, cfg *ADCSConfig, conn *ldap.Conn, \2)", content)

    # EnumerateTemplates calls
    content = content.replace("EnumerateTemplates(cfg)", "EnumerateTemplates(ctx, cfg, conn)")

    # ExploitESC calls (like in esc4 calling esc1)
    # ExploitESC1(cfg, ...)
    content = re.sub(r"ExploitESC(\d+)\(cfg, ", r"ExploitESC\1(ctx, cfg, conn, ", content)

    # Remove connectLDAP blocks (for 2 nil returns)
    content = re.sub(r"\tconn, err := connectLDAP\(cfg\)\n\tif err != nil \{\n\t\treturn nil, nil, fmt\.Errorf\(\".+?\", err\)\n\t\}\n\tdefer conn\.Close\(\)\n\n*", "", content)
    # Remove connectLDAP blocks (for 1 nil return)
    content = re.sub(r"\tconn, err := connectLDAP\(cfg\)\n\tif err != nil \{\n\t\treturn nil, fmt\.Errorf\(\".+?\", err\)\n\t\}\n\tdefer conn\.Close\(\)\n\n*", "", content)
    
    # Imports
    if "ctx context.Context" in content:
        if '"context"' not in content:
            content = content.replace('import (\n', 'import (\n\t"context"\n', 1)
        if '"github.com/go-ldap/ldap/v3"' not in content:
            content = content.replace('import (\n', 'import (\n\t"github.com/go-ldap/ldap/v3"\n', 1)

    with open(fpath, "w") as f:
        f.write(content)
