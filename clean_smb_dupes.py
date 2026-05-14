import re

# Clean coerce.go
with open("pkg/pki/coerce.go", "r") as f:
    content = f.read()

# Remove smbSession and its methods
content = re.sub(r"type smbSession struct \{.*?\n\}\n", "", content, flags=re.DOTALL)
content = re.sub(r"func \(s \*smbSession\) smb2Header.*?\{\n.*?\n\}\n", "", content, flags=re.DOTALL)
content = re.sub(r"func \(s \*smbSession\) negotiate.*?\{\n.*?\n\}\n", "", content, flags=re.DOTALL)
content = re.sub(r"func \(s \*smbSession\) sessionSetupAnonymous.*?\{\n.*?\n\}\n", "", content, flags=re.DOTALL)
content = re.sub(r"func \(s \*smbSession\) treeConnect.*?\{\n.*?\n\}\n", "", content, flags=re.DOTALL)
content = re.sub(r"func \(s \*smbSession\) createPipe.*?\{\n.*?\n\}\n", "", content, flags=re.DOTALL)
content = re.sub(r"func \(s \*smbSession\) writePipe.*?\{\n.*?\n\}\n", "", content, flags=re.DOTALL)
content = re.sub(r"func \(s \*smbSession\) readPipe.*?\{\n.*?\n\}\n", "", content, flags=re.DOTALL)

with open("pkg/pki/coerce.go", "w") as f:
    f.write(content)

# Clean rpc_enroll.go
with open("pkg/pki/rpc_enroll.go", "r") as f:
    content = f.read()

content = re.sub(r"type smbSession struct \{.*?\n\}\n", "", content, flags=re.DOTALL)
content = re.sub(r"func \(s \*smbSession\) smb2Header.*?\{\n.*?\n\}\n", "", content, flags=re.DOTALL)
content = re.sub(r"func \(s \*smbSession\) negotiate.*?\{\n.*?\n\}\n", "", content, flags=re.DOTALL)
content = re.sub(r"func \(s \*smbSession\) sessionSetupNTLM.*?\{\n.*?\n\}\n", "", content, flags=re.DOTALL)
content = re.sub(r"func \(s \*smbSession\) treeConnect.*?\{\n.*?\n\}\n", "", content, flags=re.DOTALL)
content = re.sub(r"func \(s \*smbSession\) createPipe.*?\{\n.*?\n\}\n", "", content, flags=re.DOTALL)
content = re.sub(r"func \(s \*smbSession\) writePipe.*?\{\n.*?\n\}\n", "", content, flags=re.DOTALL)
content = re.sub(r"func \(s \*smbSession\) readPipe.*?\{\n.*?\n\}\n", "", content, flags=re.DOTALL)

with open("pkg/pki/rpc_enroll.go", "w") as f:
    f.write(content)

# Fix certtheft.go imports
with open("pkg/pki/certtheft.go", "r") as f:
    lines = f.readlines()

if 'import (\n' in "".join(lines):
    idx = "".join(lines).find('import (\n') + 9
    lines.insert(import_block_start + 1, '\t"net"\n')
    lines.insert(import_block_start + 1, '\t"time"\n')

with open("pkg/pki/certtheft.go", "w") as f:
    f.write("".join(lines))
