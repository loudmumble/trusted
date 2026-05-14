.PHONY: build clean install

BINARY_NAME=smartpotato

build: build-windows build-linux

build-windows:
	@echo "Building $(BINARY_NAME) for Windows..."
	@CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags "-s -w" -o $(BINARY_NAME).exe .

build-linux:
	@echo "Building $(BINARY_NAME) for Linux..."
	@CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "-s -w" -o $(BINARY_NAME)_linux .

clean:
	@echo "Cleaning build artifacts..."
	@rm -f $(BINARY_NAME).exe $(BINARY_NAME)_linux

install: build
	@echo "Installing $(BINARY_NAME)..."
	@sudo install -m 755 $(BINARY_NAME).exe /usr/local/bin/ 2>/dev/null || true
	@sudo install -m 755 $(BINARY_NAME)_linux /usr/local/bin/ 2>/dev/null || true
	@echo "Installed to /usr/local/bin/"
