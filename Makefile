.PHONY: build build-linux build-darwin build-win build-android build-all test clean

BINARY_NAME := trusted
BUILD_DIR   := build
GO          := $(shell which go)
VERSION     := $(shell cat VERSION 2>/dev/null || echo "0.1.0")
LDFLAGS     := -s -w -X main.version=$(VERSION)

build:
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 $(GO) build -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/trusted

build-linux:
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 ./cmd/trusted
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 ./cmd/trusted

build-darwin:
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 $(GO) build -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 ./cmd/trusted
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 $(GO) build -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 ./cmd/trusted

build-win:
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 $(GO) build -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-win-amd64.exe ./cmd/trusted

build-android:
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-android-arm64 ./cmd/trusted

build-all: build-linux build-darwin build-win build-android

test:
	$(GO) test ./... -v -count=1

clean:
	rm -rf $(BUILD_DIR)
