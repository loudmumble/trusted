#!/bin/bash
set -e

echo "==> Running Go tests..."
go test -v -race -coverprofile=coverage.out ./...

echo ""
echo "==> Test coverage:"
go tool cover -func=coverage.out | tail -1

echo ""
echo "==> HTML coverage report:"
go tool cover -html=coverage.out -o coverage.html
echo "    coverage.html"
