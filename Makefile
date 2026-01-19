# Variables
LAMBDA_FUNCTIONS := sign public_key
LAMBDA_DIR := ./cmd/lambda
CLI_ENTRY=./cmd/cli
CLI_OUTPUT=build/aegis
GOOS=linux
GOARCH=amd64

.PHONY: all build clean build-cli build-lambda deploy format

all: build

## Build CLI binary
build-cli:
	@echo "Building CLI..."
	go build -o $(CLI_OUTPUT) $(CLI_ENTRY)

## Build all Lambda functions
build-lambda:
	@mkdir -p build dist
	@for fn in $(LAMBDA_FUNCTIONS); do \
		echo "Building Lambda function: $$fn..."; \
		GOOS=$(GOOS) GOARCH=$(GOARCH) CGO_ENABLED=0 go build -o build/bootstrap $(LAMBDA_DIR)/$$fn; \
		cp build/bootstrap build/bootstrap_$$fn; \
		zip -j dist/lambda_$$fn.zip build/bootstrap; \
	done

## Build everything (CLI + Lambda)
build: build-cli build-lambda

## Install CLI binary to ~/.local/bin
install-cli: build-cli
	@echo "Installing CLI to ~/.local/bin/aegis"
	cp $(CLI_OUTPUT) ~/.local/bin/aegis


## Run gofmt and go vet
format:
	@echo "Formatting and vetting Go Code..."
	go fmt ./...
	go vet ./...
	@ echo "Formatting Terraform..."
	cd terraform && terraform fmt
