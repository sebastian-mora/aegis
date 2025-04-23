# Variables
LAMBDA_ENTRY=./cmd/lambda
CLI_ENTRY=./cmd/aegis
LAMBDA_OUTPUT=build/bootstrap
LAMBDA_ZIP=build/lambda.zip
CLI_OUTPUT=build/aegis
GOOS=linux
GOARCH=amd64

.PHONY: all build clean build-cli build-lambda zip-lambda deploy format

all: build

## Build CLI binary
build-cli:
	@echo "🚀 Building CLI..."
	go build -o $(CLI_OUTPUT) $(CLI_ENTRY)

## Build Lambda binary
build-lambda:
	@echo "🛠️  Building Lambda..."
	GOOS=$(GOOS) GOARCH=$(GOARCH) CGO_ENABLED=0 go build -o $(LAMBDA_OUTPUT) $(LAMBDA_ENTRY)
	zip -j $(LAMBDA_ZIP) $(LAMBDA_OUTPUT)

## Build everything (CLI + Lambda)
build: build-cli build-lambda

## Install CLI binary to ~/.local/bin
install-cli: build-cli
	@echo "📦 Installing CLI to ~/.local/bin/aegis"
	cp $(CLI_OUTPUT) ~/.local/bin/aegis

## Run `terraform apply`
deploy-infra:
	@echo "🚢 Deploying with Terraform..."
	cd terraform && terraform init && terraform apply -auto-approve

## Run `terraform plan`
plan:
	cd terraform && terraform plan

## Run gofmt and go vet
format:
	@echo "🎨 Formatting and vetting Go Code..."
	go fmt ./...
	go vet ./...
	@ echo "🎨 Formatting Terraform..."
	cd terraform && terraform fmt
