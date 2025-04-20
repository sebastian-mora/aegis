# Variables
LAMBDA_ENTRY=cmd/lambda/main.go
CLI_ENTRY=cmd/cli/main.go
LAMBDA_OUTPUT=lambda_build/bootstrap
LAMBDA_ZIP=lambda_build/lambda.zip
CLI_OUTPUT=bin/cli
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
build: build-cli zip-lambda

## Run `terraform apply`
deploy:
	@echo "🚢 Deploying with Terraform..."
	cd terraform && terraform apply -auto-approve

## Run `terraform plan`
plan:
	cd terraform && terraform plan

## Clean up binaries and zips
clean:
	@echo "🧹 Cleaning build artifacts..."
	rm -rf bin/* lambda_build/bootstrap lambda_build/lambda.zip

## Run gofmt and go vet
format:
	@echo "🎨 Formatting and vetting..."
	go fmt ./...
	go vet ./...
