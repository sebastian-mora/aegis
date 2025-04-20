# Variables
LAMBDA_ENTRY=cmd/lambda/sign_key/main.go
CLI_ENTRY=cmd/userclient/main.go
LAMBDA_OUTPUT=build/bootstrap
LAMBDA_ZIP=build/lambda.zip
CLI_OUTPUT=build/userclient
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

## Run `terraform apply`
deploy:
	@echo "🚢 Deploying with Terraform..."
	cd terraform && terraform apply $(if $(VAR_FILE),-var-file=$(VAR_FILE))

## Run `terraform plan`
plan:
	cd terraform && terraform plan $(if $(VAR_FILE),-var-file=$(VAR_FILE))

## Run gofmt and go vet
format:
	@echo "🎨 Formatting and vetting Go Code..."
	go fmt ./...
	go vet ./...
	@ echo "🎨 Formatting Terraform..."
	cd terraform && terraform fmt
