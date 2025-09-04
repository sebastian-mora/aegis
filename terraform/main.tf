terraform {
  backend "remote" {}
}

provider "aws" {
  region = var.region
}

module "aeige_cert_signer" {
  source       = "./modules/cert_signer"
  api_name     = "aegis"
  jwt_audience = [var.jwt_audience]
  jwt_issuer   = var.jwt_issuer
  stage_name   = "prod"

  // lambda vars
  user_ca_secret_name = var.user_ca_secret_name
  jsme_expression     = var.jsme_expression
  lambda_s3_bucket    = var.lambda_s3_bucket
  lambda_s3_key       = var.lambda_s3_key
  lambda_runtime      = var.lambda_runtime
  lambda_zip_sha256   = var.lambda_zip_sha256
}

output "apigw_url" {
  value       = module.aeige_cert_signer.api_url
  description = "Aegis API Endpoint"
}