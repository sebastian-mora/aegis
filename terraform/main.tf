module "aeige_cert_signer" {
  source       = "./modules/cert_signer"
  api_name     = "aegis"
  jwt_audience = [var.jwt_audience]
  jwt_issuer   = var.jwt_issuer
  stage_name   = "prod"

  // lambda vars
  user_ca_secret_name = var.user_ca_secret_name
  jsme_expression     = var.jsme_expression
  lambda_zip_path     = var.lambda_zip_path
}

output "apigw_url" {
  value       = module.aeige_cert_signer.api_url
  description = "Aegis API Endpoint"
}