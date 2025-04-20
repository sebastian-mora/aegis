module "aeige_cert_signer" {
  source       = "./modules/cert_signer"
  api_name     = "aegis"
  jwt_audience = var.jwt_audience
  jwt_issuer   = var.jwt_issuer
  stage_name   = "prod"

  // lambda vars
  user_ca_secret_name = var.user_ca_secret_name
  lambda_zip_path     = var.lambda_zip_path
  host_ca_secret_name = var.host_ca_secret_name
}

