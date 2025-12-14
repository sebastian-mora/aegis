variable "region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "api_name" {
  description = "The name of the API"
  type        = string
  default     = "aegis"
}

variable "stage_name" {
  description = "The name of the deployment stage"
  type        = string
  default     = "prod"
}

variable "jwt_audience" {
  description = "The audience for JWT"
  type        = list(string)
}

variable "jwt_issuer" {
  description = "The issuer of the JWT"
  type        = string
}

variable "user_ca_secret_name" {
  type    = string
  default = "aegis-ssh-user-ca"
}

variable "jsme_expression" {
  type        = string
  description = "JSME Path expression that maps OAUTH attributes to SSH Cert Principals"
}

variable "lambda_runtime" {
  description = "Lambda runtime"
  type        = string
  default     = "provided.al2023"
}

variable "lambda_zip_sha256" {
  description = "SHA256 hash of the Lambda deployment package"
  type        = string
  default     = ""
}