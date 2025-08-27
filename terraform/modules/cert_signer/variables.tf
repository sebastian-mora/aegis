variable "api_name" {
  description = "The name of the API"
  type        = string
}


variable "jwt_audience" {
  description = "The audience for JWT"
  type        = list(string)
}

variable "jwt_issuer" {
  description = "The issuer of the JWT"
  type        = string
}


variable "stage_name" {
  description = "The name of the deployment stage"
  type        = string
}

variable "user_ca_secret_name" {
  type = string
}

variable "jsme_expression" {
  type        = string
  description = "JSME Path expression that maps OAUTH attributes to SSH Cert Principals"
}

variable "lambda_s3_bucket" {
  description = "S3 bucket containing the Lambda deployment package"
  type        = string
}

variable "lambda_s3_key" {
  description = "S3 key for the Lambda deployment package"
  type        = string
}

variable "lambda_runtime" {
  description = "Lambda runtime"
  type        = string
  default = "provided.al2023"
}