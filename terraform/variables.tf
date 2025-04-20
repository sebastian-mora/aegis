variable "region" {
  default = "us-east-1"
  type    = string
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
  type = string
}

variable "host_ca_secret_name" {
  type = string
}

variable "lambda_zip_path" {
  type = string
}