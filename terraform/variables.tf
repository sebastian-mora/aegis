variable "region" {
  default = "us-east-1"
  type    = string
}

variable "profile" {
  default = "default"
  type = string
}

variable "jwt_audience" {
  description = "The audience for JWT"
  type        = string
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


variable "lambda_zip_path" {
  type    = string
  default = "../build/lambda.zip"
}