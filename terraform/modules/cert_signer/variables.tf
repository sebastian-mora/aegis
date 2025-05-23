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


variable "lambda_zip_path" {
  type    = string
  default = "../build/lambda.zip"
}