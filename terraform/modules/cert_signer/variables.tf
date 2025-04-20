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

variable "host_ca_secret_name" {
  type = string
}

variable "lambda_zip_path" {
  type = string
}