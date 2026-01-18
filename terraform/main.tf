terraform {
  backend "s3" {
    bucket = "terraform-backend-aegis"
    key    = "dev/terraform.tfstate"
  }
}

provider "aws" {
  region = var.region
}