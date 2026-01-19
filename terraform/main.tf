terraform {
  backend "local" {

  }
}

provider "aws" {
  region = var.region
}