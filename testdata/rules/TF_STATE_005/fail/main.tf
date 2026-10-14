terraform {
  backend "s3" {
    bucket = "my-tf-state"
    key    = "k"
    region = "us-east-1"
  }
}

provider "aws" {
  region = "us-east-1"
}

resource "aws_s3_bucket" "state" {
  bucket = "my-tf-state"
}
