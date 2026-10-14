terraform {
  backend "s3" {
    bucket = "b"
    key    = "k"
    region = "us-east-1"
  }
}
