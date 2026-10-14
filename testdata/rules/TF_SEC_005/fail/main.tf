resource "aws_s3_bucket" "logs" {
  bucket = "my-public-logs"
  acl    = "public-read"
}
