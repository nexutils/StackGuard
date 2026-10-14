resource "aws_subnet" "a" {
  vpc_id            = "vpc-1"
  cidr_block        = "10.0.1.0/24"
  availability_zone = "us-east-1a"
}
