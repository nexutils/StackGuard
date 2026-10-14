resource "aws_instance" "web" {
  ami           = "ami-123"
  instance_type = "m5.large"
}
