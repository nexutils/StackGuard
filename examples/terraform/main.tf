provider "aws" {
  region = "eu-west-1"
}

resource "aws_s3_bucket" "assets" {
  bucket = "acme-public-assets"
  acl    = "public-read"
}

resource "aws_security_group" "bastion" {
  name = "bastion"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_instance" "orders" {
  engine              = "postgres"
  engine_version      = "16.3"
  instance_class      = "db.t4g.medium"
  publicly_accessible = true
}
