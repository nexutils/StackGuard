terraform {
  required_version = ">= 1.6"
  backend "s3" {
    bucket       = "tfstate"
    key          = "clean/terraform.tfstate"
    region       = "us-east-1"
    encrypt      = true
    use_lockfile = true
  }
}

provider "aws" {
  region = "us-east-1"
}

resource "aws_cloudwatch_metric_alarm" "cpu" {
  alarm_name          = "cpu-high"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 120
  threshold           = 80
  tags = {
    Name = "cpu-high"
  }
}
