provider "aws" {
  region     = "us-east-1"
  access_key = "AKIAIOSFODNN7EXAMPLE"
  secret_key = "wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY"
}

resource "aws_cloudwatch_metric_alarm" "a" {
  alarm_name = "a"
}
