resource "aws_iam_role" "r" {
  name               = "r"
  assume_role_policy = <<EOT
{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}
EOT
}
