resource "aws_db_instance" "main" {
  instance_class          = "db.m5.large"
  backup_retention_period = 7
}
