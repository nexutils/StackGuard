resource "aws_autoscaling_group" "a" {
  min_size         = 2
  max_size         = 2
  desired_capacity = 2
}
