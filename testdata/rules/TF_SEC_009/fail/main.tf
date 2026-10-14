resource "aws_lb_listener" "http" {
  load_balancer_arn = "arn:aws:elasticloadbalancing:x"
  protocol          = "HTTP"
  port              = 80
}
