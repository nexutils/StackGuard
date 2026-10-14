resource "aws_lb" "public" {
  name     = "pub"
  internal = false
}

resource "aws_lb_listener" "ssh" {
  load_balancer_arn = aws_lb.public.arn
  port              = 22
  protocol          = "TCP"
}
