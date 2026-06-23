resource "aws_security_group_rule" "internal" {
  cidr_blocks = ["10.0.0.0/8"]
}

resource "aws_ebs_volume" "data" {
  encrypted = true
}
