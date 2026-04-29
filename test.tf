resource "aws_s3_bucket" "demo" {
  bucket = "polaris-test-bucket-demo"
  acl    = "private"
}

resource "aws_security_group" "open_world" {
  name = "demo-sg"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
