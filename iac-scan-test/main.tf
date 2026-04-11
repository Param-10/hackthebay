resource "aws_security_group_rule" "allow_all" {
  type        = "ingress"
  from_port   = 0
  to_port     = 65535
  protocol    = "tcp"
  cidr_blocks = ["0.0.0.0/0"]
}

variable "db_password" {
  default = "hardcoded_secret_123"
}
# trigger rescan

resource "aws_s3_bucket" "public_data" {
  bucket = "my-public-bucket"
  acl    = "public-read"
}

resource "aws_db_instance" "default" {
  engine         = "mysql"
  instance_class = "db.t3.micro"
  password       = "admin123"
  publicly_accessible = true
}
