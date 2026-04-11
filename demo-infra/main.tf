resource "aws_security_group" "web" {
  name        = "web-sg"
  description = "Allow all inbound traffic"

  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

variable "db_password" {
  default = "SuperSecret123!"
}

resource "aws_db_instance" "production" {
  engine              = "postgres"
  instance_class      = "db.t3.medium"
  password            = var.db_password
  publicly_accessible = false
  storage_encrypted   = true
}

resource "aws_s3_bucket" "data" {
  bucket = "company-data-bucket"
  acl    = "public-read"
}
