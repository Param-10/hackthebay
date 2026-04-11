resource "aws_security_group" "web" {
  name        = "web-sg"
  description = "Allow all inbound traffic"

ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"] # Or specific trusted CIDRs
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
}
resource "aws_s3_bucket_acl" "data_acl" {
  bucket = aws_s3_bucket.data.id
  acl    = "private"
}
