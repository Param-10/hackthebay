resource "aws_security_group_rule" "allow_all" {
  type        = "ingress"
  from_port   = 0
  to_port     = 65535
  protocol    = "tcp"
cidr_blocks = ["10.0.0.0/8"] # Or specific trusted IPs

variable "db_password" {
  type      = string
  sensitive = true
}
# trigger rescan

resource "aws_s3_bucket" "public_data" {
  bucket = "my-public-bucket"
}
resource "aws_s3_bucket_acl_v2" "example" {
  bucket = aws_s3_bucket.public_data.id
  acl    = "private"
}

resource "aws_db_instance" "default" {
  engine         = "mysql"
  instance_class = "db.t3.micro"
  password       = var.db_password
  publicly_accessible = false
}
