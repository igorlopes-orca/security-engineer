variable "aws_region" {
  default = "us-east-1"
}

variable "instance_type" {
  default = "t2.micro"
}

variable "db_password" {
  default = "admin123"
}

variable "allowed_cidr" {
  default = "0.0.0.0/0"
}
