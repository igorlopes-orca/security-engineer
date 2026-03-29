terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# Security group open to all traffic from anywhere
resource "aws_security_group" "open" {
  name        = "open-sg"
  description = "Allows all inbound and outbound traffic"

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# EC2 instance with public IP, no IMDSv2, default VPC
resource "aws_instance" "app" {
  ami                         = "ami-0c02fb55956c7d316"
  instance_type               = var.instance_type
  associate_public_ip_address = true
  vpc_security_group_ids      = [aws_security_group.open.id]

  # IMDSv2 not enforced — vulnerable to SSRF-based metadata theft
  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "optional"
  }

  # User data with hardcoded credentials
  user_data = <<-EOF
    #!/bin/bash
    export DB_PASSWORD=admin123
    export API_KEY=sk-live-hardcoded-key-abc123
    echo "DB_PASSWORD=admin123" >> /etc/environment
  EOF

  tags = {
    Name = "vulnerable-app-server"
  }
}

# S3 bucket with public access enabled
resource "aws_s3_bucket" "data" {
  bucket        = "my-vulnerable-data-bucket"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "data" {
  bucket = aws_s3_bucket.data.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_acl" "data" {
  bucket = aws_s3_bucket.data.id
  acl    = "public-read"
}

# RDS instance publicly accessible, no encryption, no deletion protection
resource "aws_db_instance" "db" {
  identifier             = "vulnerable-db"
  engine                 = "postgres"
  engine_version         = "13.4"
  instance_class         = "db.t3.micro"
  allocated_storage      = 20
  username               = "admin"
  password               = var.db_password
  publicly_accessible    = true
  storage_encrypted      = false
  deletion_protection    = false
  skip_final_snapshot    = true
  vpc_security_group_ids = [aws_security_group.open.id]
}

# IAM role with wildcard admin permissions
resource "aws_iam_role" "app_role" {
  name = "vulnerable-app-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "admin" {
  name = "wildcard-admin"
  role = aws_iam_role.app_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}

# No VPC flow logs, no CloudTrail configured
