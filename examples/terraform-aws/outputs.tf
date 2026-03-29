output "ec2_public_ip" {
  value = aws_instance.app.public_ip
}

output "rds_endpoint" {
  value = aws_db_instance.db.endpoint
}

output "s3_bucket_name" {
  value = aws_s3_bucket.data.bucket
}
