output "api_endpoint" {
  description = "URL to trigger a scan via POST /scan"
  value       = aws_apigatewayv2_stage.default.invoke_url
}

output "compliant_bucket" {
  description = "Name of the compliant S3 bucket"
  value       = aws_s3_bucket.compliant.bucket
}

output "noncompliant_bucket" {
  description = "Name of the non-compliant S3 bucket"
  value       = aws_s3_bucket.noncompliant.bucket
}

output "noncompliant_sg" {
  description = "ID of the non-compliant security group"
  value       = aws_security_group.noncompliant.id
}

output "noncompliant_ebs" {
  description = "ID of the unencrypted EBS volume"
  value       = aws_ebs_volume.noncompliant.id
}
