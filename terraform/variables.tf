variable "region" {
  description = "AWS region to deploy into"
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Prefix used for all resource names"
  type        = string
  default     = "sec-scanner"
}

variable "account_id" {
  description = "Your AWS account ID — used to make S3 bucket names unique"
  type        = string
}

variable "lambda_image_uri" {
  description = "ECR image URI for the Lambda scanner function"
  type        = string
  default     = "placeholder"
}
