terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.region
}


# ─── S3 Buckets ───────────────────────────────────────────────────────────────

# Compliant bucket — scanner should pass this one
resource "aws_s3_bucket" "compliant" {
  bucket = "${var.project_name}-compliant-${var.account_id}"
}

resource "aws_s3_bucket_public_access_block" "compliant" {
  bucket = aws_s3_bucket.compliant.id

  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "compliant" {
  bucket = aws_s3_bucket.compliant.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Non-compliant bucket — scanner should flag this one
resource "aws_s3_bucket" "noncompliant" {
  bucket = "${var.project_name}-noncompliant-${var.account_id}"
}

# Intentionally no public access block or encryption on this bucket


# ─── VPC and Security Groups ──────────────────────────────────────────────────

resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"

  tags = {
    Name = "${var.project_name}-vpc"
  }
}

# Compliant security group — no open inbound rules
resource "aws_security_group" "compliant" {
  name        = "${var.project_name}-compliant-sg"
  description = "Compliant security group with no open inbound rules"
  vpc_id      = aws_vpc.main.id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Non-compliant security group — SSH open to the world
resource "aws_security_group" "noncompliant" {
  name        = "${var.project_name}-noncompliant-sg"
  description = "Non-compliant security group with open SSH"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}


# ─── EBS Volume ───────────────────────────────────────────────────────────────

# Non-compliant EBS volume — unencrypted
resource "aws_ebs_volume" "noncompliant" {
  availability_zone = "${var.region}a"
  size              = 1
  encrypted         = false

  tags = {
    Name = "${var.project_name}-noncompliant-ebs"
  }
}


# ─── IAM Role for Lambda ──────────────────────────────────────────────────────

resource "aws_iam_role" "lambda_role" {
  name = "${var.project_name}-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action    = "sts:AssumeRole"
        Effect    = "Allow"
        Principal = { Service = "lambda.amazonaws.com" }
      }
    ]
  })
}

resource "aws_iam_role_policy" "lambda_policy" {
  name = "${var.project_name}-lambda-policy"
  role = aws_iam_role.lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # Allow scanner to read S3, EC2, and IAM resources
        Effect = "Allow"
        Action = [
          "s3:ListAllMyBuckets",
          "s3:GetBucketPublicAccessBlock",
          "s3:GetEncryptionConfiguration",
          "s3:PutPublicAccessBlock",
          "s3:PutEncryptionConfiguration",
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeVolumes",
          "ec2:RevokeSecurityGroupIngress",
          "iam:GetAccountSummary",
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
        ]
        Resource = "*"
      }
    ]
  })
}


# ─── Lambda Function ──────────────────────────────────────────────────────────

resource "aws_lambda_function" "scanner" {
  function_name = "${var.project_name}-scanner"
  role          = aws_iam_role.lambda_role.arn
  package_type  = "Image"
  image_uri     = var.lambda_image_uri

  timeout     = 60
  memory_size = 256

  environment {
    variables = {
      PROJECT_NAME = var.project_name
    }
  }
}


# ─── API Gateway ──────────────────────────────────────────────────────────────

resource "aws_apigatewayv2_api" "scanner_api" {
  name          = "${var.project_name}-api"
  protocol_type = "HTTP"
}

resource "aws_apigatewayv2_integration" "lambda" {
  api_id                 = aws_apigatewayv2_api.scanner_api.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.scanner.invoke_arn
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "scan" {
  api_id    = aws_apigatewayv2_api.scanner_api.id
  route_key = "POST /scan"
  target    = "integrations/${aws_apigatewayv2_integration.lambda.id}"
}

resource "aws_apigatewayv2_stage" "default" {
  api_id      = aws_apigatewayv2_api.scanner_api.id
  name        = "$default"
  auto_deploy = true
}

resource "aws_lambda_permission" "api_gateway" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.scanner.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.scanner_api.execution_arn}/*/*"
}
