# /modules/pki/main.tf
provider "aws" {
  region = var.region
}

# Define KMS key for encrypting CA private keys
resource "aws_kms_key" "ca_key" {
  description             = "KMS key for PKI CA encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action = "kms:*"
        Resource = "*"
      },
      {
        Effect = "Allow"
        Principal = {
          Service = "acm-pca.amazonaws.com"
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
      }
    ]
  })

  tags = var.tags
}

# Root CA
resource "aws_acmpca_certificate_authority" "root_ca" {
    certificate_authority_configuration {
        key_algorithm = "RSA_4096"
        signing_algorithm = "SHA512WITHRSA"

        subject {
          common_name = "Coinbase Root CA"
          organization = "Coinbase, Inc."
          organizational_unit = "Security"
          country = "US"
          state = "CA"
          locality = "San Francisco"
        }
    }

    permanent_deletion_time_in_days = 30
    type = "ROOT"
    usage_mode = "GENERAL_PURPOSE"

    revocation_configuration {
      crl_configuration {
        custom_cname = "crl.internal.relio.com"
        enabled = true 
        expiration_in_days = 7
        s3_bucket_name = aws_s3_bucket.crl_bucket.bucket
      }

      ocsp_configuration {
        enabled = true
      }
    }

    tags = var.tags
}

# Self-signed certificate for the root CA
resource "aws_acmpca_certificate" "root_ca_cert" {
    certificate_authority_arn = aws_acmpca_certificate_authority.root_ca.arn
    certificate_signing_request = aws_acmpca_certificate_authority.root_ca.certificate_signing_request
    signing_algorithm = "SHA512WITHRSA"

    template_arn = "arn:aws:acm-pca:::template/RootCACertificate/V1"

    validity {
      type = "YEARS"
      value = 10
    }
}

# Activate the root CA
resource "aws_acmpca_certificate_authority_certificate" "root_ca_activation" {
    certificate_authority_arn = aws_acmpca_certificate.root_ca.arn
    certificate = aws_acmpca_certificate.root_ca_cert.certificate
    certificate_chain = aws_acmpca_certificate.root_ca_cert.certificate_chain
}

# Issuing CA
resource "aws_acmpca_certificate_authority" "issuing_ca" {
    certificate_authority_configuration {
      key_algorithm = "RSA_2048"
      signing_algorithm = "SHA256WITHRSA"

      subject {
        common_name = "Relio Issuing CA"
        organization = "Relio, Inc."
        organizational_unit = "Security"
        country = "US"
        state = "CA"
        locality = "San Francisco"
      }
    }

    permanent_deletion_time_in_days = 30
    type = "SUBORDINATE"
    usage_mode = "GENERAL_PURPOSE"

    revocation_configuration {
      crl_configuration {
        custom_cname = "crl.issuing.internal.relio.com"
        enabled = true
        expiration_in_days = 1
        s3_bucket_name = aws_s3_bucket.crl_bucket.bucket
      }

      ocsp_configuration {
        enabled = true
      }
    }
    tags = var.tags
}

# Sign the issuing CA with the root CA
resource "aws_acmpca_certificate" "issuing_ca_cert" {
    certificate_authority_arn = aws_acmpca_certificate_authority.root_ca.arn
    certificate_signing_request = aws_acmpca_certificate_authority.issuing_ca.certificate_signing_request
    signing_algorithm = "SHA512WITHRSA"

    template_arn = "arn:aws:acm-pca:::template/SubordinateCACertificate_PathLen0/V1"

    validity {
      type = "YEARS"
      value = 5
    }
}

# Activate the issuing CA
resource "aws_acmpca_certificate_authority_certificate" "issuing_ca_activation" {
  certificate_authority_arn = aws_acmpca_certificate.issuing_ca.arn
  certificate = aws_acmpca_certificate.issuing_ca_cert.certificate
  certificate_chain = aws_acmpca_certificate.issuing_ca_cert.certificate_chain
}

# CRL Distribution bucket with proper security controls
resource "aws_s3_bucket" "crl_bucket" {
    bucket = "${var.environment}-${data.aws_caller_identity.current.account_id}-pki-crl"  

    tags = var.tags
}

resource "aws_s3_bucket_ownership_controls" "crl_bucket" {
    bucket = aws_s3_bucket.crl_bucket.id
    rule {
      object_ownership = "BucketOwnerPreferred"
    }
}

resource "aws_s3_bucket_acl" "crl_bucket" {
    depends_on = [aws_s3_bucket_ownership_controls.crl_bucket]
    bucket = aws_s3_bucket.crl_bucket.id
    acl = "private"
}

resource "aws_s3_bucket_versioning" "crl_bucket" {
  bucket = aws_s3_bucket.crl_bucket.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "crl_bucket" {
    bucket = aws_s3_bucket.crl_bucket.id
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
}

resource "aws_s3_bucket_lifecycle_configuration" "crl_bucket" {
    bucket = aws_s3_bucket.crl_bucket.id

    rule {
      id = "cleanup-old-crls"
      status = "Enabled"

      expiration {
        days = 90
      }
    }
}

resource "aws_s3_bucket_public_access_block" "crl_bucket" {
  bucket                  = aws_s3_bucket.crl_bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# IAM role for applications to request certificates
resource "aws_iam_role" "cert_requestor" {
    name = "${var.environment}-pki-cert-requestor"

    assume_role_policy = jsonencode({
        Version = "2012-10-17"
        Statement = [
            {
                Effect = "Allow"
                Principal = {
                    Service = "ec2.amazonaws.com"
                }
                Action = "sts:AssumeRole"
            }
        ]
    })
    tags = var.tags
}

resource "aws_iam_policy" "cert_requestor" {
    name = "${var.environment}-pki-cert-requestor-policy"
    description = "Policy for requesting certificates from private CA"

    policy = jsonencode({
        Version = "2012-10-17"
        Statement = [
            {
                Effect = "Allow"
                Action = [
                    "acm-pca:IssueCertificate",
                    "acm-pca:GetCertificate",
                    "acm-pca:ListPermissions"
                ]
                Resource = aws_acmpca_certificate_authority.issuing_ca.arn
            },
            {
                Effect = "Allow"
                Action = [
                    "secretsmanager:CreateSecret",
                    "secretsmanager:PutSecretValue",
                    "secretsmanager:UpdateSecret",
                    "secretsmanager:DeleteSecret",
                    "secretsmanager:DescribeSecret",
                    "secretsmanager:GetSecretValue"
                ]
                Resource = "arn:aws:secretsmanager:${var.region}:${data.aws_caller_identity.current.account_id}:secret:pki/*"
            }
        ]
    })
}

resource "aws_iam_role_policy_attachment" "cert_requestor" {
    role = aws_iam_role.cert_requestor.name
    policy_arn = aws_iam_policy.cert_requestor.arn 
}

# Lambda function for auto-renewal of certificates
resource "aws_lambda_function" "cert_renewer" {
  function_name = "${var.environment}-pki-cert-renewal"
  role = aws_iam_role.cert_requestor.arn
  handler = "cert_renewer.lambda_handler"
  runtime = "python3.9"
  timeout = 300
  memory_size = 512
  filename = data.archive_file.cert_renewer_zip.output_path
  source_code_hash = data.archive_file.cert_renewer_zip.output_base64sha256

  environment {
    variables = {
      ISSUING_CA_ARN = aws_acmpca_certificate.issuing_ca.arn,
      SECRETS_MANAGER_PATH = "pki/"
    }
  }
  tags = var.tags
}

data "archive_file" "cert_renewer_zip" {
    type = "zip"
    output_path = "${path.module}/cert_renewer.zip"
    
    source {
      content = file("${path.module}/lambda/cert_renewer.py")
      filename = "cert_renewer.py"
    }
}

resource "aws_iam_role" "cert_renewal_lambda" {
    name = "${var.environment}-pki-cert-renewal-lambda"
    
    assume_role_policy = jsonencode({
        Version = "2012-10-17"
        Statement = [
            {
                Effect = "Allow"
                Principal = {
                    Service = "lambda.amazonaws.com"
                }
                Action = "sts:AssumeRole"
            }
        ]
    })
    tags = var.tags
}

resource "aws_iam_policy" "cert_renewal_lambda" {
    name = "${var.environment}-pki-cert-renewal-policy"
    description = "Policy for certificate renewal lambda"

    policy = jsonencode({
        Version = "2012-10-17"
        Statement = [
            {
                Effect = "Allow"
                Action = [
                    "acm-pca:IssueCertificate",
                    "acm-pca:GetCertificate",
                    "acm-pca:ListPermissions"
                ]
                Resource = aws_acmpca_certificate_authority.issuing_ca.arn
            },
            {
                Effect = "Allow"
                Action = [
                    "secretsmanager:ListSecrets",
                    "secretsmanager:DescribeSecret",
                    "secretsmanager:GetSecretValue",
                    "secretsmanager:PutSecretValue",
                    "secretsmanager:UpdateSecret"
                ]
                Resource = "arn:aws:secretsmanager:${var.region}:${data.aws_caller_identity.current.account_id}:secret:pki/*"
            },
            {
                Effect = "Allow"
                Action = [
                    "logs:CreateLogGroup",
                    "logs:CreateLogStream",
                    "logs:PutLogEvents"
                ]
                Resource = "arn:aws:logs:${var.region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/${var.environment}-pki-cert-renewal:*"
            }
        ]
    })
}

resource "aws_iam_role_policy_attachment" "cert_renewal_lambda" {
    role = aws_iam_role.cert_renewal_lambda.name
    policy_arn = aws_iam_policy.cert_renewal_lambda.arn
}

# Cloudwatch Event to trigger certificate renewal
resource "aws_cloudwatch_event_rule" "cert_renewal" {
    name = "${var.environment}-pki-cert-renewal-schedule"
    description = "Schedule for checking and renewing certificates"
    schedule_expression = "rate(1 day)"

    tags = var.tags
}

resource "aws_cloudwatch_event_target" "cert_renewal" {
    rule = aws_cloudwatch_event_rule.cert_renewal.name
    target_id = "InvokeLambda"
    arn = aws_lambda_function.cert_renewer.arn
}

resource "aws_lambda_permission" "cert_renewal" {
    statement_id = "AllowExecutionFromCloudWatch"
    action = "lambda:InvokeFunction"
    function_name = aws_lambda_function.cert_renewer.function_name
    principal = "events.amazonaws.com"
    source_arn = aws_cloudwatch_event_rule.cert_renewal.arn
}

# CloudWatch Alarms for monitoring
resource "aws_cloudwatch_metric_alarm" "ca_expiry" {
  alarm_name          = "${var.environment}-pki-ca-expiry"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 1
  metric_name         = "DaysToExpiry"
  namespace           = "AWS/ACM-PCA"
  period              = 86400
  statistic           = "Minimum"
  threshold           = 90
  alarm_description   = "This alarm monitors CA certificate expiry"
  alarm_actions       = [aws_sns_topic.pki_alerts.arn]
  ok_actions          = [aws_sns_topic.pki_alerts.arn]

  dimensions = {
    CertificateAuthorityArn = aws_acmpca_certificate_authority.issuing_ca.arn
  }
  
  tags = var.tags
}

resource "aws_sns_topic" "pki_alerts" {
    name = "${var.environment}-pki-alerts"
  
    tags = var.tags
}

resource "aws_sns_topic_subscription" "pki_alerts" {
    topic_arn = aws_sns_topic.pki_alerts.arn
    protocol = "email"
    endpoint = var.alert_email
}

# Data sources
data "aws_caller_identity" "current" {}