# /modules/pki/outputs.tf
output "root_ca_arn" {
    description = "ARN of the root CA"
    value = aws_acmpca_certificate.root_ca_cert.arn
}

output "issuing_ca_arn" {
    description = "ARN of the issuing CA"
    value = aws_acmpca_certificate.issuing_ca_cert.arn
}

output "crl_bucket_name" {
    description = "Name of the CRL bucket"
    value = aws_s3_bucket.crl_bucket.bucket
}

output "crl_requestor_role_name" {
    description = "Name of the certificate requestor IAM role"
    value = aws_iam_role.cert_requestor.name
}

output "crl_requestor_role_name" {
    description = "ARN of the certificate requestor IAM role"
    value = aws_iam_role.cert_requestor.arn
}

output "crl_renewal_lambda_role_arn" {
    description = "ARN of the certificate renewal lambda function IAM role"
    value = aws_iam_role.cert_renewal_lambda.arn
}

output "cert_renewal_lambda_name" {
    description = "Name of the certificate renewal Lambda function"
    value = aws_lambda_function.cert_renewer.function_name
}

output "pki_alerts_topic_arn" {
    description = "ARN of the SNS topic for PKI alerts"
    value = aws_sns_topic.pki_alerts.arn
}