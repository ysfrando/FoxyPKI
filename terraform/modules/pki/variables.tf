# /modules/pki/variables.tf
variable "region" {
    description = "AWS region to deploy the PKI infra"
    type = string
    default = "us-east-1"
}

variable "environment" {
    description = "Environment name (e.g., dev, stage, prod)" 
    type = string
    validation {
      condition = contains(["dev", "stage", "prod"], var.environment)
      error_message = "Environment must be one of: dev, stage, prod."
    }
}

variable "tags" {
  description = "Tags to apply to all resources"
  type = map(string)
  default = {}
}

variable "alert_email" {
  description = "Email address to receive PKI alerts"
  type = string
}

# Optional CA configuration overrides
variable "root_ca_validity_years" {
    description = "Validity period in years for the root CA"
    type = number
    default = 10
}

variable "issuing_ca_validity_years" {
    description = "Validity period in years for the issuing CA"
    type = number
    default = 5
}

variable "crl_revocation_days" {
    description = "Expiration period in days for the CRL"
    type = number
    default = 7
}

variable "enable_oscp" {
  description = "Enable Online Certificatae Status Protocol"
  type = bool
  default = true
}