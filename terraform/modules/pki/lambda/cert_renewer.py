# /modules/pki/lambda/cert_renewer.py
import boto3
import json
import os
import logging
import datetime
import uuid
import base64
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

# Set up logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Initialize AWS clients
secretsmanager = boto3.client('secretsmanager')
acmpca = boto3.client('acm-pca')

# Get environment variables
ISSUING_CA_ARN = os.environ['ISSUING_CA_ARN']
SECRETS_MANAGER_PATH = os.environ['SECRETS_MANAGER_PATH']

# Constants
RENEWAL_THRESHOLD_DAYS = 30
CERT_VALIDITY_DAYS = 365

def lambda_handler(event, context):
    """
    Lambda function to check for certificates close to expiry and renew them
    """
    logger.info('Starting certificate renewal check')
    
    try:
        # List all certificate secrets
        secret_list = list_certificate_secrets()
        
        # Process each certificate for renewal
        for secret_name in secret_list:
            process_certificate(secret_name)

        return {
            'status': 200,
            'body': json.dumps('Certificate renewal check completed successfully')
        }      
    except Exception as e:
        logger.error(f"Error during certificate renewal: {str(e)}")  
        raise
    
def list_certificate_secrets():
    """
    List all secrets in the PKI path that contain certificates
    """
    secrets = []
    
    paginator = secretsmanager.get_paginator('list_secrets')
    
    for page in paginator.paginate(Filter={'Key': 'name', 'Values': [SECRETS_MANAGER_PATH]}):
        for secret in page['SecretList']:
            secrets.append(secret['Name'])
    
    return secrets
    
def process_certificate(secret_name):
    """
    Check if a certificates needs renewal and renew if necessary
    """
    try:
        # Get the current certificate
        secret_value = secretsmanager.get_secret_value(SecretId=secret_name)
        secret_data = json.loads(secret_value['SecretString'])
        
        # Skip if not a certificate
        if 'certificate' not in secret_data or 'private_key' not in secret_data:
            logger.info(f'Secret {secret_name} is not a certificate, skipping')
            return
        
        # Parse the certificate to check expiry
        cert_data = base64.b64decode(secret_data['certificate'])
        cert = x509.load_pem_x509_certificate(cert_data, default_backend())
        
        # Calculate days until expiry
        days_until_expiry = (cert.not_valid_after - datetime.datetime.now()).days
        
        logger.info(f'Certificate {secret_name} expires in {days_until_expiry} days')
        
        # Check if renewal is needed:
        if days_until_expiry <= RENEWAL_THRESHOLD_DAYS:
            logger.info(f'Renewing certificate {secret_name}')
            renew_certificate(secret_name, secret_data)
    except Exception as e:
        logger.error(f"Error processing certificate {secret_name}: {str(e)}")
        raise
            
def renew_certificate(secret_name, secret_data):
    """
    Renew a certificate that is close to expiry
    """
    try:
        # Extract certificate info for renewal
        cert_data = base64.b64decode(secret_data['certificate'])
        cert = x509.load_pem_x509_certificate(cert_data, default_backend())
        
        # Extract the common name and SANs from the current cert
        common_name = None
        for attr in cert.subject:
            if attr.oid == NameOID.COMMON_NAME:
                common_name = attr.value
                break
            
        if not common_name:
            raise ValueError("Could not extract common name from certificate")
        
        # Extract SANs
        san_domains = []
        try:
            san_ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            san_domains = [dnsname.value for dnsname in san_ext.value]
        except x509.extensions.ExtensionNotFound:
            # No SANs in the certificate
            pass
        
        # Load the private key
        private_key_data = base64.b64decode(secret_data['private_key'])
        private_key = serialization.load_pem_private_key(
            private_key_data,
            password=None,
            backend=default_backend()
        )
        
        # Generate a CSR
        csr = generate_csr(private_key, common_name, san_domains)

        # Issue a new certificate
        cert_response = acmpca.issue_certificate(
            CertificateAuthorityArn=ISSUING_CA_ARN,
            Csr=csr,
            SigningAlgorithm='SHA256WITHRSA',
            Validity={
                'Value': CERT_VALIDITY_DAYS,
                'Type': 'DAYS'
            },
            IdempotencyToken=str(uuid.uuid4())
        )

        # Wait for the cert to be issued
        waiter = acmpca.get_waiter('certificate_issued')
        waiter.wait(
            CertificateAuthorityArn=ISSUING_CA_ARN,
            CertificateArn=cert_response['CertificateArn']
        )
        
        # Get the issued cert
        get_cert_response = acmpca.get_certificate(
            CertificateAuthorityArn=ISSUING_CA_ARN,
            CertificateArn=cert_response['CertificateArn']
        )
        
        # Update the secret with the new certificate
        updated_secret = secret_data.copy()
        updated_secret['certificate'] = base64.b64encode(get_cert_response['Certificate'].encode()).decode()
        updated_secret['certificate_chain'] = base64.b64encode(get_cert_response['CertificateChain'].encode()).decode()
        
        secretsmanager.put_secret_value(
            SecretId=secret_name,
            SecretString=json.dumps(updated_secret)
        )
        
        logger.info(f'Successfully renewed certificate: {secret_name}')
        
    except Exception as e:
        logger.error(f'Error renewing certificate {secret_name}: {str(e)}')
        raise
        
def generate_csr(private_key, common_name, san_domains=[]):
    """
    Generate a Certificate Signing Request (CSR)
    """
    # Create a CSR builder
    builder = x509.CertificateSigningRequestBuilder()
    
    # Add subject
    builder = builder.subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'Relio, Inc.'),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, 'Security'),
        x509.NameAttribute(NameOID.COUNTRY_NAME, 'US'),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, 'CA'),
        x509.NameAttribute(NameOID.LOCALITY_NAME, 'San Francisco')
    ]))
    
    # Add SANs if available
    if san_domains:
        san_list = [x509.DNSName(domain) for domain in san_domains]
        builder = builder.add_extension(
            x509.SubjectAlternativeName(san_list),
            critical=False
        )
        
    # Sign the CSR with our private key
    csr = builder.sign(private_key, hashes.SHA256(), default_backend())
    
    # Return the CSR in PEM format
    csr_pem = csr.public_bytes(serialization.Encoding.PEM)
    return csr_pem