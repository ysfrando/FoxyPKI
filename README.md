
## PKI Infra Architecture
### PKI Module
- KMS Key: You create a KMS key to encrypt and protect the private key of the Root CA
- Root CA: The Root Certificate Authority is created using the KMS key for private key protection. It has a custom revocation configuration (CRL and OSCP)
- Self-Signed Certificate: A certificate is issued for the Root CA itself, making it a fully functional cA capable of signing certificates
- Activation: After the certificate is issued, the Root CA is activated, making it available to issue certificates for the organization or other subordinate CAs