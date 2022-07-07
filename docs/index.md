# Go Client Library for EJBCA

## Overview
The EJBCA Go Client is a Go library/SDK designed to simplify the generation of cryptographic digital
certificates in accordance with enterprise security policies through an [EJBCA Certificate Authority](https://www.primekey.com/products/).
See the [getting started guide](https://github.com/Keyfactor/ejbca-go-client/blob/main/docs/getting-started.md)
to learn the basics of using the library.

## Requirements
* [Go](https://golang.org/doc/install) (v1.18 +)
* EJBCA
	* [EJBCA Enterprise](https://www.primekey.com/products/ejbca-enterprise/) (v7.7 +)

## Authentication
The EJBCA Go Client is designed to work with the EJBCA REST API interface included with EJBCA Enterprise by PrimeKey.
Future development will add support for the EST interface. As such, the client requires that a client certificate and
associated private key be available for authentication with EJBCA. Additionally, if the EJBCA server certificate is signed by
an untrusted source, it's recommended that this certificate be registered with the client as a root of trust. Configuration
requires that these certificates be stored in a known location on the file system.

## Supported Methods
### Client
#### NewEJBCAClient
```go
package main
	
import (
	"github.com/Keyfactor/ejbca-go-client/pkg/ejbca"
	"log"
	"os"
)
config := &ejbca.Config{
	// Path to client certificate in PEM format. This certificate must contain a client certificate that
	// is recognized by the EJBCA instance represented by Hostname. This PEM file may also contain the private
	// key associated with the certificate, but KeyFile can also be set to configure the private key.
	CertificateFile: os.Getenv("EJBCA_CERTPATH"),
	
	// Path to private key in PEM format. This file should contain the private key associated with the
	// client certificate configured in CertificateFile.
	KeyFile:         os.Getenv("EJBCA_KEYPATH"),
	
	// Password that protects private key (if encrypted)
	Password:        os.Getenv("EJBCA_KEYPASSWORD"),
	
	// Path to the root CA that signed the certificate passed to the client for HTTPS connection.
	// This is not required if the CA is trusted by the host operating system. This should be a PEM
	// formatted certificate, and doesn't necessarily have to be the CA that signed CertificateFile.
	CAFile:          os.Getenv("EJBCA_CAPATH"),

	DefaultCertificateProfileName   os.Getenv("EJBCA_CERT_PROFILE_NAME"),
	DefaultEndEntityProfileName     os.Getenv("EJBCA_END_ENTITY_PROFILE_NAME"),
	DefaultCertificateAuthorityName os.Getenv("EJBCA_CA_NAME"),
}

// Generate a new client factory using the config struct and EJBCA hostname
factory := ejbca.ClientFactory(os.Getenv("EJBCA_HOSTNAME"), config)
if factory == nil {
	log.Fatalf("Failed to create client factory")
}

// Generate a new EST client by passing the NewESTClient method EJBCA username and password.
client, err := factory.NewESTClient(os.Getenv("USERNAME"), os.Getenv("PASSWORD"))
if err != nil {
log.Fatal(err)
}

// Configure the EJBCA REST client
// The factory returns the same client object for both methods. This means that a client object
// can be used for EST and/or REST.
_, err = factory.NewEJBCAClient()
if err != nil {
	log.Fatal(err)
}
```
### Certificate
#### EnrollPKCS10
```go
enroll := &ejbca.PKCS10CSREnrollment{
	// Note that CertificateProfileName, EndEntityProfileName, CertificateAuthorityName, 
	// Username, and Password are all stored in the client object as default values,
	// so they don't need to be configured here.
	CertificateRequest:       csr,
	IncludeChain:             true,
}

resp, err := client.EnrollPKCS10(enroll)
if err != nil {
	return err, nil
}
```
#### RevokeCertificate
```go
arg := &ejbca.RevokeCertificate{
	IssuerDn:                issuer,
	CertificateSerialNumber: serialNumber,
	Reason:                  "CESSATION_OF_OPERATION",
	Date:                    time.Now().Format(time.RFC3339),
}

resp, err := client.RevokeCertificate(arg)
if err != nil {
	log.Fatal(err)
}
```
#### CheckRevocationStatus
```go
status, err := client.CheckRevocationStatus(issuerDn, serialNumber)
if err != nil {
	log.Fatal(err)
}
var state string
if status.Revoked {
	state = "is"
} else {
	state = "is not"
}

fmt.Printf("Certificate with serial number %s %s revoked.", status.SerialNumber, state)
```
#### EnrollKeystore
```go
config := &ejbca.EnrollKeystore{
	// Note that Username and Password are stored in the client object as default values,
	// so they don't need to be configured here.
	KeyAlg:   "RSA",
	KeySpec:  "2048",
}

keystore, err := client.EnrollKeystore(config)
if err != nil {
	log.Fatal(err)
}

fmt.Printf("Enrolled new keystore with serial number %s", keystore.SerialNumber)
```
#### GetExpiringCertificates
```go
days := 90
certificates, err := client.GetExpiringCertificates(days, 0, 100)
if err != nil {
	log.Fatal(err)
}

fmt.Printf("There are %d certificates expiring in the next %d days.", len(certificates.CertificatesRestResponse.Certificates), days)
```
#### EnrollCertificateRequest
```go
enroll := &ejbca.EnrollCertificateRequest{
	// Note that Username and Password are stored in the client object as default values,
	// so they don't need to be configured here.
	CertificateRequest:       csr,
	IncludeChain:             false,
	CertificateAuthorityName: caName,
}

certificateRequestResponse, err := client.EnrollCertificateRequest(enroll)
if err != nil {
	log.Fatal(err)
}
```
#### SearchCertificates
```go
criteria := &ejbca.SearchCertificate{Search{
	MaxNumberOfResults: 100,
	Criteria: []Criteria{
		{
			Property:  "STATUS",
			Value:     "CERT_ACTIVE",
			Operation: "EQUAL",
		},
	},
}}

certificates, err := client.SearchCertificates(criteria)
if err != nil {
	log.Fatal(err)
}

fmt.Printf("Found %d certificates", len(certificates.Certificates))
```
#### GetV1CertificateStatus
```go
status, err := client.GetV1CertificateStatus()
if err != nil {
	log.Fatal(err)
}

fmt.Printf("V1 certificate endpoint has status %s, version %s, and revision %s", status.Status, status.Version, status.Revision)
```

### Certificate Authority
#### GetEJBCACAList
```go
list, err := client.GetEJBCACAList()
if err != nil {
	log.Fatal(err)
}
fmt.Printf("There are %d certificate authorities.", len(list.CertificateAuthorities))
```
#### GetCRLByIssuerDn
```go
crl, err := client.GetCRLByIssuerDn(issuerDn)
if err != nil {
return 
}
fmt.Printf("CRL from CA with issuer DN %s: \n%#v",issuerDn, crl)
```
#### GetV1CAStatus
```go
status, err := client.GetV1CAStatus()
if err != nil {
	return 
}
fmt.Printf("V1 CA endpoint has status %s, version %s, and revision %s", status.Status, status.Version, status.Revision)
```