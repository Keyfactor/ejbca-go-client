# Getting Started with the Go Client Library for EJBCA

## Requirements
* [Go](https://golang.org/doc/install) (v1.18 +)
* EJBCA
    * [EJBCA Enterprise](https://www.primekey.com/products/ejbca-enterprise/) (v7.7 +)

## Authentication
The EJBCA Go Client is designed to work with the EJBCA REST API interface included with EJBCA Enterprise by PrimeKey.
As such, the REST client requires that a client certificate and
associated private key be available for authentication with EJBCA. Additionally, if the EJBCA server certificate is signed by
an untrusted source, it's recommended that this certificate be registered with the client as a root of trust. Configuration
requires that these certificates be stored in a known location on the file system. The client also supports the EJBCA EST interface,
which uses a username and password for HTTP basic authentication.

## Getting Started
1. Use the following command to download the EJBCA Go Client.
   ```shell
   go get github.com/Keyfactor/ejbca-go-client/pkg/ejbca
   ```
2. Include the EJBCA Go Client in a project that requires programmatic access to EJBCA.
    ```go
    package main
	
    import (
        "github.com/Keyfactor/ejbca-go-client/pkg/ejbca"
        "log"
        "os"
    )
    ```
3. In the root directory of the project, run the following commands to vendor the module.
    ```shell
    go mod tidy
    go mod vendor
    ```
4. Create an `ejbca.Config` struct and populate with configuration. If an EST client is desired and there is no need for
   use of the EJBCA REST interface, this step is not necessary. This is because EST only requires a username and password
   for basic HTTP authentication. 
    ```go
    config := &ejbca.Config{
        // Path to client certificate in PEM format. This certificate must contain a client certificate that
        // is recognized by the EJBCA instance. This PEM file may also contain the private
        // key associated with the certificate, but KeyFile can also be set to configure the private key.
        CertificateFile: os.Getenv("EJBCA_CERTPATH"),
   
        // Path to private key in PEM format. This file should contain the private key associated with the
        // client certificate configured in CertificateFile.
        KeyFile:         os.Getenv("EJBCA_KEYPATH"),
   		
        // Password that protects private key (if encrypted)
        KeyPassword:     os.Getenv("EJBCA_KEYPASSWORD"),
   		
        // Path to the root CA that signed the certificate passed to the client for HTTPS connection.
        // This is not required if the CA is trusted by the host operating system. This should be a PEM
        // formatted certificate, and doesn't necessarily have to be the CA that signed CertificateFile.
        CAFile:          os.Getenv("EJBCA_CAPATH"),
    }
    ```
   The client also supports the configuration of default values for certificate profile name, end entity profile name, 
   and certificate authority. Configuration for default values is useful for applications where this information is
   difficult to access or not safe to keep locally.
   ```go
   config.DefaultCertificateProfileName = os.Getenv("EJBCA_CERT_PROFILE_NAME")
   config.DefaultEndEntityProfileName = os.Getenv("EJBCA_END_ENTITY_PROFILE_NAME")
   config.DefaultCertificateAuthorityName = os.Getenv("EJBCA_CA_NAME")
   ```
5. Pass the EJBCA hostname and configuration object to the `ejbca.ClientFactory()` method.
    ```go
    factory := ejbca.ClientFactory(os.Getenv("EJBCA_HOSTNAME"), config)
    ```
6. Generate the appropriate client using the client factory. Note that the factory is able to generate an EST client and/or
   a REST client, and the object returned by both `` and `` are the same `Client` object. The following snippet configures
   both the REST and EST client.
   ```go
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
7. Use the `client` object to carry out interactions with EJBCA.
    ```go
    keyBytes, _ := rsa.GenerateKey(rand.Reader, 2048)

    subj := pkix.Name{
        CommonName: "EJBCA-Go-Client",
    }

    template := x509.CertificateRequest{
        Subject:            subj,
        SignatureAlgorithm: x509.SHA256WithRSA,
    }
    var csrBuf bytes.Buffer
    csrBytes, _ := x509.CreateCertificateRequest(rand.Reader, &template, keyBytes)
    err := pem.Encode(&csrBuf, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})
    if err != nil {
        return
    }
 
    config := &ejbca.PKCS10CSREnrollment{
        IncludeChain: true, 
        CertificateRequest: csrBuf.String()}
    resp, err := client.EnrollPKCS10(config)
    if err != nil {
        return err
    }
    fmt.Println(resp.Certificate)
    ```