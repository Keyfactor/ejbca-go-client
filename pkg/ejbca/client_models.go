package ejbca

import "net/http"

type SharedClientFactory struct {
	hostname string
	config   *Config
	client   *Client
}

type Client struct {
	RESTClient
	EST *ESTClient
}

type RESTClient struct {
	configured                      bool
	hostname                        string
	httpRESTClient                  *http.Client
	defaultCertificateProfileName   string
	defaultEndEntityProfileName     string
	defaultCertificateAuthorityName string
}

type ESTClient struct {
	hostname        string
	httpESTClient   *http.Client
	basicAuth       string
	defaultESTAlias string
}

// Config is a struct holding all necessary client configuration data
// for communicating with the EJBCA API. This includes the hostname, and configuration for the client certificate.
// Required field options:
// 	- Hostname and CertificateFile and KeyFile
//  - Hostname and PKCS12Path
type Config struct {

	// Path to client certificate in PEM format. This certificate must contain a client certificate that
	// is recognized by the EJBCA instance represented by Hostname. This PEM file may also contain the private
	// key associated with the certificate, but KeyFile can also be set to configure the private key.
	CertificateFile string

	// Path to private key in PEM format. This file should contain the private key associated with the
	// client certificate configured in CertificateFile.
	KeyFile string

	// Password that protects private key (if encrypted)
	KeyPassword string

	// Path to the root CA that signed the certificate passed to the client for HTTPS connection.
	// This is not required if the CA is trusted by the host operating system. This should be a PEM
	// formatted certificate, and doesn't necessarily have to be the CA that signed CertificateFile.
	// Note that GoLang searches the following locations for CA certificates, and configuring a CAFile has the same
	// effect as adding the CA certificate to one of the paths:
	// from https://go.dev/src/crypto/x509/root_linux.go
	//
	// Possible certificate files; stop after finding one.
	//	var certFiles = []string{
	//		"/etc/ssl/certs/ca-certificates.crt",                // Debian/Ubuntu/Gentoo etc.
	//		"/etc/pki/tls/certs/ca-bundle.crt",                  // Fedora/RHEL 6
	//		"/etc/ssl/ca-bundle.pem",                            // OpenSUSE
	//		"/etc/pki/tls/cacert.pem",                           // OpenELEC
	//		"/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", // CentOS/RHEL 7
	//		"/etc/ssl/cert.pem",                                 // Alpine Linux
	//  }
	//
	//	// Possible directories with certificate files; all will be read.
	//	var certDirectories = []string{
	//		"/etc/ssl/certs",               // SLES10/SLES11, https://golang.org/issue/12139
	//		"/etc/pki/tls/certs",           // Fedora/RHEL
	//		"/system/etc/security/cacerts", // Android
	//	}
	CAFile string

	// Optional default values for REST client
	DefaultCertificateProfileName   string
	DefaultEndEntityProfileName     string
	DefaultCertificateAuthorityName string

	// Optional default values for EST client
	DefaultESTAlias string
}

// request is a structure that holds required information for communicating with
// the EJBCA API. Included inside this struct is a pointer to an APIHeaders struct, a payload as an
// interface, and other configuration information for the API call.
type request struct {
	Method   string
	Endpoint string
	Headers  map[string]string
	Query    map[string]string
	Payload  interface{}
}

// Criteria contains search criteria used to query various EJBCA endpoints.
type Criteria struct {
	Property  string `json:"property"`
	Value     string `json:"value"`
	Operation string `json:"operation"`
}

// Search is a generic struct created for easy reuse of EJBCA endpoints that require queries.
type Search struct {
	MaxNumberOfResults int        `json:"max_number_of_results"`
	Criteria           []Criteria `json:"criteria"`
}
