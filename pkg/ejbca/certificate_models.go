package ejbca

import "crypto/x509"

// finalizeCertificateEnrollment contains configuration for finalizing a certificate enrollment
// with EJBCA, and is a required argument for the FinalizeCertificateEnrollment() method.
type finalizeCertificateEnrollment struct {
	// ResponseFormat must be one of 'P12’, 'BCFKS’, 'JKS’, ‘DER’
	ResponseFormat string `json:"response_format,omitempty"`

	// Certificate password
	Password string `json:"password,omitempty"`
}

type CertificateData struct {
	Certificate        *x509.Certificate
	SerialNumber       string
	CertificateChain   []*x509.Certificate
	PrivateKey         interface{}
	CertificateProfile string
	EndEntityProfile   string
}

type certificateDataResponse struct {
	Certificate        string   `json:"certificate,omitempty"`
	SerialNumber       string   `json:"serial_number,omitempty"`
	ResponseFormat     string   `json:"response_format,omitempty"`
	CertificateChain   []string `json:"certificate_chain,omitempty"`
	CertificateProfile string   `json:"certificate_profile,omitempty"`
	EndEntityProfile   string   `json:"end_entity_profile,omitempty"`
	password           string
}

// RevokeCertificate contains configuration data required for revoking certificates enrolled by an EJBCA CA, and is
// required to use the RevokeCertificate() method.
type RevokeCertificate struct {
	// Subject DN of the issuing CA
	IssuerDn string `json:"-"`

	// Hex serial number (without prefix, e.g. ‘00’)
	CertificateSerialNumber string `json:"-"`

	// Reason must be a valid RFC5280 reason. One of
	// NOT_REVOKED, UNSPECIFIED ,KEY_COMPROMISE,
	// CA_COMPROMISE, AFFILIATION_CHANGED, SUPERSEDED, CESSATION_OF_OPERATION,
	// CERTIFICATE_HOLD, REMOVE_FROM_CRL, PRIVILEGES_WITHDRAWN, AA_COMPROMISE
	Reason string `json:"-"`

	// ISO 8601 Date string, eg. ‘2018-06-15T14:07:09Z’
	Date string `json:"-"`
}

// RevokeCertificateResponse contains the response returned by the RevokeCertificate() method.
type RevokeCertificateResponse struct {
	IssuerDn         string `json:"issuer_dn,omitempty"`
	SerialNumber     string `json:"serial_number,omitempty"`
	RevocationReason string `json:"revocation_reason,omitempty"`
	RevocationDate   string `json:"revocation_date,omitempty"`
	Message          string `json:"message,omitempty"`
	Revoked          bool   `json:"revoked,omitempty"`
}

// PKCS10CSREnrollment contains configuration data required to enroll a PKCS10 CSR in PEM format, and is
// a required argument for the EnrollPKCS10() method.
type PKCS10CSREnrollment struct {
	CertificateRequest string `json:"certificate_request,omitempty"`

	// Certificate profile name that EJBCA will enroll the CSR with. Leave this blank to use default
	// certificate profile configured with client.
	CertificateProfileName string `json:"certificate_profile_name,omitempty"`

	// End entity profile that EJBCA will enroll the CSR with. Leave this blank to use default
	// end entity profile configured with client.
	EndEntityProfileName string `json:"end_entity_profile_name,omitempty"`

	// Name of EJBCA certificate authority that will enroll CSR. Leave this blank to use default
	// certificate authority configured with client.
	CertificateAuthorityName string `json:"certificate_authority_name,omitempty"`
	Username                 string `json:"username,omitempty"`
	Password                 string `json:"password,omitempty"`
	AccountBindingId         string `json:"account_binding_id,omitempty"`
	IncludeChain             bool   `json:"include_chain,omitempty"`
}

// GetRevocationStatusResponse contains response data returned by the CheckRevocationStatus() method.
type GetRevocationStatusResponse struct {
	RevokeCertificateResponse
}

// EnrollKeystore contains configuration data required to enroll a keystore with EJBCA.
type EnrollKeystore struct {
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	KeyAlg   string `json:"key_alg,omitempty"`
	KeySpec  string `json:"key_spec,omitempty"`
}

type CertificatesRestResponse struct {
	Certificates []certificateDataResponse
}

type expiringCertificatesResp struct {
	PaginationRestResponseComponent PaginationRestResponseComponent `json:"pagination_rest_response_component"`
	CertificatesRestResponse        CertificatesRestResponse        `json:"certificates_rest_response"`
}

// The ExpiringCertificates struct is returned by the GetExpiringCertificates() method.
type ExpiringCertificates struct {
	PaginationRestResponseComponent PaginationRestResponseComponent
	CertificatesRestResponse        []*CertificateData
}

// PaginationRestResponseComponent is a structure that is contained within the ExpiringCertificates struct
// and is used to modularize response content.
type PaginationRestResponseComponent struct {
	MoreResults     bool `json:"more_results,omitempty"`
	NextOffset      int  `json:"next_offset,omitempty"`
	NumberOfResults int  `json:"number_of_results,omitempty"`
}

// EnrollCertificateRequest contains configuration data required to enroll a certificate request with EJBCA.
type EnrollCertificateRequest struct {
	CertificateRequest       string `json:"certificate_request,omitempty"`
	Username                 string `json:"username,omitempty"`
	Password                 string `json:"password,omitempty"`
	IncludeChain             bool   `json:"include_chain,omitempty"`
	CertificateAuthorityName string `json:"certificate_authority_name,omitempty"`
}

// SearchCertificate contains search criteria required to search for certificates enrolled by EJBCA.
type SearchCertificate struct {
	Search
}

// SearchCertificateCriteriaResponse contains the query data returned by the SearchCertificates() method.
type searchCertificateCriteriaResponse struct {
	Certificates []certificateDataResponse `json:"certificates,omitempty"`
	MoreResults  bool                      `json:"more_results,omitempty"`
}

// V1CertificateEndpointStatus contains status information about the V1 certificate endpoint.
type V1CertificateEndpointStatus struct {
	Status   string `json:"status,omitempty"`
	Version  string `json:"version,omitempty"`
	Revision string `json:"revision,omitempty"`
}
