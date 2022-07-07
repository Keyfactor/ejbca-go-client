package ejbca

type CAInfo struct {
	CertificateAuthorities []CertificateAuthorities `json:"certificate_authorities"`
}

type CertificateAuthorities struct {
	Id             int    `json:"id,omitempty"`
	Name           string `json:"name,omitempty"`
	SubjectDn      string `json:"subject_dn,omitempty"`
	IssuerDn       string `json:"issuer_dn,omitempty"`
	ExpirationDate string `json:"expiration_date,omitempty"`
}

type LatestCRL struct {
	CRL            []string `json:"crl,omitempty"`
	ResponseFormat string   `json:"response_format,omitempty"`
}

type V1CARestResourceStatus struct {
	Status   string `json:"status,omitempty"`
	Version  string `json:"version,omitempty"`
	Revision string `json:"revision,omitempty"`
}
