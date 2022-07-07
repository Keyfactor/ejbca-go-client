package ejbca

// EndEntitySearch is used to search for specific end entities supported by an EJBCA instance.
type EndEntitySearch struct {
	Search
}

type EndEntitySearchResponse struct {
	EndEntities []EndEntity `json:"end_entities"`
	MoreResults bool        `json:"more_results"`
}

type EndEntity struct {
	Username       string          `json:"username"`
	Dn             string          `json:"dn"`
	SubjectAltName string          `json:"subject_alt_name"`
	Email          *string         `json:"email"`
	Status         string          `json:"status"`
	Token          string          `json:"token"`
	ExtensionData  []ExtensionData `json:"extension_data"`
}

type ExtensionData struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type V1EndEntityStatus struct {
	V1CertificateEndpointStatus
}
