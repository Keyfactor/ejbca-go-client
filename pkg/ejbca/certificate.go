package ejbca

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"strconv"
)

func (c *RESTClient) FinalizeCertificateEnrollment(requestId int, password string) (*CertificateData, error) {
	log.Printf("[INFO] Finalizing certificate enrollment for request ID %d", requestId)

	endpoint := fmt.Sprintf("v1/certificate/%d/finalize", requestId)

	payload := &finalizeCertificateEnrollment{
		ResponseFormat: "DER",
		Password:       password,
	}

	requestConfig := &request{
		Method:   "POST",
		Endpoint: endpoint,
		Payload:  payload,
	}

	resp, err := c.sendRESTRequest(requestConfig)
	if err != nil {
		return nil, err
	}

	jsonResp := &certificateDataResponse{}
	err = json.NewDecoder(resp.Body).Decode(&jsonResp)
	if err != nil {
		return nil, err
	}

	data, err := serializeCertificateResponse(jsonResp)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func (c *RESTClient) RevokeCertificate(rca *RevokeCertificate) (*RevokeCertificateResponse, error) {
	log.Printf("[INFO] Revoking certificate with serial number %s", rca.CertificateSerialNumber)

	endpoint := fmt.Sprintf("v1/certificate/%s/%s/revoke", rca.IssuerDn, rca.CertificateSerialNumber)

	// Construct query if reason and/or date were specified

	query := make(map[string]string)

	if rca.Reason != "" {
		query["reason"] = rca.Reason
	}
	if rca.Date != "" {
		query["date"] = rca.Date
	}

	requestConfig := &request{
		Method:   "PUT",
		Endpoint: endpoint,
		Query:    query,
	}

	resp, err := c.sendRESTRequest(requestConfig)
	if err != nil {
		return nil, err
	}

	jsonResp := &RevokeCertificateResponse{}
	err = json.NewDecoder(resp.Body).Decode(&jsonResp)
	if err != nil {
		return nil, err
	}
	return jsonResp, nil
}

func (c *RESTClient) EnrollPKCS10(enrollment *PKCS10CSREnrollment) (*CertificateData, error) {
	log.Println("[INFO] Enrolling PKCS10 certificate")

	if enrollment.CertificateProfileName == "" {
		if c.defaultCertificateProfileName == "" {
			return nil, fmt.Errorf("certificate profile is required")
		} else {
			enrollment.CertificateProfileName = c.defaultCertificateProfileName
		}
	}

	if enrollment.EndEntityProfileName == "" {
		if c.defaultEndEntityProfileName == "" {
			return nil, fmt.Errorf("end entity profile is required")
		} else {
			enrollment.EndEntityProfileName = c.defaultEndEntityProfileName
		}
	}

	if enrollment.CertificateAuthorityName == "" {
		if c.defaultCertificateAuthorityName == "" {
			return nil, fmt.Errorf("certificate authority name is required")
		} else {
			enrollment.CertificateAuthorityName = c.defaultCertificateAuthorityName
		}
	}

	requestConfig := &request{
		Method:   "POST",
		Endpoint: "v1/certificate/pkcs10enroll",
		Payload:  enrollment,
	}

	resp, err := c.sendRESTRequest(requestConfig)
	if err != nil {
		return nil, err
	}

	jsonResp := &certificateDataResponse{}
	err = json.NewDecoder(resp.Body).Decode(jsonResp)
	if err != nil {
		return nil, err
	}

	return serializeCertificateResponse(jsonResp)
}

// CheckRevocationStatus checks if the certificate issued by issuerDn with serial number certificateSerialNumber is revoked.
// Give certificateSerialNumber a hex encoded serial number. IE hex representation of a really large unsigned integer.
func (c *RESTClient) CheckRevocationStatus(issuerDn string, certificateSerialNumber string) (*GetRevocationStatusResponse, error) {
	log.Printf("[INFO] Checking revocation status of certificate wtih serial number %s issued by CA with DN %s", certificateSerialNumber, issuerDn)

	endpoint := fmt.Sprintf("v1/certificate/%s/%s/revocationstatus", issuerDn, certificateSerialNumber)

	requestConfig := &request{
		Method:   "GET",
		Endpoint: endpoint,
	}

	resp, err := c.sendRESTRequest(requestConfig)
	if err != nil {
		return nil, err
	}

	jsonResp := &GetRevocationStatusResponse{}
	err = json.NewDecoder(resp.Body).Decode(&jsonResp)
	if err != nil {
		return nil, err
	}
	return jsonResp, nil
}

func (c *RESTClient) EnrollKeystore(keystore *EnrollKeystore) (*CertificateData, error) {
	log.Printf("[INFO] Enrolling keystore with algorithm %s", keystore.KeyAlg)

	requestConfig := &request{
		Method:   "POST",
		Endpoint: "v1/certificate/enrollkeystore",
		Payload:  keystore,
	}

	resp, err := c.sendRESTRequest(requestConfig)
	if err != nil {
		return nil, err
	}

	jsonResp := &certificateDataResponse{}
	err = json.NewDecoder(resp.Body).Decode(&jsonResp)
	if err != nil {
		return nil, err
	}

	return serializeCertificateResponse(jsonResp)
}

func (c *RESTClient) GetExpiringCertificates(days int, offset int, maxNumberOfResults int) (*ExpiringCertificates, error) {
	log.Println("[INFO] Getting list of expiring certificates")

	// Construct query if reason and/or date were specified

	query := make(map[string]string)
	query["days"] = strconv.Itoa(days)
	query["offset"] = strconv.Itoa(offset)

	if maxNumberOfResults > 0 {
		query["maxNumberOfResults"] = strconv.Itoa(maxNumberOfResults)
	}

	requestConfig := &request{
		Method:   "GET",
		Endpoint: "v1/certificate/expire",
		Query:    query,
	}

	resp, err := c.sendRESTRequest(requestConfig)
	if err != nil {
		return nil, err
	}

	jsonResp := &expiringCertificatesResp{}
	err = json.NewDecoder(resp.Body).Decode(&jsonResp)
	if err != nil {
		return nil, err
	}

	var data []*CertificateData
	for _, cert := range jsonResp.CertificatesRestResponse.Certificates {
		var leaf *CertificateData
		leaf, err = serializeCertificateResponse(&cert)
		if err != nil {
			return nil, err
		}

		data = append(data, leaf)
	}

	expiringCerts := new(ExpiringCertificates)
	expiringCerts.PaginationRestResponseComponent = jsonResp.PaginationRestResponseComponent
	expiringCerts.CertificatesRestResponse = data

	return expiringCerts, nil
}

func (c *RESTClient) EnrollCertificateRequest(certificateRequest *EnrollCertificateRequest) (*CertificateData, error) {
	log.Println("[INFO] Enrolling certificate request")

	requestConfig := &request{
		Method:   "POST",
		Endpoint: "v1/certificate/certificaterequest",
		Payload:  certificateRequest,
	}

	resp, err := c.sendRESTRequest(requestConfig)
	if err != nil {
		return nil, err
	}

	jsonResp := &certificateDataResponse{}
	err = json.NewDecoder(resp.Body).Decode(&jsonResp)
	if err != nil {
		return nil, err
	}

	return serializeCertificateResponse(jsonResp)
}

func (c *RESTClient) SearchCertificates(criteria *SearchCertificate) ([]*CertificateData, bool, error) {
	log.Printf("[INFO] Searching EJBCA for certificates with criteria %x", criteria)

	requestConfig := &request{
		Method:   "POST",
		Endpoint: "v1/certificate/search",
		Payload:  criteria,
	}

	resp, err := c.sendRESTRequest(requestConfig)
	if err != nil {
		return nil, false, err
	}

	jsonResp := &searchCertificateCriteriaResponse{}
	err = json.NewDecoder(resp.Body).Decode(&jsonResp)
	if err != nil {
		return nil, false, err
	}

	var data []*CertificateData
	for _, cert := range jsonResp.Certificates {
		var temp *CertificateData
		temp, err = serializeCertificateResponse(&cert)
		if err != nil {
			return nil, false, err
		}
		data = append(data, temp)
	}

	return data, jsonResp.MoreResults, nil
}

func (c *RESTClient) GetV1CertificateStatus() (*V1CertificateEndpointStatus, error) {
	log.Println("[INFO] Getting EJBCA V1 Certificate Endpoint Status")

	requestConfig := &request{
		Method:   "GET",
		Endpoint: "v1/certificate/status",
	}

	resp, err := c.sendRESTRequest(requestConfig)
	if err != nil {
		return nil, err
	}

	jsonResp := &V1CertificateEndpointStatus{}
	err = json.NewDecoder(resp.Body).Decode(&jsonResp)
	if err != nil {
		return nil, err
	}
	return jsonResp, nil
}

func serializeCertificateResponse(resp *certificateDataResponse) (*CertificateData, error) {
	data := new(CertificateData)
	var err error

	var certificates []*x509.Certificate
	if resp.ResponseFormat == "DER" {
		// First, extract leaf
		var decoded []byte
		if resp.Certificate != "" {
			// Certificate is usually base64 encoded PEM
			decoded, err = base64.StdEncoding.DecodeString(resp.Certificate)
			if err != nil {
				return nil, err
			}

			certificates, err = x509.ParseCertificates(decoded)
			if err != nil {
				// Sometimes, certificate response is base64 encoded twice. Before returning error, try decoding again
				decoded, err = base64.StdEncoding.DecodeString(string(decoded))
				if err != nil {
					return nil, err
				}
				certificates, err = x509.ParseCertificates(decoded)
				if err != nil {
					return nil, err
				}
			}
			if len(certificates) > 0 {
				data.Certificate = certificates[0]
			}
		}

		if len(resp.CertificateChain) > 0 {
			// Then, extract chain
			for _, cert := range resp.CertificateChain {
				decoded, err = base64.StdEncoding.DecodeString(cert)
				if err != nil {
					return nil, err
				}
				var i *x509.Certificate
				i, err = x509.ParseCertificate(decoded)
				if err != nil {
					return nil, err
				}
				data.CertificateChain = append(data.CertificateChain, i)
			}
		}
	}

	data.SerialNumber = resp.SerialNumber
	data.CertificateProfile = resp.CertificateProfile
	data.EndEntityProfile = resp.EndEntityProfile

	return data, nil
}
