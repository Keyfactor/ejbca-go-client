package ejbca

import (
	"encoding/json"
	"fmt"
	"log"
	"strconv"
)

func (c *RESTClient) FinalizeCertificateEnrollment(enrollment *FinalizeCertificateEnrollment) (*FinalizeCertificateEnrollmentResponse, error) {
	log.Printf("[INFO] Finalizing certificate enrollment for request ID %d", enrollment.RequestId)

	endpoint := fmt.Sprintf("v1/certificate/%d/finalize", enrollment.RequestId)

	requestConfig := &request{
		Method:   "POST",
		Endpoint: endpoint,
		Payload:  enrollment,
	}

	resp, err := c.sendRESTRequest(requestConfig)
	if err != nil {
		return nil, err
	}

	jsonResp := &FinalizeCertificateEnrollmentResponse{}
	err = json.NewDecoder(resp.Body).Decode(&jsonResp)
	if err != nil {
		return nil, err
	}
	return jsonResp, nil
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

func (c *RESTClient) EnrollPKCS10(enrollment *PKCS10CSREnrollment) (*PKCS10CSREnrollmentResponse, error) {
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

	jsonResp := &PKCS10CSREnrollmentResponse{}
	err = json.NewDecoder(resp.Body).Decode(&jsonResp)
	if err != nil {
		return nil, err
	}
	return jsonResp, nil
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

func (c *RESTClient) EnrollKeystore(keystore *EnrollKeystore) (*EnrollKeystoreResponse, error) {
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

	jsonResp := &EnrollKeystoreResponse{}
	err = json.NewDecoder(resp.Body).Decode(&jsonResp)
	if err != nil {
		return nil, err
	}
	return jsonResp, nil
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

	jsonResp := &ExpiringCertificates{}
	err = json.NewDecoder(resp.Body).Decode(&jsonResp)
	if err != nil {
		return nil, err
	}
	return jsonResp, nil
}

func (c *RESTClient) EnrollCertificateRequest(certificateRequest *EnrollCertificateRequest) (*EnrollCertificateRequestResponse, error) {
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

	jsonResp := &EnrollCertificateRequestResponse{}
	err = json.NewDecoder(resp.Body).Decode(&jsonResp)
	if err != nil {
		return nil, err
	}
	return jsonResp, nil
}

func (c *RESTClient) SearchCertificates(criteria *SearchCertificate) (*SearchCertificateCriteriaResponse, error) {
	log.Printf("[INFO] Searching EJBCA for certificates with criteria %x", criteria)

	requestConfig := &request{
		Method:   "POST",
		Endpoint: "v1/certificate/search",
		Payload:  criteria,
	}

	resp, err := c.sendRESTRequest(requestConfig)
	if err != nil {
		return nil, err
	}

	jsonResp := &SearchCertificateCriteriaResponse{}
	err = json.NewDecoder(resp.Body).Decode(&jsonResp)
	if err != nil {
		return nil, err
	}
	return jsonResp, nil
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
