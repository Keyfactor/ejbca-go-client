package ejbca

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
)

func (c *RESTClient) GetEJBCACAList() (*CAInfo, error) {
	log.Println("[INFO] Getting EJBCA CA list")

	requestConfig := &request{
		Method:   "GET",
		Endpoint: "v1/ca",
	}

	resp, err := c.sendRESTRequest(requestConfig)
	if err != nil {
		return nil, err
	}

	jsonResp := &CAInfo{}
	err = json.NewDecoder(resp.Body).Decode(&jsonResp)
	if err != nil {
		return nil, err
	}
	return jsonResp, nil
}

func (c *RESTClient) GetCACertificate(subjectDn string) ([]*x509.Certificate, error) {
	log.Printf("[INFO] Downloading CA certificate with subject DN %s", subjectDn)

	endpoint := fmt.Sprintf("v1/ca/%s/certificate/download", subjectDn)

	requestConfig := &request{
		Method:   "GET",
		Endpoint: endpoint,
	}

	resp, err := c.sendRESTRequest(requestConfig)
	if err != nil {
		return nil, err
	}

	encodedBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var block *pem.Block
	var certificate *x509.Certificate
	var chain []*x509.Certificate
	for {
		block, encodedBytes = pem.Decode(encodedBytes)
		if block == nil {
			break
		} else if block.Type == "CERTIFICATE" {
			certificate, err = x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, err
			}
			chain = append(chain, certificate)
		}

	}

	return chain, nil
}

func (c *RESTClient) GetCRLByIssuerDn(issuerDn string) (*LatestCRL, error) {
	log.Printf("[INFO] Retreiving CRL from CA with issuer DN %s", issuerDn)

	endpoint := fmt.Sprintf("v1/ca/%s/getLatestCrl", issuerDn)

	requestConfig := &request{
		Method:   "GET",
		Endpoint: endpoint,
	}

	resp, err := c.sendRESTRequest(requestConfig)
	if err != nil {
		return nil, err
	}

	jsonResp := &LatestCRL{}
	err = json.NewDecoder(resp.Body).Decode(&jsonResp)
	if err != nil {
		return nil, err
	}
	return jsonResp, nil
}

func (c *RESTClient) GetV1CAStatus() (*V1CARestResourceStatus, error) {
	log.Println("[INFO] Getting EJBCA V1 CA Endpoint Status")

	requestConfig := &request{
		Method:   "GET",
		Endpoint: "v1/ca/status",
	}

	resp, err := c.sendRESTRequest(requestConfig)
	if err != nil {
		return nil, err
	}

	jsonResp := &V1CARestResourceStatus{}
	err = json.NewDecoder(resp.Body).Decode(&jsonResp)
	if err != nil {
		return nil, err
	}
	return jsonResp, nil
}
