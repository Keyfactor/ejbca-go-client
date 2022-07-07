package ejbca

import (
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"go.mozilla.org/pkcs7"
	"io"
	"log"
	"strings"
)

func (e *ESTClient) CaCerts(alias string) ([]*x509.Certificate, error) {
	log.Println("[INFO] Getting CA certificate and chain with EST")

	endpoint := ""
	if alias != "" {
		endpoint = alias + "/"
	}
	endpoint += "cacerts"

	requestConfig := &request{
		Method:   "GET",
		Endpoint: endpoint,
	}

	resp, err := e.sendESTRequest(requestConfig)
	if err != nil {
		return nil, err
	}

	// Ensure that we got a pkcs7 mime
	content, ok := resp.Header["Content-Type"]
	if !ok || !strings.Contains(content[0], "application/pkcs7-mime") {
		return nil, fmt.Errorf("unknown or empty content-type %s", content[0])
	}

	// Ensure that the response is base64 encoded
	encoding, ok := resp.Header["Content-Transfer-Encoding"]
	if !ok || encoding[0] != "base64" {
		return nil, fmt.Errorf("unknown or empty content-transfer-encoding %s", encoding[0])
	}

	log.Printf("[TRACE] Decoding PKCS#7 mime")

	encodedBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	decodedBytes, err := base64.StdEncoding.DecodeString(string(encodedBytes))
	if err != nil {
		return nil, err
	}

	parsed, err := pkcs7.Parse(decodedBytes)
	if err != nil {
		return nil, err
	}

	log.Printf("[DEBUG] Found %d certificates in chain", len(parsed.Certificates))

	return parsed.Certificates, nil
}

// SimpleEnroll uses the EJBCA EST endpoint with an optional alias to perform a simple CSR enrollment.
// * alias - optional EJBCA EST alias
// * csr   - Base64 encoded PKCS#10 CSR
func (e *ESTClient) SimpleEnroll(alias string, csr string) ([]*x509.Certificate, error) {
	log.Println("[INFO] Performing a simple CSR enrollment with EST")

	endpoint := ""
	if alias != "" {
		// Use alias passed as argument, if provided
		endpoint = alias + "/"
	} else if e.defaultESTAlias != "" {
		// If not provided, use the default alias, if it exists
		endpoint = alias + "/"
	}
	endpoint += "simpleenroll"

	headers := make(map[string]string)
	headers["Content-Transfer-Encoding"] = "base64"
	headers["Content-Type"] = "application/pkcs10"

	requestConfig := &request{
		Method:   "POST",
		Endpoint: endpoint,
		Headers:  headers,
		Payload:  csr,
	}

	resp, err := e.sendESTRequest(requestConfig)
	if err != nil {
		return nil, err
	}

	// Verify headers
	encoding, ok := resp.Header["Content-Transfer-Encoding"]
	if !ok || encoding[0] != "base64" {
		return nil, fmt.Errorf("unknown or empty content-transfer-encoding %s", encoding[0])
	}

	content, ok := resp.Header["Content-Type"]
	if !ok || !strings.Contains(content[0], "application/pkcs7-mime") {
		return nil, fmt.Errorf("unknown or empty content-type %s", content[0])
	}

	log.Printf("[TRACE] Decoding PKCS#7 mime")

	encodedBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	decodedBytes, err := base64.StdEncoding.DecodeString(string(encodedBytes))
	if err != nil {
		return nil, err
	}

	parsed, err := pkcs7.Parse(decodedBytes)
	if err != nil {
		return nil, err
	}

	log.Printf("[DEBUG] Found %d certificates in chain", len(parsed.Certificates))

	return parsed.Certificates, nil
}

func (e *ESTClient) SimpleReEnroll(alias string, csr *x509.CertificateRequest) (string, error) {
	err := "[WARN] Simple ReEnroll EST method not implemented"
	log.Println(err)
	return "", fmt.Errorf(err)
}
