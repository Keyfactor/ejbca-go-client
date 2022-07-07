package ejbca

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"testing"
	"time"
)

func TestClient_EnrollCertificateRequest(t *testing.T) {
	ejbcaTestPreCheck(t)

	entity := getEJBCAEntityConfig(t)

	caName, err := getCAName()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Setting CA to %s", caName)

	// Generate a PKCS#10 CSR with a random CN
	cn := fmt.Sprintf("ejbcaGoClient_%s", randStringFromCharSet(10))
	csr := generateCSR(cn, "Administrators", "Internal Test", "US")

	enroll := &EnrollCertificateRequest{
		CertificateRequest:       csr,
		Username:                 entity,
		Password:                 "foo123",
		IncludeChain:             false,
		CertificateAuthorityName: caName,
	}

	certificateRequestResponse, err := client.EnrollCertificateRequest(enroll)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Successfully enrolled CSR with CN %s and serial number %s", cn, certificateRequestResponse.SerialNumber)

}

func enrollCertificateWithCSR(entity string) (error, *PKCS10CSREnrollmentResponse) {
	caName, err := getCAName()
	if err != nil {
		return err, nil
	}

	log.Printf("Setting CA to %s", caName)

	// Generate a PKCS#10 CSR with a random CN
	cn := fmt.Sprintf("ejbcaGoClient_%s", randStringFromCharSet(10))
	csr := generateCSR(cn, "Administrators", "Internal Test", "US")

	// TODO this needs to be streamlined.
	enroll := &PKCS10CSREnrollment{
		CertificateRequest:       csr,
		CertificateAuthorityName: caName,
		EndEntityProfileName:     "AdminInternal",
		CertificateProfileName:   "Authentication-2048-3y",
		IncludeChain:             true,
		Username:                 entity,
		Password:                 "foo123",
	}

	resp, err := client.EnrollPKCS10(enroll)
	if err != nil {
		return err, nil
	}

	return nil, resp
}

func parseRespToChain(resp *PKCS10CSREnrollmentResponse) string {

	cert, err := base64.StdEncoding.DecodeString(resp.Certificate)
	if err != nil {
		return ""
	}
	chain := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert})
	for _, certificate := range resp.CertificateChain {
		leaf, err := base64.StdEncoding.DecodeString(certificate)
		if err != nil {
			return ""
		}

		chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf})...)
	}

	return string(chain)
}

func TestClient_EnrollPKCS10(t *testing.T) {
	ejbcaTestPreCheck(t)

	entity := getEJBCAEntityConfig(t)

	err, resp := enrollCertificateWithCSR(entity)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("Enrolled certificate with SN %s", resp.SerialNumber)

	log.Printf("Chain:\n%s", parseRespToChain(resp))

	// Clean up
	decoded, err := base64.StdEncoding.DecodeString(resp.Certificate)
	if err != nil {
		t.Fatal(err)
	}

	certificate, err := x509.ParseCertificate(decoded)
	if err != nil {
		t.Fatal(err)
	}

	issuer := fmt.Sprintf("%s", certificate.Issuer)

	arg := &RevokeCertificate{
		IssuerDn:                issuer,
		CertificateSerialNumber: resp.SerialNumber,
		Reason:                  "CESSATION_OF_OPERATION",
		Date:                    time.Now().Format(time.RFC3339),
	}

	revokeResp, err := client.RevokeCertificate(arg)
	if err != nil {
		t.Fatal(err)
	}

	if !revokeResp.Revoked {
		t.Fatal(revokeResp.Message)
	}
}

func TestClient_CheckRevocationStatus(t *testing.T) {
	ejbcaTestPreCheck(t)

	certificate, err := getRandomEJBCACertificate()
	if err != nil {
		t.Fatal(err)
	}
	issuer := fmt.Sprintf("%s", certificate.Issuer)
	sn := fmt.Sprintf("%x", certificate.SerialNumber)

	status, err := client.CheckRevocationStatus(issuer, sn)
	if err != nil {
		t.Fatal(err)
	}
	var state string
	if status.Revoked {
		state = "is"
	} else {
		state = "is not"
	}

	t.Logf("Certificate with serial number %s %s revoked.", status.SerialNumber, state)
}

func TestClient_EnrollKeystore(t *testing.T) {
	ejbcaTestPreCheck(t)
	entity := getEJBCAEntityConfig(t)

	config := &EnrollKeystore{
		Username: entity,
		Password: "foo123",
		KeyAlg:   "RSA",
		KeySpec:  "2048",
	}

	keystore, err := client.EnrollKeystore(config)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("Enrolled new keystore with serial number %s", keystore.SerialNumber)
}

func TestClient_GetExpiringCertificates(t *testing.T) {
	ejbcaTestPreCheck(t)
	days := 90
	certificates, err := client.GetExpiringCertificates(days, 0, 100)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("There are %d certificates expiring in the next %d days.", len(certificates.CertificatesRestResponse.Certificates), days)
}

func TestClient_FinalizeCertificateEnrollment(t *testing.T) {
	t.Skip("Not implemented")
	ejbcaTestPreCheck(t)
}

func TestClient_GetV1CertificateStatus(t *testing.T) {
	ejbcaTestPreCheck(t)

	status, err := client.GetV1CertificateStatus()
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("V1 certificate endpoint has status %s, version %s, and revision %s", status.Status, status.Version, status.Revision)
}

func TestClient_RevokeCertificate(t *testing.T) {
	ejbcaTestPreCheck(t)

	// Enroll a certificate first
	entity := getEJBCAEntityConfig(t)
	err, resp := enrollCertificateWithCSR(entity)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("Enrolled certificate with serial number %s", resp.SerialNumber)

	decoded, err := base64.StdEncoding.DecodeString(resp.Certificate)
	if err != nil {
		t.Fatal(err)
	}

	certificate, err := x509.ParseCertificate(decoded)
	if err != nil {
		t.Fatal(err)
	}

	issuer := fmt.Sprintf("%s", certificate.Issuer)

	arg := &RevokeCertificate{
		IssuerDn:                issuer,
		CertificateSerialNumber: resp.SerialNumber,
		Reason:                  "CESSATION_OF_OPERATION",
		Date:                    time.Now().Format(time.RFC3339),
	}

	revokeResp, err := client.RevokeCertificate(arg)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("Revoked certificate with serial number %s on %s; %s", revokeResp.SerialNumber, revokeResp.RevocationDate, revokeResp.Message)
}

func TestClient_SearchCertificates(t *testing.T) {
	ejbcaTestPreCheck(t)

	criteria := &SearchCertificate{Search{
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
		t.Fatal(err)
	}

	t.Logf("Found %d certificates", len(certificates.Certificates))
}

func getCAName() (string, error) {
	// First, get a list of CAs from EJBCA
	list, err := client.GetEJBCACAList()
	if err != nil {
		return "", err
	}
	var caName string
	// If this EJBCA instance has ManagementCA, enroll here because it's a safe bet
	for _, ca := range list.CertificateAuthorities {
		if ca.Name == "ManagementCA" {
			caName = ca.Name
		}
	}
	// Otherwise, just enroll off the first CA in the list
	if caName == "" {
		caName = list.CertificateAuthorities[0].Name
	}
	return caName, nil
}

func generateCSR(commonName string, ou string, o string, country string) string {
	keyBytes, _ := rsa.GenerateKey(rand.Reader, 2048)

	subj := pkix.Name{
		CommonName: commonName,
	}
	if ou != "" {
		subj.OrganizationalUnit = []string{ou}
	}
	if o != "" {
		subj.Organization = []string{o}
	}
	if country != "" {
		subj.Country = []string{country}
	}

	template := x509.CertificateRequest{
		Subject:            subj,
		SignatureAlgorithm: x509.SHA256WithRSA,
	}
	var csrBuf bytes.Buffer
	csrBytes, _ := x509.CreateCertificateRequest(rand.Reader, &template, keyBytes)
	err := pem.Encode(&csrBuf, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})
	if err != nil {
		return ""
	}

	return csrBuf.String()
}

func getRandomEJBCACertificate() (*x509.Certificate, error) {
	criteria := &SearchCertificate{Search{
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
		return nil, err
	}

	// Search certificate returns certificates in base64 PEM encoding with no headers. To get DER encoding, decode Base64
	// twice, then pass to ParseCertificate to grab the Issuer DN etc.
	num, err := rand.Int(rand.Reader, big.NewInt(int64(len(certificates.Certificates))))
	if err != nil {
		return nil, err
	}
	cert := certificates.Certificates[num.Int64()].Certificate

	decoded, err := base64.StdEncoding.DecodeString(cert)
	if err != nil {
		return nil, err
	}

	decoded2, err := base64.StdEncoding.DecodeString(string(decoded))
	if err != nil {
		return nil, err
	}

	certificate, err := x509.ParseCertificate(decoded2)
	if err != nil {
		return nil, err
	}

	return certificate, nil
}
